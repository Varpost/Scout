"""Semgrep engine — maps ``semgrep scan --json`` results onto Findings."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from scout.engines import BaseEngine, register_engine
from scout.models import Finding

# Covers both classic semgrep labels (INFO/WARNING/ERROR) and the newer
# LOW..CRITICAL scale some rulesets emit. Unknown labels default to MEDIUM.
SEMGREP_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "INFO": "LOW",
    "LOW": "LOW",
}

# ponytail: fixed generous cap; make configurable only if a real tree hits it.
SEMGREP_TIMEOUT_SECONDS = 600


def _warn(message: str) -> None:
    """Emit a visible warning — engine failures must never be silent."""
    print(f"scout: semgrep engine: {message}", file=sys.stderr)


def _dict(value: object) -> dict[str, Any]:
    """Return the value if it is a dict, else an empty one (defensive parse)."""
    return value if isinstance(value, dict) else {}


def parse_semgrep_json(text: str) -> list[Finding]:
    """Map a ``semgrep scan --json`` document onto Scout findings.

    Args:
        text: Raw JSON emitted by semgrep on stdout.

    Returns:
        One finding per semgrep result; malformed individual results are
        skipped rather than failing the whole parse.

    Raises:
        ValueError: If the document is not a JSON object.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("unexpected JSON shape (expected an object)")

    findings: list[Finding] = []
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        extra = _dict(result.get("extra"))
        start = _dict(result.get("start"))
        metadata = _dict(extra.get("metadata"))
        check_id = str(result.get("check_id") or "semgrep-rule")
        line = start.get("line")
        references = [str(ref) for ref in (metadata.get("references") or []) if isinstance(ref, str)][:3]
        findings.append(
            Finding(
                # Path(...) round-trip normalizes separators so engine findings
                # dedupe against native ones on Windows too.
                file=str(Path(str(result.get("path") or ""))),
                line=line if isinstance(line, int) and line > 0 else 1,
                severity=SEMGREP_SEVERITY.get(str(extra.get("severity") or "").upper(), "MEDIUM"),
                title=check_id.rsplit(".", 1)[-1],
                description=str(extra.get("message") or "").strip() or f"Semgrep rule {check_id} matched.",
                scanner="semgrep",
                snippet=str(extra.get("lines") or "").strip(),
                # A rule that ships an autofix is a mechanical phase-1 change;
                # everything else needs a real code change.
                fix_phase=1 if extra.get("fix") else 3,
                fix_summary=f"See semgrep rule {check_id}.",
                references=references,
            )
        )
    return findings


@register_engine
class SemgrepEngine(BaseEngine):
    """Runs semgrep with its default rules and merges the results."""

    name = "semgrep"
    binary = "semgrep"

    def run(self, path: Path) -> list[Finding]:
        """Invoke ``semgrep scan --json`` on the target path.

        Args:
            path: Root directory or file to scan.

        Returns:
            Mapped findings; empty (with a stderr note) on any engine failure.
        """
        exe = shutil.which(self.binary)
        if exe is None:  # pragma: no cover — callers gate on available()
            return []
        cmd = [exe, "scan", "--json", "--quiet", "--disable-version-check", str(path)]
        try:
            proc = subprocess.run(  # noqa: S603 — fixed argv, absolute exe, no shell
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=SEMGREP_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _warn(f"failed to run semgrep: {exc}")
            return []
        try:
            return parse_semgrep_json(proc.stdout)
        except ValueError as exc:
            detail = (proc.stderr or "").strip().splitlines()
            _warn(f"{exc} (exit code {proc.returncode}{'; ' + detail[-1] if detail else ''})")
            return []
