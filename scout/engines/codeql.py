"""CodeQL engine — maps ``codeql database analyze`` SARIF onto Findings.

CodeQL is GitHub's semantic analysis engine. Unlike semgrep it is two-step:
build an extraction database for each language, then analyze it with the
official query pack. Both steps run through the CodeQL CLI
(https://github.com/github/codeql-cli-binaries — also ships with `gh`),
which must be on PATH as ``codeql``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from scout.engines import BaseEngine, register_engine
from scout.models import Finding

# Languages Scout asks CodeQL to extract, keyed by the file suffixes that
# prove the language is present ("javascript" covers TypeScript).
LANGUAGE_SUFFIXES = {
    "javascript": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    "python": {".py"},
}

# CodeQL security-severity is a CVSS-style 0-10 score attached to each rule.
SECURITY_SEVERITY_BANDS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.0, "LOW"))
# Fallback when a rule carries no score: the SARIF result level.
LEVEL_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}

# ponytail: fixed generous cap per CLI step; database extraction on large
# repos is minutes by design — make configurable only if a real tree hits it.
CODEQL_TIMEOUT_SECONDS = 1800


def _warn(message: str) -> None:
    """Emit a visible warning — engine failures must never be silent."""
    print(f"scout: codeql engine: {message}", file=sys.stderr)


def _dict(value: object) -> dict[str, Any]:
    """Return the value if it is a dict, else an empty one (defensive parse)."""
    return value if isinstance(value, dict) else {}


def detect_languages(path: Path) -> list[str]:
    """Languages CodeQL should extract, judged by file suffixes present.

    Args:
        path: Root directory or file to scan.

    Returns:
        Sorted language names (subset of ``LANGUAGE_SUFFIXES`` keys).
    """
    candidates = [path] if path.is_file() else path.rglob("*")
    found: set[str] = set()
    try:
        for candidate in candidates:
            suffix = candidate.suffix.lower()
            for language, suffixes in LANGUAGE_SUFFIXES.items():
                if suffix in suffixes:
                    found.add(language)
            if len(found) == len(LANGUAGE_SUFFIXES):
                break
    except OSError:  # unreadable subtree — scan what was seen so far
        pass
    return sorted(found)


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    """Severity from the rule's security-severity score, else the SARIF level."""
    try:
        score = float(str(_dict(rule.get("properties")).get("security-severity")))
    except ValueError:
        return LEVEL_SEVERITY.get(str(result.get("level") or "").lower(), "MEDIUM")
    return next(label for floor, label in SECURITY_SEVERITY_BANDS if score >= floor)


def parse_sarif(text: str, root: Path) -> list[Finding]:
    """Map a CodeQL SARIF document onto Scout findings.

    Args:
        text: Raw SARIF (2.1.0) emitted by ``codeql database analyze``.
        root: Scan root the SARIF's relative artifact URIs resolve against.

    Returns:
        One finding per SARIF result; malformed individual results are
        skipped rather than failing the whole parse.

    Raises:
        ValueError: If the document is not a JSON object.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid SARIF JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("unexpected SARIF shape (expected an object)")

    findings: list[Finding] = []
    for run in data.get("runs") or []:
        run = _dict(run)
        driver = _dict(_dict(run.get("tool")).get("driver"))
        rules = {str(rule.get("id")): rule for rule in driver.get("rules") or [] if isinstance(rule, dict)}
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "codeql-rule")
            rule = rules.get(rule_id, {})
            location = _dict(next(iter(result.get("locations") or []), None))
            physical = _dict(location.get("physicalLocation"))
            uri = str(_dict(physical.get("artifactLocation")).get("uri") or "")
            region = _dict(physical.get("region"))
            line = region.get("startLine")
            help_uri = rule.get("helpUri")
            findings.append(
                Finding(
                    # SARIF URIs are source-root-relative with forward slashes;
                    # joining onto the scan root matches native finding paths
                    # so the merge dedupe works on Windows too.
                    file=str(Path(root, *uri.split("/"))) if uri else str(root),
                    line=line if isinstance(line, int) and line > 0 else 1,
                    severity=_severity(result, rule),
                    title=rule_id,
                    description=str(_dict(result.get("message")).get("text") or "").strip()
                    or f"CodeQL rule {rule_id} matched.",
                    scanner="codeql",
                    snippet=str(_dict(_dict(region.get("snippet"))).get("text") or "").strip(),
                    # CodeQL ships no autofixes in SARIF — always a real change.
                    fix_phase=3,
                    fix_summary=f"See CodeQL rule {rule_id}.",
                    references=[str(help_uri)] if isinstance(help_uri, str) and help_uri else [],
                )
            )
    return findings


@register_engine
class CodeQLEngine(BaseEngine):
    """Runs CodeQL's official security queries and merges the results."""

    name = "codeql"
    binary = "codeql"

    def run(self, path: Path) -> list[Finding]:
        """Build a CodeQL database per detected language and analyze it.

        Args:
            path: Root directory or file to scan.

        Returns:
            Mapped findings; empty (with a stderr note) on any engine failure.
        """
        exe = shutil.which(self.binary)
        if exe is None:  # pragma: no cover — callers gate on available()
            return []
        languages = detect_languages(path)
        if not languages:
            _warn("no files in a CodeQL-supported language (python/javascript) — skipped")
            return []
        findings: list[Finding] = []
        for language in languages:
            findings.extend(self._run_language(exe, path, language))
        return findings

    def _run_language(self, exe: str, path: Path, language: str) -> list[Finding]:
        """Database-create + analyze one language; fail open on any step."""
        with tempfile.TemporaryDirectory(prefix="scout-codeql-") as tmp:
            database = Path(tmp) / f"db-{language}"
            sarif = Path(tmp) / f"{language}.sarif"
            steps = (
                [exe, "database", "create", str(database), f"--language={language}", f"--source-root={path}"],
                [
                    exe,
                    "database",
                    "analyze",
                    str(database),
                    # Official query pack; its default suite is the same
                    # security set GitHub code scanning runs.
                    f"codeql/{language}-queries",
                    "--format=sarif-latest",
                    f"--output={sarif}",
                    "--download",
                ],
            )
            for cmd in steps:
                try:
                    proc = subprocess.run(  # noqa: S603 — fixed argv, absolute exe, no shell
                        cmd,
                        capture_output=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=CODEQL_TIMEOUT_SECONDS,
                        check=False,
                        # Engines are reachable from the MCP server; an inherited
                        # protocol stdin deadlocks child processes on Windows.
                        stdin=subprocess.DEVNULL,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    _warn(f"{language}: failed to run codeql: {exc}")
                    return []
                if proc.returncode != 0:
                    detail = (proc.stderr or "").strip().splitlines()
                    _warn(
                        f"{language}: codeql {cmd[1]} {cmd[2]} exited {proc.returncode}"
                        f"{'; ' + detail[-1] if detail else ''}"
                    )
                    return []
            try:
                return parse_sarif(sarif.read_text(encoding="utf-8"), path)
            except (OSError, ValueError) as exc:
                _warn(f"{language}: {exc}")
                return []
