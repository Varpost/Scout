"""Baseline support — accept current findings, alert only on new ones.

The detect-secrets/Gitleaks adoption pattern: ``scout scan --write-baseline``
records every current finding in ``.scout-baseline.json``; later scans with
``--baseline`` report only findings that aren't in the file.

Finding identity is ``(finding id, relative file, hash of the normalized
flagged-line content)`` — deliberately **no line numbers**. Line-based
identity would resurrect every baselined finding the moment someone inserts
a line above it; hashing the stripped line text keeps identity stable under
unrelated edits while any change to the flagged line itself re-raises the
finding for review.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scout.agents.reporter_agent import _finding_id
from scout.models import Finding

BASELINE_VERSION = 1
DEFAULT_BASELINE_NAME = ".scout-baseline.json"

# (finding id, root-relative POSIX path, content hash)
BaselineKey = tuple[str, str, str]


def _content_hash(finding: Finding, file_lines: dict[str, list[str] | None]) -> str:
    """Hash the finding's normalized flagged-line content.

    Project-level findings (synthetic line anchors) and unreadable files fall
    back to the snippet, which is deterministic for those scanners.

    Args:
        finding: The finding to fingerprint.
        file_lines: Shared per-run cache of file contents (path → lines).

    Returns:
        A 16-hex-char digest of the stripped content.
    """
    text: str | None = None
    if finding.line >= 1 and not finding.project_level:
        if finding.file not in file_lines:
            try:
                raw = Path(finding.file).read_text(encoding="utf-8", errors="ignore")
                file_lines[finding.file] = raw.splitlines()
            except OSError:
                file_lines[finding.file] = None
        lines = file_lines[finding.file]
        if lines is not None and finding.line <= len(lines):
            text = lines[finding.line - 1]
    if text is None:
        text = finding.snippet
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]


def _relative_file(finding: Finding, root: Path) -> str:
    """Return the finding's path relative to the scan root, POSIX-style.

    Relative paths keep a committed baseline portable across machines and CI.
    Files outside the root (shouldn't happen) keep their path as-is.
    """
    try:
        return Path(finding.file).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(finding.file).as_posix()


def _keys(findings: list[Finding], root: Path) -> list[BaselineKey]:
    """Compute the identity key for each finding, sharing one file cache."""
    cache: dict[str, list[str] | None] = {}
    return [(_finding_id(f), _relative_file(f, root), _content_hash(f, cache)) for f in findings]


def write_baseline(findings: list[Finding], root: Path, baseline_path: Path) -> int:
    """Write the baseline file for the given findings.

    Args:
        findings: Findings to accept (post-suppression, post-dedupe).
        root: Scan root; file paths are stored relative to it.
        baseline_path: Where to write the JSON file.

    Returns:
        Number of distinct entries written.

    Raises:
        OSError: If the file can't be written.
    """
    entries = [{"id": fid, "file": file, "hash": digest} for fid, file, digest in sorted(set(_keys(findings, root)))]
    payload = {"version": BASELINE_VERSION, "findings": entries}
    baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def load_baseline(baseline_path: Path) -> set[BaselineKey]:
    """Load and validate a baseline file.

    Args:
        baseline_path: Path passed to ``--baseline``.

    Returns:
        The set of accepted finding identities.

    Raises:
        ValueError: If the file is missing, unreadable, or not a valid
            baseline document.
    """
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read baseline file {baseline_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in baseline file {baseline_path}: {exc}") from exc

    entries = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"baseline file {baseline_path} has no 'findings' array — regenerate with --write-baseline")

    keys: set[BaselineKey] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in ("id", "file", "hash")):
            raise ValueError(f"baseline file {baseline_path} has a malformed entry — regenerate with --write-baseline")
        keys.add((entry["id"], entry["file"], entry["hash"]))
    return keys


def filter_baselined(findings: list[Finding], root: Path, known: set[BaselineKey]) -> list[Finding]:
    """Drop findings whose identity appears in the baseline.

    Args:
        findings: Findings from the current scan.
        root: Scan root used when the baseline was written.
        known: Identities loaded from the baseline file.

    Returns:
        Only the findings not covered by the baseline.
    """
    return [f for f, key in zip(findings, _keys(findings, root), strict=True) if key not in known]
