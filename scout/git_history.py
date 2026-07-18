"""Scan git history for secrets — a secret committed then removed is still compromised.

HEAD-only scanning misses credentials that were committed and later deleted;
this walks every commit on every branch (``git log -p --all`` via subprocess —
deliberately not gitpython, which was dropped as a dependency) and runs the
existing secrets patterns over each commit's added lines.

Honest scope (also in the README): Gitleaks and TruffleHog do deep, fast
history secret-scanning as their core job. This is the built-in convenience
pass, not a replacement — point a serious history audit at those.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from scout.agents.scout_agent import ScanOutcome
from scout.models import Finding, severity_rank
from scout.scanners.secrets import SecretsScanner

_COMMIT_PREFIX = "COMMIT "
_HUNK_NEW_START = re.compile(r"@@ -\S+ \+(\d+)")


def _ensure_git_repo(root: Path) -> None:
    """Fail fast with a clear message when git or the repository is missing.

    Args:
        root: Directory that should be inside a git repository.

    Raises:
        ValueError: git is not on PATH, or ``root`` is not in a git repo.
    """
    try:
        # stdin=DEVNULL: scan_diff calls this inside the stdio MCP server,
        # where a child inheriting the protocol stdin pipe deadlocks (Windows).
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--git-dir"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise ValueError("--git-history needs the `git` executable on PATH") from None
    if result.returncode != 0:
        raise ValueError(f"not a git repository: {root}")


def _collect_added_lines(root: Path) -> dict[tuple[str, str], list[tuple[int, str]]]:
    """Stream ``git log -p --all`` and gather added lines per (commit, file).

    Args:
        root: Directory inside the git repository.

    Returns:
        Mapping of ``(commit_sha, file_path)`` to ``(new_file_line, text)``
        pairs for every ``+`` line in that commit's diff.

    Raises:
        ValueError: the git subprocess exits non-zero.
    """
    # ponytail: whole-history added lines held in memory — flush per commit
    # if this ever hurts on monorepo-scale histories.
    added: dict[tuple[str, str], list[tuple[int, str]]] = {}
    proc = subprocess.Popen(
        [
            "git",
            "-C",
            str(root),
            "log",
            "--all",
            "-p",
            "--unified=0",
            "--no-color",
            "--no-renames",
            "--pretty=format:COMMIT %H",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    sha = ""
    current_file: str | None = None
    new_line = 0
    for raw in proc.stdout or []:
        line = raw.rstrip("\n")
        if line.startswith(_COMMIT_PREFIX):
            sha = line[len(_COMMIT_PREFIX) :].strip()
            current_file = None
        elif line.startswith("+++ "):
            target = line[4:].strip()
            if target.startswith('"') and target.endswith('"'):
                target = target[1:-1]
            # `+++ /dev/null` (deletion) has no b/ prefix and is skipped.
            current_file = target[2:] if target.startswith("b/") else None
        elif line.startswith("@@"):
            match = _HUNK_NEW_START.match(line)
            new_line = int(match.group(1)) if match else 0
        elif line.startswith("+") and current_file is not None and sha:
            added.setdefault((sha, current_file), []).append((new_line, line[1:]))
            new_line += 1
    if proc.wait() != 0:
        raise ValueError("git log failed while reading history")
    return added


def scan_git_history(root: Path) -> ScanOutcome:
    """Scan every commit on every branch for added lines that leak secrets.

    Each commit's added lines are fed through the secrets scanner as a
    pseudo-file (inheriting all its placeholder/comment filtering), then
    findings are remapped to the real line number in that commit's version of
    the file and anchored to the commit: ``file`` becomes
    ``<path> @ <short-sha>`` and the description names the full SHA. Deduped
    on (commit, file, line, title).

    Args:
        root: Directory inside the git repository to audit.

    Returns:
        ScanOutcome with severity-sorted findings; ``files_scanned`` is the
        number of distinct (commit, file) diffs whose added lines were
        scanned.

    Raises:
        ValueError: git is missing, ``root`` is not a git repository, or the
            log subprocess fails.
    """
    _ensure_git_repo(root)
    added = _collect_added_lines(root)

    scanner = SecretsScanner()
    seen: set[tuple[str, str, int, str]] = set()
    findings: list[Finding] = []
    for (commit, file), entries in added.items():
        pseudo_content = "\n".join(text for _, text in entries)
        for finding in scanner.scan_file(Path(file), pseudo_content):
            real_line, text = entries[finding.line - 1]
            key = (commit, file, real_line, finding.title)
            if key in seen:
                continue
            seen.add(key)
            finding.file = f"{file} @ {commit[:12]}"
            finding.line = real_line
            finding.snippet = text
            finding.description = (
                f"Committed in {commit}. {finding.description} "
                "Deleting it from the current code does not un-leak it — rotate the credential."
            )
            findings.append(finding)

    findings.sort(key=lambda f: severity_rank(f.severity))
    return ScanOutcome(findings=findings, files_scanned=len(added))
