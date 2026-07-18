"""Scout MCP server — exposes the deterministic scan as an agent-callable tool.

Wraps the same scan → JSON pipeline the CLI uses so a coding agent (Claude
Code, Cursor, …) can run Scout as a cheap, deterministic verifier inside a
scan → fix → rescan loop without paying for inference. Served over stdio via
the ``scout-mcp`` entry point; needs the ``mcp`` extra:
``pip install "scout-security[mcp]"``.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from scout.agents.reporter_agent import generate_json
from scout.agents.scout_agent import run_scout
from scout.config import load_config

mcp = FastMCP("scout")

# `@@ -a[,b] +c[,d] @@` — c is the first new line, d the new-line count.
_HUNK_HEADER = re.compile(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@")


def _changed_lines(root: Path) -> dict[str, set[int]]:
    """Map absolute file paths to the line numbers changed vs HEAD.

    Covers staged + unstaged edits (``git diff HEAD``) plus untracked files
    (every line counts as changed — agents in a fix loop create new files).

    Args:
        root: Directory inside the git repository.

    Returns:
        ``{absolute_path: changed_line_numbers}``; an empty set means the
        whole file is new (all lines changed).

    Raises:
        ValueError: the git diff subprocess fails.
    """
    # stdin=DEVNULL: a child inheriting this server's protocol stdin pipe
    # deadlocks the whole stdio session on Windows.
    diff = subprocess.run(
        ["git", "-C", str(root), "diff", "HEAD", "--unified=0", "--no-color", "--no-renames"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if diff.returncode != 0:
        raise ValueError(f"git diff failed: {diff.stderr.strip() or 'unknown error'}")

    changed: dict[str, set[int]] = {}
    current: set[int] | None = None
    for line in diff.stdout.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target.startswith('"') and target.endswith('"'):
                target = target[1:-1]
            # `+++ /dev/null` (deletion) has no b/ prefix and is skipped.
            if target.startswith("b/"):
                current = changed.setdefault(str(root / target[2:]), set())
            else:
                current = None
        elif line.startswith("@@") and current is not None:
            match = _HUNK_HEADER.match(line)
            if match:
                start = int(match.group(1))
                count = int(match.group(2)) if match.group(2) is not None else 1
                current.update(range(start, start + count))  # count 0 = pure deletion

    untracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if untracked.returncode == 0:
        for rel in untracked.stdout.splitlines():
            if rel.strip():
                changed[str(root / rel.strip())] = set()  # empty = whole file
    return changed


@mcp.tool()
def scan_path(path: str) -> dict[str, Any]:
    """Scan a file or directory for security vulnerabilities.

    Runs Scout's deterministic static analysis — same scan, same findings, no
    AI and no tokens (the only network is the dependency scanner's OSV lookups)
    — and returns the Layer-3 JSON: each finding's file, line, severity,
    scanner, title, explanation, fix guidance, and stable id. Point a fix loop
    at these and call again to verify.

    Args:
        path: File or directory to scan.

    Returns:
        The findings payload: ``tool``, ``version``, ``files_scanned``,
        ``severity_counts``, and ``findings[]``.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"path does not exist: {path}")
    # AI off (deterministic); the scanned project's [tool.scout] still applies.
    config = load_config(project_path=target)
    outcome = run_scout(target, config, quiet=True)
    document = generate_json(
        outcome.findings,
        output_path=None,
        project_path=target,
        files_scanned=outcome.files_scanned,
    )
    payload: dict[str, Any] = json.loads(document)
    return payload


@mcp.tool()
def scan_diff(path: str = ".") -> dict[str, Any]:
    """Scan only the lines changed since the last commit — the fix-loop tool.

    Runs the same deterministic scan as ``scan_path``, then keeps only
    findings on lines you changed (staged + unstaged edits vs HEAD, plus
    untracked files in full). Call after editing to check exactly what your
    change introduced, without wading through pre-existing findings.
    Project-level findings (app-wide checks with no single line) are
    excluded. Zero tokens; the only network is the dependency scanner's OSV
    lookups.

    Args:
        path: Directory inside a git repository (default: current directory).

    Returns:
        Same payload shape as ``scan_path``: ``tool``, ``version``,
        ``files_scanned`` (changed files considered), ``severity_counts``,
        and ``findings[]`` limited to changed lines.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If git is missing, ``path`` is not in a git repository,
            or the diff cannot be read.
    """
    from scout.git_history import _ensure_git_repo

    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"path does not exist: {path}")
    root = target if target.is_dir() else target.parent
    _ensure_git_repo(root)

    changed = _changed_lines(root)
    config = load_config(project_path=root)
    outcome = run_scout(root, config, quiet=True)
    kept = []
    for finding in outcome.findings:
        if finding.project_level:
            continue
        lines = changed.get(str(Path(finding.file)))
        if lines is None:
            continue
        if not lines or finding.line in lines:  # empty set = new file, all lines
            kept.append(finding)

    document = generate_json(kept, output_path=None, project_path=root, files_scanned=len(changed))
    payload: dict[str, Any] = json.loads(document)
    return payload


def main() -> None:
    """Entry point for the ``scout-mcp`` console script (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
