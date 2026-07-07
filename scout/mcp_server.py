"""Scout MCP server — exposes the deterministic scan as an agent-callable tool.

Wraps the same scan → JSON pipeline the CLI uses so a coding agent (Claude
Code, Cursor, …) can run Scout as a cheap, deterministic verifier inside a
scan → fix → rescan loop without paying for inference. Served over stdio via
the ``scout-mcp`` entry point; needs the ``mcp`` extra:
``pip install "scout-security[mcp]"``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from scout.agents.reporter_agent import generate_json
from scout.agents.scout_agent import run_scout
from scout.config import load_config

mcp = FastMCP("scout")

# ponytail: no `scan_diff` tool — mapping findings to a git diff's changed
# lines isn't cheap, and `scan_path` already covers the fix → rescan loop.
# Add it if agents ask to scan only staged changes.


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


def main() -> None:
    """Entry point for the ``scout-mcp`` console script (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
