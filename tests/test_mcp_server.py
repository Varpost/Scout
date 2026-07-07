"""Scout MCP server (T2.2) — stdio round-trip + in-process checks.

The acceptance test spawns the server as a subprocess over stdio with the MCP
client library and asserts structured findings come back. In-process tests
cover the tool body (the subprocess is invisible to coverage) and the entry
point.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent

FIXTURES = Path(__file__).parent / "fixtures"
PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"


async def _scan_over_stdio(path: str) -> CallToolResult:
    """Spawn `python -m scout.mcp_server`, initialize, and call scan_path."""
    params = StdioServerParameters(command=sys.executable, args=["-m", "scout.mcp_server"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert "scan_path" in {t.name for t in tools.tools}
            return await session.call_tool("scan_path", {"path": path}, read_timeout_seconds=timedelta(seconds=60))


def test_scan_path_over_stdio_returns_findings() -> None:
    result = anyio.run(_scan_over_stdio, str(FIXTURES))
    assert result.isError is False
    block = result.content[0]
    assert isinstance(block, TextContent)
    payload = json.loads(block.text)
    assert payload["tool"] == "scout"
    assert payload["files_scanned"] > 0
    assert payload["findings"], "fixtures contain deliberate vulnerabilities"
    ids = {f["id"] for f in payload["findings"]}
    assert any(i.startswith(("injection/", "secrets/")) for i in ids)


def test_scan_path_direct_shape() -> None:
    from scout.mcp_server import scan_path

    payload = scan_path(str(FIXTURES))
    assert payload["tool"] == "scout"
    assert payload["files_scanned"] > 0
    assert isinstance(payload["findings"], list)
    assert payload["findings"]


def test_scan_path_missing_path_errors() -> None:
    from scout.mcp_server import scan_path

    with pytest.raises(FileNotFoundError):
        scan_path(str(FIXTURES / "definitely-not-here"))


def test_entry_point_declared() -> None:
    # Drift guard: the console script must resolve to the real callable.
    from scout.mcp_server import main

    assert callable(main)
    assert 'scout-mcp = "scout.mcp_server:main"' in PYPROJECT.read_text(encoding="utf-8")
