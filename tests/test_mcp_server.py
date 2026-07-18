"""Scout MCP server (T2.2) — stdio round-trip + in-process checks.

The acceptance test spawns the server as a subprocess over stdio with the MCP
client library and asserts structured findings come back. In-process tests
cover the tool body (the subprocess is invisible to coverage) and the entry
point.
"""

from __future__ import annotations

import json
import subprocess
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

VULN_LINE = 'os.system("ls " + user_input)\n'


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=scout@test.invalid",
            "-c",
            "user.name=scout-test",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _diff_repo(tmp_path: Path) -> Path:
    """Repo with a committed vulnerable file and uncommitted changes.

    Committed: old.py (pre-existing finding — must NOT appear in scan_diff).
    Uncommitted: a vulnerable line appended to edited.py (tracked change) and
    a brand-new new.py (untracked).
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "old.py").write_text(VULN_LINE, encoding="utf-8")
    (repo / "edited.py").write_text("print('clean')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    (repo / "edited.py").write_text("print('clean')\n" + VULN_LINE, encoding="utf-8")
    (repo / "new.py").write_text("result = eval(user_input)\n", encoding="utf-8")
    return repo


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


def test_scan_diff_reports_only_changed_lines(tmp_path) -> None:
    from scout.mcp_server import scan_diff

    repo = _diff_repo(tmp_path)
    payload = scan_diff(str(repo))
    files = {Path(f["file"]).name for f in payload["findings"]}
    assert "edited.py" in files, "changed line in a tracked file must be reported"
    assert "new.py" in files, "untracked files count as fully changed"
    assert "old.py" not in files, "pre-existing findings must be filtered out"
    # The tracked file's finding sits on the appended line, not line 1.
    edited = next(f for f in payload["findings"] if Path(f["file"]).name == "edited.py")
    assert edited["line"] == 2


def test_scan_diff_clean_worktree_is_empty(tmp_path) -> None:
    from scout.mcp_server import scan_diff

    repo = _diff_repo(tmp_path)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "commit everything")
    payload = scan_diff(str(repo))
    assert payload["findings"] == []


def test_scan_diff_outside_repo_errors(tmp_path) -> None:
    from scout.mcp_server import scan_diff

    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    with pytest.raises(ValueError, match="not a git repository"):
        scan_diff(str(plain))


def test_scan_diff_missing_path_errors() -> None:
    from scout.mcp_server import scan_diff

    with pytest.raises(FileNotFoundError):
        scan_diff(str(FIXTURES / "definitely-not-here"))


async def _scan_diff_over_stdio(path: str) -> CallToolResult:
    """Spawn the server over stdio and call scan_diff on a temp repo."""
    params = StdioServerParameters(command=sys.executable, args=["-m", "scout.mcp_server"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert "scan_diff" in {t.name for t in tools.tools}
            return await session.call_tool("scan_diff", {"path": path}, read_timeout_seconds=timedelta(seconds=60))


def test_scan_diff_over_stdio(tmp_path) -> None:
    repo = _diff_repo(tmp_path)
    result = anyio.run(_scan_diff_over_stdio, str(repo))
    assert result.isError is False
    block = result.content[0]
    assert isinstance(block, TextContent)
    payload = json.loads(block.text)
    names = {Path(f["file"]).name for f in payload["findings"]}
    assert "old.py" not in names
    assert {"edited.py", "new.py"} <= names


def test_entry_point_declared() -> None:
    # Drift guard: the console script must resolve to the real callable.
    from scout.mcp_server import main

    assert callable(main)
    assert 'scout-mcp = "scout.mcp_server:main"' in PYPROJECT.read_text(encoding="utf-8")
