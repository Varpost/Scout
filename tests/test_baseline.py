"""Tests for the baseline workflow (--write-baseline / --baseline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scout.baseline import load_baseline
from scout.cli import app

runner = CliRunner()


def _make_project(tmp_path) -> Path:
    # Reports/baselines written outside the project would pollute other
    # tests' assertions if they landed inside the scan root — keep the
    # scanned tree in its own subdirectory.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("result = eval(user_input)\n", encoding="utf-8")
    return proj


def test_write_baseline_then_rescan_is_clean(tmp_path):
    proj = _make_project(tmp_path)

    # Sanity: the finding gates the exit code before any baseline exists.
    assert runner.invoke(app, ["scan", str(proj), "--no-ai"]).exit_code == 1

    write = runner.invoke(app, ["scan", str(proj), "--no-ai", "--write-baseline"])
    assert write.exit_code == 0
    baseline = proj / ".scout-baseline.json"
    assert baseline.exists()

    rescan = runner.invoke(app, ["scan", str(proj), "--no-ai", "--baseline", str(baseline)])
    assert rescan.exit_code == 0
    assert "No vulnerabilities found" in rescan.output


def test_new_finding_alone_is_reported_and_fails(tmp_path):
    proj = _make_project(tmp_path)
    runner.invoke(app, ["scan", str(proj), "--no-ai", "--write-baseline"])

    (proj / "worker.py").write_text('os.system("ls " + user_input)\n', encoding="utf-8")
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(proj),
            "--no-ai",
            "--baseline",
            str(proj / ".scout-baseline.json"),
            "--format",
            "json",
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 1
    findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
    assert len(findings) == 1
    assert findings[0]["file"].endswith("worker.py")


def test_unrelated_lines_above_do_not_resurrect_baselined_finding(tmp_path):
    proj = _make_project(tmp_path)
    runner.invoke(app, ["scan", str(proj), "--no-ai", "--write-baseline"])

    # Shift the flagged line down — line-based identity would resurrect it.
    (proj / "app.py").write_text(
        "import os\nimport sys\n\n\nresult = eval(user_input)\n",
        encoding="utf-8",
    )
    rescan = runner.invoke(app, ["scan", str(proj), "--no-ai", "--baseline", str(proj / ".scout-baseline.json")])
    assert rescan.exit_code == 0


def test_editing_the_flagged_line_brings_the_finding_back(tmp_path):
    proj = _make_project(tmp_path)
    runner.invoke(app, ["scan", str(proj), "--no-ai", "--write-baseline"])

    (proj / "app.py").write_text("result = eval(other_input)\n", encoding="utf-8")
    rescan = runner.invoke(app, ["scan", str(proj), "--no-ai", "--baseline", str(proj / ".scout-baseline.json")])
    assert rescan.exit_code == 1


def test_baseline_stores_relative_posix_paths(tmp_path):
    proj = _make_project(tmp_path)
    runner.invoke(app, ["scan", str(proj), "--no-ai", "--write-baseline"])

    entries = json.loads((proj / ".scout-baseline.json").read_text(encoding="utf-8"))["findings"]
    assert entries, "the eval finding should have been accepted"
    for entry in entries:
        assert not Path(entry["file"]).is_absolute()
        assert "\\" not in entry["file"]


def test_write_baseline_honors_custom_baseline_path(tmp_path):
    proj = _make_project(tmp_path)
    custom = tmp_path / "accepted.json"

    write = runner.invoke(app, ["scan", str(proj), "--no-ai", "--write-baseline", "--baseline", str(custom)])
    assert write.exit_code == 0
    assert custom.exists()

    rescan = runner.invoke(app, ["scan", str(proj), "--no-ai", "--baseline", str(custom)])
    assert rescan.exit_code == 0


def test_write_baseline_on_clean_project(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("print('hi')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(proj), "--no-ai", "--write-baseline"])
    assert result.exit_code == 0
    data = json.loads((proj / ".scout-baseline.json").read_text(encoding="utf-8"))
    assert data["findings"] == []


def test_missing_baseline_file_exits_2(tmp_path):
    proj = _make_project(tmp_path)
    result = runner.invoke(app, ["scan", str(proj), "--no-ai", "--baseline", str(tmp_path / "nope.json")])
    assert result.exit_code == 2


def test_malformed_baseline_exits_2(tmp_path):
    proj = _make_project(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(proj), "--no-ai", "--baseline", str(bad)])
    assert result.exit_code == 2


def test_load_baseline_rejects_wrong_schema(tmp_path):
    bad = tmp_path / "b.json"
    bad.write_text('{"findings": [{"id": 1}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="malformed entry"):
        load_baseline(bad)


def test_load_baseline_rejects_missing_findings_array(tmp_path):
    bad = tmp_path / "b.json"
    bad.write_text('{"version": 1}', encoding="utf-8")
    with pytest.raises(ValueError, match="no 'findings' array"):
        load_baseline(bad)
