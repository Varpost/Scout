"""Tests for the external engine orchestrator (scout/engines/)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from scout.cli import app
from scout.config import ScoutConfig, load_config
from scout.engines import get_engines
from scout.engines.semgrep import SemgrepEngine, parse_semgrep_json
from scout.models import Finding

runner = CliRunner()

# Captured shape of `semgrep scan --json` output — no real semgrep in CI.
SEMGREP_JSON = json.dumps(
    {
        "results": [
            {
                "check_id": "python.lang.security.audit.subprocess-shell-true",
                "path": "app/main.py",
                "start": {"line": 12, "col": 1},
                "end": {"line": 12, "col": 40},
                "extra": {
                    "message": "subprocess call with shell=True identified.",
                    "severity": "ERROR",
                    "lines": "subprocess.run(cmd, shell=True)",
                    "metadata": {"references": ["https://example.com/subprocess-rule"]},
                },
            },
            {
                "check_id": "python.flask.security.audit.debug-enabled",
                "path": "app/server.py",
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {
                    "message": "Flask app run with debug=True.",
                    "severity": "WARNING",
                    "lines": "app.run(debug=True)",
                    "fix": "app.run(debug=False)",
                    "metadata": {},
                },
            },
        ],
        "errors": [],
    }
)


def _config(engines: tuple[str, ...] = ("semgrep",)) -> ScoutConfig:
    return ScoutConfig(
        ai_provider="none",
        anthropic_key=None,
        openai_key=None,
        ollama_host="http://localhost:11434",
        ollama_model="llama3",
        engines=engines,
    )


def test_parse_maps_results_to_findings():
    findings = parse_semgrep_json(SEMGREP_JSON)
    assert len(findings) == 2

    shell = findings[0]
    assert shell.file == str(Path("app/main.py"))
    assert shell.line == 12
    assert shell.severity == "HIGH"  # ERROR → HIGH
    assert shell.title == "subprocess-shell-true"
    assert shell.scanner == "semgrep"
    assert shell.snippet == "subprocess.run(cmd, shell=True)"
    assert shell.fix_phase == 3  # no autofix shipped
    assert shell.references == ["https://example.com/subprocess-rule"]

    debug = findings[1]
    assert debug.severity == "MEDIUM"  # WARNING → MEDIUM
    assert debug.fix_phase == 1  # rule ships an autofix → mechanical fix


def test_parse_unknown_severity_defaults_to_medium():
    doc = json.dumps(
        {"results": [{"check_id": "r.x", "path": "a.py", "start": {"line": 1}, "extra": {"severity": "BOGUS"}}]}
    )
    assert parse_semgrep_json(doc)[0].severity == "MEDIUM"


def test_parse_invalid_json_raises():
    with pytest.raises(ValueError, match="invalid JSON"):
        parse_semgrep_json("semgrep exploded")
    with pytest.raises(ValueError, match="unexpected JSON shape"):
        parse_semgrep_json("[1, 2]")


def test_unknown_engine_name_raises():
    with pytest.raises(ValueError, match="unknown engine"):
        get_engines(("nope",))


def test_get_engines_returns_semgrep():
    (engine,) = get_engines(("semgrep",))
    assert isinstance(engine, SemgrepEngine)


def test_run_invokes_semgrep_and_parses(monkeypatch):
    seen: dict[str, list[str]] = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return SimpleNamespace(stdout=SEMGREP_JSON, stderr="", returncode=1)

    monkeypatch.setattr("scout.engines.semgrep.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("scout.engines.semgrep.subprocess.run", fake_run)
    findings = SemgrepEngine().run(Path("proj"))
    assert len(findings) == 2
    assert seen["cmd"][0] == "/usr/bin/semgrep"
    assert "--json" in seen["cmd"]


def test_run_fails_open_on_subprocess_error(monkeypatch, capsys):
    def boom(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 600)

    monkeypatch.setattr("scout.engines.semgrep.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("scout.engines.semgrep.subprocess.run", boom)
    assert SemgrepEngine().run(Path("proj")) == []
    assert "semgrep engine" in capsys.readouterr().err


def test_run_fails_open_on_garbage_output(monkeypatch, capsys):
    monkeypatch.setattr("scout.engines.semgrep.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        "scout.engines.semgrep.subprocess.run",
        lambda cmd, **kwargs: SimpleNamespace(stdout="not json", stderr="ruleset error", returncode=2),
    )
    assert SemgrepEngine().run(Path("proj")) == []
    err = capsys.readouterr().err
    assert "invalid JSON" in err
    assert "exit code 2" in err


def test_scan_skips_missing_engine_with_note(tmp_path, monkeypatch, capsys):
    from scout.agents.scout_agent import run_scout

    (tmp_path / "app.py").write_text('os.system("ls " + user_input)\n', encoding="utf-8")
    monkeypatch.setattr("scout.engines.shutil.which", lambda _: None)
    outcome = run_scout(tmp_path, _config(), quiet=True)
    # Native findings still present; engine skipped with one visible note.
    assert any(f.scanner == "injection" for f in outcome.findings)
    assert not any(f.scanner == "semgrep" for f in outcome.findings)
    assert "not installed" in capsys.readouterr().err


def test_scan_merges_engine_findings_and_dedupes_native_lines(tmp_path, monkeypatch):
    from scout.agents.scout_agent import run_scout

    target = tmp_path / "app.py"
    target.write_text('os.system("ls " + user_input)\n', encoding="utf-8")

    def fake_run(self, path):
        return [
            # Collides with the native os.system finding at (file, line 1) → dropped.
            Finding(
                file=str(target),
                line=1,
                severity="HIGH",
                title="dangerous-system-call",
                description="dup",
                scanner="semgrep",
            ),
            # New line → merged.
            Finding(
                file=str(target),
                line=99,
                severity="CRITICAL",
                title="unique-semgrep-rule",
                description="new",
                scanner="semgrep",
            ),
        ]

    monkeypatch.setattr(SemgrepEngine, "available", lambda self: True)
    monkeypatch.setattr(SemgrepEngine, "run", fake_run)
    outcome = run_scout(tmp_path, _config(), quiet=True)
    titles = {f.title for f in outcome.findings}
    assert "unique-semgrep-rule" in titles
    assert "dangerous-system-call" not in titles
    assert any(f.scanner == "injection" for f in outcome.findings)


def test_scan_without_engines_never_touches_engine_code(tmp_path, monkeypatch):
    from scout.agents.scout_agent import run_scout

    def boom(self, path):  # pragma: no cover — must not be called
        raise AssertionError("engine ran without being requested")

    monkeypatch.setattr(SemgrepEngine, "run", boom)
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    outcome = run_scout(tmp_path, _config(engines=()), quiet=True)
    assert outcome.files_scanned == 1


def test_config_engines_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.scout]\nengines = ["semgrep"]\n', encoding="utf-8")
    config = load_config(project_path=tmp_path)
    assert config.engines == ("semgrep",)
    # CLI flag replaces the config list entirely.
    config = load_config(project_path=tmp_path, cli_engines=["other"])
    assert config.engines == ("other",)


def test_config_engines_wrong_type_raises(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.scout]\nengines = "semgrep"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="engines must be an array of strings"):
        load_config(project_path=tmp_path)


def test_cli_rejects_unknown_engine(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--engine", "nope"])
    assert result.exit_code == 2
    assert "unknown engine" in result.output
