"""Tests for the CodeQL engine (scout/engines/codeql.py)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scout.engines import get_engines
from scout.engines.codeql import CodeQLEngine, detect_languages, parse_sarif

# Captured shape of `codeql database analyze --format=sarif-latest` output —
# no real CodeQL in CI.
SARIF_SAMPLE = json.dumps(
    {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "js/xss",
                                "helpUri": "https://codeql.github.com/codeql-query-help/javascript/js-xss/",
                                "properties": {"security-severity": "9.8", "problem.severity": "error"},
                            },
                            {"id": "js/unused-local-variable", "properties": {}},
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "js/xss",
                        "level": "error",
                        "message": {"text": "Cross-site scripting vulnerability due to user-provided value."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.js"},
                                    "region": {"startLine": 42, "snippet": {"text": "el.innerHTML = req.query.q"}},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "js/unused-local-variable",
                        "level": "note",
                        "message": {"text": "Unused variable x."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/util.js"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    },
                ],
            }
        ]
    }
)


def test_parse_maps_sarif_to_findings():
    findings = parse_sarif(SARIF_SAMPLE, Path("proj"))
    assert len(findings) == 2

    xss = findings[0]
    assert xss.file == str(Path("proj") / "src" / "app.js")
    assert xss.line == 42
    assert xss.severity == "CRITICAL"  # security-severity 9.8
    assert xss.title == "js/xss"
    assert xss.scanner == "codeql"
    assert xss.snippet == "el.innerHTML = req.query.q"
    assert xss.fix_phase == 3
    assert xss.references == ["https://codeql.github.com/codeql-query-help/javascript/js-xss/"]

    unused = findings[1]
    assert unused.severity == "LOW"  # no score → SARIF level "note"
    assert unused.line == 7


def test_parse_security_severity_bands():
    def sarif_with(properties: dict, level: str = "warning") -> str:
        return json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": "r", "properties": properties}]}},
                        "results": [{"ruleId": "r", "level": level, "locations": []}],
                    }
                ]
            }
        )

    assert parse_sarif(sarif_with({"security-severity": "7.5"}), Path("p"))[0].severity == "HIGH"
    assert parse_sarif(sarif_with({"security-severity": "5.0"}), Path("p"))[0].severity == "MEDIUM"
    assert parse_sarif(sarif_with({"security-severity": "2.0"}), Path("p"))[0].severity == "LOW"
    assert parse_sarif(sarif_with({"security-severity": "bogus"}), Path("p"))[0].severity == "MEDIUM"  # → level
    assert parse_sarif(sarif_with({}, level="mystery"), Path("p"))[0].severity == "MEDIUM"


def test_parse_result_without_location_defaults():
    doc = json.dumps({"runs": [{"tool": {"driver": {"rules": []}}, "results": [{"ruleId": "js/x"}]}]})
    (finding,) = parse_sarif(doc, Path("proj"))
    assert finding.file == str(Path("proj"))
    assert finding.line == 1
    assert finding.description == "CodeQL rule js/x matched."


def test_parse_invalid_sarif_raises():
    with pytest.raises(ValueError, match="invalid SARIF JSON"):
        parse_sarif("codeql exploded", Path("p"))
    with pytest.raises(ValueError, match="unexpected SARIF shape"):
        parse_sarif("[1, 2]", Path("p"))


def test_get_engines_returns_codeql():
    (engine,) = get_engines(("codeql",))
    assert isinstance(engine, CodeQLEngine)


def test_detect_languages(tmp_path):
    assert detect_languages(tmp_path) == []
    (tmp_path / "app.ts").write_text("let x = 1\n", encoding="utf-8")
    assert detect_languages(tmp_path) == ["javascript"]
    (tmp_path / "job.py").write_text("x = 1\n", encoding="utf-8")
    assert detect_languages(tmp_path) == ["javascript", "python"]
    assert detect_languages(tmp_path / "job.py") == ["python"]


def test_run_creates_db_analyzes_and_parses(tmp_path, monkeypatch):
    (tmp_path / "app.js").write_text("el.innerHTML = q\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        output = next((arg.split("=", 1)[1] for arg in cmd if arg.startswith("--output=")), None)
        if output:  # the analyze step writes the SARIF file
            Path(output).write_text(SARIF_SAMPLE, encoding="utf-8")
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr("scout.engines.codeql.shutil.which", lambda _: "/usr/bin/codeql")
    monkeypatch.setattr("scout.engines.codeql.subprocess.run", fake_run)
    findings = CodeQLEngine().run(tmp_path)

    assert [cmd[1:3] for cmd in commands] == [["database", "create"], ["database", "analyze"]]
    create, analyze = commands
    assert "--language=javascript" in create
    assert f"--source-root={tmp_path}" in create
    assert "codeql/javascript-queries" in analyze
    assert "--format=sarif-latest" in analyze
    assert len(findings) == 2
    assert findings[0].scanner == "codeql"
    # SARIF URIs resolve against the scan root.
    assert findings[0].file == str(tmp_path / "src" / "app.js")


def test_run_skips_unsupported_tree_with_note(tmp_path, monkeypatch, capsys):
    (tmp_path / "notes.txt").write_text("hi\n", encoding="utf-8")
    monkeypatch.setattr("scout.engines.codeql.shutil.which", lambda _: "/usr/bin/codeql")
    assert CodeQLEngine().run(tmp_path) == []
    assert "no files in a CodeQL-supported language" in capsys.readouterr().err


def test_run_fails_open_on_subprocess_error(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    def boom(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1800)

    monkeypatch.setattr("scout.engines.codeql.shutil.which", lambda _: "/usr/bin/codeql")
    monkeypatch.setattr("scout.engines.codeql.subprocess.run", boom)
    assert CodeQLEngine().run(tmp_path) == []
    assert "codeql engine" in capsys.readouterr().err


def test_run_fails_open_on_nonzero_exit(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr("scout.engines.codeql.shutil.which", lambda _: "/usr/bin/codeql")
    monkeypatch.setattr(
        "scout.engines.codeql.subprocess.run",
        lambda cmd, **kwargs: SimpleNamespace(stdout="", stderr="extractor blew up", returncode=2),
    )
    assert CodeQLEngine().run(tmp_path) == []
    err = capsys.readouterr().err
    assert "exited 2" in err
    assert "extractor blew up" in err
