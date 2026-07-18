"""Tests for the custom scanner — user-defined YAML rules."""

from __future__ import annotations

from pathlib import Path

from scout.config import load_config
from scout.scanners import get_all_scanners
from scout.scanners.custom import CustomScanner, load_rules


def _project(tmp_path: Path, rules_yaml: str) -> Path:
    (tmp_path / "pyproject.toml").write_text('[tool.scout]\nrules = ["scout-rules.yml"]\n', encoding="utf-8")
    (tmp_path / "scout-rules.yml").write_text(rules_yaml, encoding="utf-8")
    return tmp_path


VALID_RULE = """\
rules:
  - id: internal-api-host
    pattern: "internal\\\\.corp\\\\.example"
    message: "Internal hostname committed to source."
    severity: HIGH
    fix_phase: 1
    fix: "Move the hostname to configuration."
"""


def test_custom_scanner_is_registered():
    assert any(cls.name == "custom" for cls in get_all_scanners())


def test_valid_rule_produces_finding(tmp_path):
    project = _project(tmp_path, VALID_RULE)
    target = project / "app.py"
    target.write_text('url = "https://internal.corp.example/api"\n', encoding="utf-8")
    findings = CustomScanner().scan([target])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "internal-api-host"
    assert finding.severity == "HIGH"
    assert finding.fix_phase == 1
    assert finding.scanner == "custom"
    assert finding.fix_summary == "Move the hostname to configuration."
    assert finding.line == 1


def test_no_rules_config_means_no_findings_and_no_warnings(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.scout]\n", encoding="utf-8")
    target = tmp_path / "app.py"
    target.write_text("anything = 1\n", encoding="utf-8")
    assert CustomScanner().scan([target]) == []
    assert capsys.readouterr().err == ""


def test_malformed_rule_warns_and_others_still_run(tmp_path, capsys):
    yaml_text = """\
rules:
  - id: bad-regex
    pattern: "([unclosed"
    message: "broken"
    severity: HIGH
  - id: works
    pattern: "TODO-SECURITY"
    message: "flagged"
    severity: LOW
"""
    project = _project(tmp_path, yaml_text)
    target = project / "app.py"
    target.write_text("# TODO-SECURITY harden this\n", encoding="utf-8")
    findings = CustomScanner().scan([target])
    assert [f.title for f in findings] == ["works"]
    err = capsys.readouterr().err
    assert "bad-regex" in err and "invalid regex" in err


def test_unknown_severity_is_skipped_with_warning(tmp_path, capsys):
    yaml_text = 'rules:\n  - {id: x, pattern: "abc", message: m, severity: BANANAS}\n'
    project = _project(tmp_path, yaml_text)
    target = project / "app.py"
    target.write_text("abc\n", encoding="utf-8")
    assert CustomScanner().scan([target]) == []
    assert "severity" in capsys.readouterr().err


def test_missing_rules_file_warns_not_crashes(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text('[tool.scout]\nrules = ["nope.yml"]\n', encoding="utf-8")
    target = tmp_path / "app.py"
    target.write_text("abc\n", encoding="utf-8")
    assert CustomScanner().scan([target]) == []
    assert "cannot read" in capsys.readouterr().err


def test_invalid_yaml_warns_not_crashes(tmp_path, capsys):
    project = _project(tmp_path, "rules: [unclosed\n")
    target = project / "app.py"
    target.write_text("abc\n", encoding="utf-8")
    assert CustomScanner().scan([target]) == []
    assert "not valid YAML" in capsys.readouterr().err


def test_suffix_filter_limits_rule_to_named_extensions(tmp_path):
    yaml_text = 'rules:\n  - {id: py-only, pattern: "MARKER", message: m, severity: LOW, suffixes: [".py"]}\n'
    project = _project(tmp_path, yaml_text)
    py_file = project / "app.py"
    py_file.write_text("MARKER\n", encoding="utf-8")
    js_file = project / "app.js"
    js_file.write_text("MARKER\n", encoding="utf-8")
    findings = CustomScanner().scan([py_file, js_file])
    assert [Path(f.file).name for f in findings] == ["app.py"]


def test_duplicate_rule_id_skipped(tmp_path, capsys):
    yaml_text = (
        "rules:\n"
        '  - {id: dup, pattern: "aaa", message: first, severity: LOW}\n'
        '  - {id: dup, pattern: "bbb", message: second, severity: LOW}\n'
    )
    project = _project(tmp_path, yaml_text)
    target = project / "app.py"
    target.write_text("aaa bbb\n", encoding="utf-8")
    findings = CustomScanner().scan([target])
    assert [f.description for f in findings] == ["first"]
    assert "duplicate" in capsys.readouterr().err


def test_empty_string_matching_pattern_rejected(tmp_path, capsys):
    yaml_text = 'rules:\n  - {id: empty, pattern: "x*", message: m, severity: LOW}\n'
    project = _project(tmp_path, yaml_text)
    target = project / "app.py"
    target.write_text("xxx\n", encoding="utf-8")
    assert CustomScanner().scan([target]) == []
    assert "empty string" in capsys.readouterr().err


def test_inline_ignore_suppresses_custom_finding(tmp_path):
    from scout.agents.scout_agent import run_scout

    project = _project(tmp_path, VALID_RULE)
    (project / "app.py").write_text(
        'url = "https://internal.corp.example/api"  # scout: ignore[custom]\n', encoding="utf-8"
    )
    outcome = run_scout(project, load_config(ai_provider="none", project_path=project), quiet=True)
    assert not any(f.scanner == "custom" for f in outcome.findings)


def test_load_rules_direct_missing_fields(tmp_path, capsys):
    rules_file = tmp_path / "r.yml"
    rules_file.write_text('rules:\n  - {pattern: "abc", message: m, severity: LOW}\n', encoding="utf-8")
    assert load_rules([rules_file]) == []
    assert "missing a string `id`" in capsys.readouterr().err
