"""Tests for the scan orchestrator — inline `scout: ignore` suppression."""

from __future__ import annotations

from scout.agents.scout_agent import _apply_inline_suppressions, run_scout
from scout.config import load_config
from scout.models import Finding


def _finding(
    file: str,
    line: int,
    scanner: str = "injection",
    title: str = "eval() usage",
    project_level: bool = False,
) -> Finding:
    return Finding(
        file=file,
        line=line,
        severity="CRITICAL",
        title=title,
        description="d",
        scanner=scanner,
        project_level=project_level,
    )


def test_bare_ignore_suppresses(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("x = eval(user_input)  # scout: ignore\n", encoding="utf-8")
    assert _apply_inline_suppressions([_finding(str(target), 1)]) == []


def test_unmarked_line_is_kept(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("x = eval(user_input)\n", encoding="utf-8")
    findings = [_finding(str(target), 1)]
    assert _apply_inline_suppressions(findings) == findings


def test_scoped_ignore_matches_scanner_name(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("x = eval(user_input)  # scout: ignore[injection]\n", encoding="utf-8")
    assert _apply_inline_suppressions([_finding(str(target), 1)]) == []


def test_scoped_ignore_matches_finding_id(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("x = eval(user_input)  # scout: ignore[injection/eval_usage]\n", encoding="utf-8")
    assert _apply_inline_suppressions([_finding(str(target), 1)]) == []


def test_scoped_ignore_keeps_other_rules(tmp_path):
    # An ignore scoped to a different scanner must not suppress this finding.
    target = tmp_path / "app.py"
    target.write_text("x = eval(user_input)  # scout: ignore[secrets]\n", encoding="utf-8")
    findings = [_finding(str(target), 1)]
    assert _apply_inline_suppressions(findings) == findings


def test_project_level_findings_are_never_suppressed(tmp_path):
    # The CSRF finding anchors to a synthetic line 1 — a scout: ignore that
    # happens to sit there must not swallow an app-wide finding.
    target = tmp_path / "server.py"
    target.write_text("# scout: ignore\nfrom flask import Flask\n", encoding="utf-8")
    finding = _finding(str(target), 1, scanner="headers", title="No CSRF protection detected", project_level=True)
    assert _apply_inline_suppressions([finding]) == [finding]


def test_line_zero_findings_are_never_suppressed():
    finding = _finding("package.json", 0, scanner="deps", title="Vulnerable package: x")
    assert _apply_inline_suppressions([finding]) == [finding]


def test_unreadable_file_keeps_finding(tmp_path):
    finding = _finding(str(tmp_path / "does-not-exist.py"), 3)
    assert _apply_inline_suppressions([finding]) == [finding]


def test_suppression_end_to_end_via_run_scout(tmp_path):
    (tmp_path / "app.py").write_text(
        'os.system("ls " + a)\nos.system("ls " + b)  # scout: ignore\n',
        encoding="utf-8",
    )
    outcome = run_scout(tmp_path, load_config(ai_provider="none"), quiet=True)
    injection_lines = [f.line for f in outcome.findings if f.scanner == "injection"]
    assert injection_lines == [1]
