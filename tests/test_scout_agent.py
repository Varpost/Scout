"""Tests for the scan orchestrator — suppression, dedupe, and sorting."""

from __future__ import annotations

from scout.agents.scout_agent import _apply_inline_suppressions, _dedupe_findings, run_scout
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


# --- Dedupe + sort -----------------------------------------------------------


def test_dedupe_keeps_distinct_patterns_on_the_same_line():
    findings = [
        _finding("app.py", 1, title="os.system() call"),
        _finding("app.py", 1, title="eval() usage"),
    ]
    assert _dedupe_findings(findings) == findings


def test_dedupe_collapses_true_duplicates():
    findings = [_finding("app.py", 1), _finding("app.py", 1)]
    assert _dedupe_findings(findings) == [findings[0]]


def test_distinct_patterns_on_one_line_both_survive_run_scout(tmp_path):
    # Regression: the (file, line, scanner) key silently dropped the second
    # pattern hit on the same line.
    (tmp_path / "app.py").write_text("os.system(eval(payload))\n", encoding="utf-8")
    outcome = run_scout(tmp_path, load_config(ai_provider="none"), quiet=True)
    titles = {f.title for f in outcome.findings if f.scanner == "injection"}
    assert {"os.system() call", "eval() usage"} <= titles


def test_repeated_pattern_on_one_line_collapses_via_run_scout(tmp_path):
    (tmp_path / "app.py").write_text("eval(a) or eval(b)\n", encoding="utf-8")
    outcome = run_scout(tmp_path, load_config(ai_provider="none"), quiet=True)
    eval_findings = [f for f in outcome.findings if f.title == "eval() usage"]
    assert len(eval_findings) == 1


def test_findings_are_sorted_by_severity(tmp_path):
    # A LOW (constant shell=True) and a CRITICAL (eval) — CRITICAL must lead.
    (tmp_path / "app.py").write_text(
        'subprocess.run("ls -la", shell=True)\nresult = eval(user_input)\n',
        encoding="utf-8",
    )
    outcome = run_scout(tmp_path, load_config(ai_provider="none"), quiet=True)
    severities = [f.severity for f in outcome.findings]
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    assert severities == sorted(severities, key=lambda s: rank[s])
    assert severities[0] == "CRITICAL"
    assert "LOW" in severities
