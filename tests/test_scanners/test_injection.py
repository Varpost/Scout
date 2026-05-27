"""Tests for the injection scanner."""

from pathlib import Path

from scout.scanners.injection import InjectionScanner

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_detects_sql_concatenation():
    scanner = InjectionScanner()
    content = FIXTURES.joinpath("has_injection.js").read_text()
    findings = scanner.scan_file(FIXTURES / "has_injection.js", content)
    titles = [f.title for f in findings]
    assert any("SQL" in t for t in titles)


def test_detects_innerhtml_xss():
    scanner = InjectionScanner()
    content = FIXTURES.joinpath("has_injection.js").read_text()
    findings = scanner.scan_file(FIXTURES / "has_injection.js", content)
    titles = [f.title for f in findings]
    assert any("innerHTML" in t for t in titles)


def test_no_injection_in_safe_code():
    scanner = InjectionScanner()
    content = FIXTURES.joinpath("safe_app.py").read_text()
    findings = scanner.scan_file(FIXTURES / "safe_app.py", content)
    assert len(findings) == 0, f"False positives: {[f.title for f in findings]}"


def test_injection_findings_are_critical():
    scanner = InjectionScanner()
    content = FIXTURES.joinpath("has_injection.js").read_text()
    findings = scanner.scan_file(FIXTURES / "has_injection.js", content)
    sql_findings = [f for f in findings if "SQL" in f.title]
    for f in sql_findings:
        assert f.severity == "CRITICAL"
        assert f.fix_phase == 4
