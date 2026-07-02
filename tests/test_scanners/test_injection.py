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


def test_model_eval_is_not_flagged():
    # Regression: PyTorch's model.eval() is a method call, not Python eval().
    scanner = InjectionScanner()
    content = "model.eval()\nself.encoder.eval()\n"
    findings = scanner.scan_file(Path("train.py"), content)
    assert findings == [], [f.title for f in findings]


def test_bare_eval_is_still_flagged():
    scanner = InjectionScanner()
    findings = scanner.scan_file(Path("app.py"), "result = eval(user_input)\n")
    assert any("eval" in f.title for f in findings)


def test_constant_shell_true_is_low_not_critical():
    # Regression: a fixed command string can't be injected into.
    scanner = InjectionScanner()
    findings = scanner.scan_file(Path("app.py"), 'subprocess.run("ls -la", shell=True)\n')
    assert findings, "constant shell=True should still be reported"
    assert all(f.severity == "LOW" for f in findings), [(f.title, f.severity) for f in findings]


def test_dynamic_shell_true_is_critical():
    scanner = InjectionScanner()
    for line in (
        'subprocess.run(f"ls {directory}", shell=True)\n',
        "subprocess.run(cmd, shell=True)\n",
        'subprocess.run("ls " + user_dir, shell=True)\n',
        'subprocess.run("ls %s" % user_dir, shell=True)\n',
        'subprocess.run("ls {}".format(user_dir), shell=True)\n',
    ):
        findings = scanner.scan_file(Path("app.py"), line)
        assert any(f.severity == "CRITICAL" and "shell=True" in f.title for f in findings), line


def test_fixture_command_injection_is_detected():
    # Regression: the exec(`ping -c 1 ${host}`) in Scout's own fixture
    # (has_injection.js:31-37) was missed by every pattern.
    scanner = InjectionScanner()
    content = FIXTURES.joinpath("has_injection.js").read_text()
    findings = scanner.scan_file(FIXTURES / "has_injection.js", content)
    assert any("exec()" in f.title for f in findings), [f.title for f in findings]


def test_template_literal_sql_is_detected():
    scanner = InjectionScanner()
    content = "db.query(`SELECT * FROM users WHERE id = ${userId}`);\n"
    findings = scanner.scan_file(Path("app.js"), content)
    assert any(f.title == "SQL template literal" for f in findings)


def test_regex_exec_is_not_flagged():
    # RegExp.prototype.exec is everywhere in JS — dotted calls must not match.
    scanner = InjectionScanner()
    content = "const m = pattern.exec(`${input}`);\n"
    findings = scanner.scan_file(Path("app.js"), content)
    assert not any("exec" in f.title.lower() for f in findings), [f.title for f in findings]


def test_exec_with_concatenation_is_detected():
    scanner = InjectionScanner()
    content = 'exec("ping -c 1 " + host);\n'
    findings = scanner.scan_file(Path("app.js"), content)
    assert any("exec()" in f.title for f in findings)


def test_spawn_shell_true_is_detected():
    scanner = InjectionScanner()
    content = "const p = spawn(cmd, { shell: true });\n"
    findings = scanner.scan_file(Path("app.js"), content)
    assert any("spawn" in f.title for f in findings)
