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


# --- AST pass (Python files) ---


def test_ast_catches_multiline_shell_true():
    # Regex could never see a call split across lines; the AST pass can.
    scanner = InjectionScanner()
    content = 'subprocess.run(\n    f"ls {directory}",\n    shell=True,\n)\n'
    findings = scanner.scan_file(Path("app.py"), content)
    assert any(f.severity == "CRITICAL" and "shell=True" in f.title for f in findings)


def test_ast_catches_bare_imported_run():
    # from subprocess import run — no `subprocess.` prefix for regex to match.
    scanner = InjectionScanner()
    content = "from subprocess import run\nrun(cmd, shell=True)\n"
    findings = scanner.scan_file(Path("app.py"), content)
    assert any("shell=True with dynamic command" == f.title for f in findings)


def test_ast_constant_eval_is_not_flagged():
    # eval on a literal has nothing injectable — the old regex flagged it.
    scanner = InjectionScanner()
    findings = scanner.scan_file(Path("app.py"), 'x = eval("2 + 2")\n')
    assert findings == [], [f.title for f in findings]


def test_ast_python_exec_is_flagged():
    scanner = InjectionScanner()
    findings = scanner.scan_file(Path("app.py"), "exec(code_from_request)\n")
    assert any(f.title == "exec() usage" and f.severity == "CRITICAL" for f in findings)


def test_ast_constant_os_system_is_low():
    scanner = InjectionScanner()
    findings = scanner.scan_file(Path("app.py"), 'os.system("cls")\n')
    assert [f.severity for f in findings] == ["LOW"]


def test_ast_eval_in_string_literal_is_not_flagged():
    # The FP class AST kills: source that merely *mentions* a sink in a string.
    scanner = InjectionScanner()
    content = 'HELP = "never call eval(user_input) or os.system(cmd)"\n'
    findings = scanner.scan_file(Path("docs.py"), content)
    assert findings == [], [f.title for f in findings]


def test_ast_sql_fstring_and_concat():
    scanner = InjectionScanner()
    content = (
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        'db.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
        'db.execute("SELECT * FROM logs WHERE day = %s" % day)\n'
        "db.execute(QUERY_TEMPLATE.format(table=table))\n"
        'db.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
    )
    findings = scanner.scan_file(Path("app.py"), content)
    assert [f.line for f in findings] == [1, 2, 3, 4]
    assert findings[0].title == "SQL f-string query"
    assert all(f.severity == "CRITICAL" for f in findings)


def test_ast_prebuilt_query_variable_is_not_flagged():
    # execute(query) on a plain name: could be parameterized — don't guess.
    scanner = InjectionScanner()
    findings = scanner.scan_file(Path("app.py"), "db.execute(query)\n")
    assert findings == []


def test_unparseable_python_falls_back_to_regex():
    scanner = InjectionScanner()
    content = 'os.system("ls " + user_input)\nthis is not valid python !!!\n'
    findings = scanner.scan_file(Path("legacy.py"), content)
    assert any(f.title == "os.system() call" for f in findings)


# --- Reachability signal (intra-file source→sink) ---


def _scan_py(content: str):
    return InjectionScanner().scan_file(Path("app.py"), content)


def test_sink_fed_by_request_args_is_reachable():
    findings = _scan_py('cmd = request.args.get("cmd")\nos.system(cmd)\n')
    assert [f.reachable for f in findings] == [True]


def test_sink_fed_directly_by_source_is_reachable():
    for content in (
        'os.system(request.form["c"])\n',
        "eval(input())\n",
        "subprocess.run(sys.argv[1], shell=True)\n",
        'db.execute(f"SELECT * FROM t WHERE k = {os.environ[key]}")\n',
    ):
        findings = _scan_py(content)
        assert findings and findings[0].reachable is True, content


def test_sink_fed_by_constant_is_not_reachable():
    findings = _scan_py('cmd = "ls -la"\nsubprocess.run(cmd, shell=True)\n')
    assert [f.reachable for f in findings] == [False]


def test_sink_with_unknown_name_is_undetermined():
    findings = _scan_py("result = eval(user_input)\n")
    assert [f.reachable for f in findings] == [None]


def test_tainted_wins_over_later_constant_assignment():
    content = 'cmd = request.args.get("cmd")\ncmd = "ls"\nos.system(cmd)\n'
    findings = _scan_py(content)
    assert [f.reachable for f in findings] == [True]


def test_reachable_surfaces_in_json_and_report(tmp_path):
    from scout.agents.reporter_agent import finding_to_dict, generate_report

    findings = _scan_py('cmd = request.args.get("cmd")\nos.system(cmd)\n')
    assert finding_to_dict(findings[0])["reachable"] is True

    report_path = tmp_path / "report.md"
    generate_report(findings, report_path)
    assert "Reachable from untrusted input" in report_path.read_text(encoding="utf-8")
