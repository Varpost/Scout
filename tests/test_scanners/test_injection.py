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


def test_raw_sql_percent_format_still_detected_in_js():
    scanner = InjectionScanner()
    content = 'db.run("SELECT * FROM users WHERE id = %s" % (user_id,));\n'
    findings = scanner.scan_file(Path("app.js"), content)
    assert any(f.title == "Raw SQL with string format" for f in findings)


# --- XSS constant-value skips and new sinks ---


def _scan_js(content: str):
    return InjectionScanner().scan_file(Path("app.js"), content)


def test_constant_innerhtml_is_not_flagged():
    # A constant can never carry user input — same principle as constant shell=True.
    for line in (
        'el.innerHTML = "";\n',
        "el.innerHTML = '<b>Done!</b>';\n",
        "el.innerHTML = `<span>static</span>`;\n",
    ):
        assert _scan_js(line) == [], line


def test_dynamic_innerhtml_still_flagged():
    for line in (
        "el.innerHTML = userHtml;\n",
        'el.innerHTML = "<b>" + name;\n',
        "el.innerHTML = `hello ${name}`;\n",
        "el.innerHTML += chunk;\n",
        "el.innerHTML = '${name}';\n",  # quoted but inside a template literal
    ):
        findings = _scan_js(line)
        assert any("innerHTML" in f.title for f in findings), line


def test_outerhtml_dynamic_flagged_constant_not():
    assert any("outerHTML" in f.title for f in _scan_js("el.outerHTML = widget;\n"))
    assert _scan_js('el.outerHTML = "<div/>";\n') == []


def test_document_write_constant_not_flagged():
    assert _scan_js('document.write("<hr>");\n') == []
    assert any("document.write" in f.title for f in _scan_js("document.write(banner);\n"))


def test_insert_adjacent_html():
    flagged = _scan_js("el.insertAdjacentHTML('beforeend', userCard);\n")
    assert any("insertAdjacentHTML" in f.title for f in flagged)
    assert _scan_js("el.insertAdjacentHTML('beforeend', '<hr>');\n") == []


def test_dangerously_set_inner_html():
    flagged = _scan_js("<div dangerouslySetInnerHTML={{__html: rawMarkdown}} />\n")
    assert any("dangerouslySetInnerHTML" in f.title for f in flagged)
    assert _scan_js('<div dangerouslySetInnerHTML={{__html: "<b>hi</b>"}} />\n') == []


def test_jquery_html_sink():
    assert any(".html()" in f.title for f in _scan_js("$('#out').html(message);\n"))
    assert _scan_js("$('#out').html();\n") == []  # getter
    assert _scan_js("$('#out').html('<b>static</b>');\n") == []


def test_sql_raw_sink():
    flagged = _scan_js("db.raw(`SELECT * FROM t WHERE id = ${id}`);\n")
    assert any(f.title == "SQL raw() with dynamic input" for f in flagged)
    # The concatenated form is covered by the existing concatenation pattern.
    flagged = _scan_js('knex.raw("SELECT * FROM t WHERE n = " + name);\n')
    assert any("SQL" in f.title for f in flagged)
    assert _scan_js('db.raw("SELECT 1");\n') == []


def test_minified_js_scans_in_linear_time():
    # Regression: the Raw-SQL pattern's unbounded .* gaps backtracked for
    # MINUTES on single-line minified JS (found via jquery.min.js in the C1
    # benchmark corpus). This synthetic worst case must stay fast.
    import time

    scanner = InjectionScanner()
    chunk = 'a("x",b).delete.c;"q";' * 10_000  # one ~220KB line, quotes + "delete"
    t0 = time.time()
    scanner.scan_file(Path("vendor.min.js"), chunk + "\n")
    assert time.time() - t0 < 5, "pathological minified line must not trigger regex backtracking"


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


# --- JS lexical taint tracking ---


def _scan_js(content: str):
    return InjectionScanner().scan_file(Path("app.js"), content)


def test_js_nosql_sink_with_tainted_destructured_value():
    content = "const { email } = req.body;\nconst user = await User.findOne({ email });\n"
    findings = _scan_js(content)
    assert [f.title for f in findings] == ["NoSQL query with user-controlled value"]
    assert findings[0].reachable is True
    assert findings[0].line == 2


def test_js_nosql_sink_with_constant_value_is_not_flagged():
    assert _scan_js('const user = await User.findOne({ email: "admin@x.io" });\n') == []


def test_js_nosql_sink_tainted_object_value():
    content = "const code = ctx.query.code;\nawait strapi.query().findOne({ resetPasswordToken: code });\n"
    findings = _scan_js(content)
    assert [f.title for f in findings] == ["NoSQL query with user-controlled value"]


def test_js_array_find_callback_is_not_flagged():
    content = "const id = req.params.id;\nconst hit = users.find(u => u.id === id);\n"
    assert _scan_js(content) == []


def test_js_query_with_tainted_string_is_flagged():
    content = "const sql = req.body.sql;\ndb.query(sql, []);\n"
    findings = _scan_js(content)
    assert [f.title for f in findings] == ["SQL query with user-controlled string"]
    assert findings[0].severity == "CRITICAL"


def test_js_query_with_untainted_variable_is_not_flagged():
    # Parameterized call whose query text never touches user input — the
    # taint gate must keep this quiet even though the arg is a variable.
    content = 'const sql = "SELECT 1";\npool.query(sql, [req.body.id]);\n'
    assert _scan_js(content) == []


def test_js_exec_with_tainted_command_via_propagation():
    content = 'const q = req.query.q;\nconst cmd = "ping " + q;\nexec(cmd);\n'
    findings = _scan_js(content)
    assert [f.title for f in findings] == ["exec() with user-controlled command"]
    assert findings[0].reachable is True


def test_js_eval_of_tainted_name_is_reachable():
    content = "const code = location.hash.slice(1);\neval(code);\n"
    findings = _scan_js(content)
    assert [f.title for f in findings] == ["eval() usage"]
    assert findings[0].reachable is True


def test_js_innerhtml_with_provable_constant_is_dropped():
    content = "const template = '<b>hi</b>';\nel.innerHTML = template;\n"
    assert _scan_js(content) == []


def test_js_innerhtml_with_unknown_name_is_kept_undetermined():
    findings = _scan_js("el.innerHTML = data;\n")
    assert [f.title for f in findings] == ["innerHTML assignment"]
    assert findings[0].reachable is None


def test_js_innerhtml_with_tainted_name_is_reachable():
    content = "const q = req.query.q;\nel.innerHTML = q;\n"
    findings = _scan_js(content)
    assert [f.title for f in findings] == ["innerHTML assignment"]
    assert findings[0].reachable is True


def test_js_typescript_annotation_still_tracks_taint():
    content = "const x: string = req.query.q;\neval(x);\n"
    findings = InjectionScanner().scan_file(Path("app.ts"), content)
    assert findings and findings[0].reachable is True


def test_js_function_constructor_dynamic_vs_literal():
    assert [f.title for f in _scan_js('new Function("return " + x);\n')] == ["Function constructor with dynamic code"]
    assert _scan_js('const add = new Function("a", "b", "return a + b");\n') == []


def test_js_vm_runincontext_is_flagged():
    findings = _scan_js("vm.runInNewContext(payload, sandbox);\n")
    assert [f.title for f in findings] == ["vm.runInContext with dynamic code"]


def test_js_taint_skips_minified_lines():
    # A minified line must not feed the taint env: `a` is assigned from
    # req.body inside it, but the line is skipped, so using `a` at a sink
    # stays undetermined rather than becoming a confident CRITICAL.
    long_line = "var a=req.body.x;f(a);" * 27  # > _JS_MAX_LINE (594), < file-minified 2000
    content = long_line + "\nel.innerHTML = a;\n"
    line2 = [f for f in _scan_js(content) if f.line == 2]
    assert [f.reachable for f in line2] == [None]


# --- child_process member-call command injection (D4) ---


def test_js_member_exec_with_callback_is_flagged():
    for content in (
        'cp.exec("ps " + args, function (err, out) {});\n',
        "shell.exec(cmd, { silent: true });\n",
        "exec(combineCommand, function (err) {});\n",
        "child_process.exec(args.join(' '), fn);\n",
    ):
        findings = _scan_js(content)
        assert any(f.title == "child_process exec (member call)" for f in findings), content


def test_regexp_exec_is_not_flagged_as_command():
    # regexp.exec()/pattern.exec() take one argument — the string to test —
    # so the callback/options signal must never fire on them.
    for content in (
        "const m = pattern.exec(input);\n",
        "while ((m = re.exec(str)) !== null) {}\n",
        r"const parts = /(\d+)/.exec(value);" + "\n",
    ):
        findings = _scan_js(content)
        assert not any("member call" in f.title for f in findings), content


def test_constant_command_exec_is_not_member_flagged():
    # A fixed command string with a callback isn't injectable.
    findings = _scan_js('cp.exec("ls -la", function (err) {});\n')
    assert not any(f.title == "child_process exec (member call)" for f in findings)


# --- minified/bundled file skip (D4) ---


def test_minified_named_file_is_skipped_for_injection():
    # Same content flagged in a source file must be skipped in a .min.js.
    content = "el.innerHTML = data;\ndocument.write(x);\n"
    assert _scan_js(content), "sanity: flagged in normal source"
    assert InjectionScanner().scan_file(Path("vendor/jquery.min.js"), content) == []
    assert InjectionScanner().scan_file(Path("app.bundle.js"), content) == []


def test_long_line_file_is_treated_as_minified():
    giant = "var x=1;" + "a" * 3000 + ";el.innerHTML=data;\n"
    assert InjectionScanner().scan_file(Path("dist/app.js"), giant) == []


def test_python_with_long_line_is_not_minified_skipped():
    # A .py file is source regardless of line length — never bundle-skipped.
    content = 'x = "' + "y" * 2500 + '"\nos.system(cmd)\n'
    findings = InjectionScanner().scan_file(Path("app.py"), content)
    assert any(f.title == "os.system() call" for f in findings)


# --- Path traversal (OWASP A01) + SSRF (OWASP A10), taint-gated (D5) ---


def test_py_path_traversal_taint_gated():
    findings = _scan_py('f = request.args["file"]\nopen(f)\n')
    assert [(f.title, f.reachable) for f in findings] == [("Path traversal", True)]


def test_py_open_constant_path_is_not_flagged():
    assert _scan_py('open("config.json")\n') == []


def test_py_send_from_directory_uses_filename_arg():
    findings = _scan_py('name = request.args["name"]\nsend_from_directory(BASE, name)\n')
    assert any(f.title == "Path traversal" for f in findings)


def test_py_ssrf_taint_gated():
    findings = _scan_py('u = request.args["url"]\nrequests.get(u)\n')
    assert [(f.title, f.reachable) for f in findings] == [("Server-side request forgery (SSRF)", True)]


def test_py_ssrf_constant_url_is_not_flagged():
    assert _scan_py('requests.get("https://api.example.com/health")\n') == []


def test_py_urlopen_bare_is_ssrf():
    findings = _scan_py('from urllib.request import urlopen\nu = request.args["u"]\nurlopen(u)\n')
    assert any(f.title == "Server-side request forgery (SSRF)" for f in findings)


def test_js_path_traversal_taint_gated():
    findings = _scan_js("const p = req.query.file;\nfs.readFileSync(p);\n")
    assert [(f.title, f.reachable) for f in findings] == [("Path traversal", True)]


def test_js_sendfile_constant_is_not_flagged():
    assert _scan_js('res.sendFile("./index.html");\n') == []


def test_js_ssrf_axios_and_fetch_tainted():
    for content in ("const u = req.query.url;\naxios.get(u);\n", "fetch(req.body.target);\n"):
        findings = _scan_js(content)
        assert any(f.title == "Server-side request forgery (SSRF)" for f in findings), content


def test_js_map_get_is_not_ssrf():
    # .get on a non-client receiver must never be an SSRF false positive.
    assert _scan_js("const v = cache.get(req.query.id);\n") == []


def test_new_categories_are_high_severity_phase_4():
    findings = _scan_py('p = request.args["p"]\nopen(p)\n')
    assert findings[0].severity == "HIGH"
    assert findings[0].fix_phase == 4


# --- E1: deserialization (CWE-502), open redirect (CWE-601), weak randomness (CWE-330) ---


def test_py_pickle_loads_tainted_is_flagged():
    findings = _scan_py("import pickle\nd = request.data\npickle.loads(d)\n")
    assert [(f.title, f.reachable) for f in findings] == [("Insecure deserialization", True)]


def test_py_pickle_loads_untainted_is_not_flagged():
    assert _scan_py("import pickle\npickle.loads(cached_bytes)\n") == []


def test_py_yaml_load_without_safe_loader_is_flagged_flat():
    # Missing SafeLoader is the vuln — flagged regardless of taint (bandit B506).
    findings = _scan_py("import yaml\nyaml.load(open('c.yml'))\n")
    assert any(f.title == "Insecure deserialization" for f in findings)


def test_py_yaml_safe_variants_are_not_flagged():
    assert _scan_py("import yaml\nyaml.load(f, Loader=yaml.SafeLoader)\n") == []
    assert _scan_py("import yaml\nyaml.safe_load(f)\n") == []


def test_js_unserialize_tainted_flagged_dotted_and_bare():
    for content in (
        "const d = req.body.data;\nserialize.unserialize(d);\n",
        "const d = req.body.data;\nunserialize(d);\n",
    ):
        assert any(f.title == "Insecure deserialization" for f in _scan_js(content)), content


def test_py_open_redirect_taint_gated():
    findings = _scan_py('to = request.args["next"]\nreturn redirect(to)\n')
    assert [(f.title, f.reachable) for f in findings] == [("Open redirect", True)]


def test_py_redirect_constant_is_not_flagged():
    assert _scan_py('return redirect("/home")\n') == []


def test_js_open_redirect_taint_gated():
    assert any(f.title == "Open redirect" for f in _scan_js("res.redirect(req.query.url);\n"))
    assert _scan_js('res.redirect("/login");\n') == []


def test_js_redirect_with_status_code_form_flags_url():
    findings = _scan_js("const u = req.query.url;\nres.redirect(301, u);\n")
    assert any(f.title == "Open redirect" for f in findings)


def test_weak_random_for_token_is_flagged_both_languages():
    js = _scan_js("const token = Math.random().toString(36).slice(2);\n")
    py = _scan_py("otp = random.randint(1000, 9999)\n")
    assert [f.title for f in js] == ["Weak randomness for security value"]
    assert [f.title for f in py] == ["Weak randomness for security value"]
    assert js[0].severity == "MEDIUM"


def test_weak_random_without_security_keyword_is_not_flagged():
    assert _scan_js("const jitter = Math.random() * 1000;\n") == []
    assert _scan_py("x = random.random()\n") == []


# (The property "E1 titles are not scored by the injection benchmark" is proven
# empirically by the benchmark run showing identical TP/FP/FN, not by a unit
# test — importing benchmarks/ here would couple the suite to a non-package.)


# --- E2.5: broadened JS taint sources (req.url) + path sinks + wrapped args ---


def test_js_req_url_is_a_taint_source():
    findings = _scan_js("const p = req.url;\nfs.readFile(p, cb);\n")
    assert [(f.title, f.reachable) for f in findings] == [("Path traversal", True)]


def test_js_fs_stat_access_exists_are_path_sinks():
    for sink in ("stat", "access", "exists", "createReadStream", "realpath"):
        content = f"fs.{sink}(req.params.file);\n"
        assert any(f.title == "Path traversal" for f in _scan_js(content)), sink


def test_js_path_join_wrapper_does_not_cut_the_taint():
    # The comma inside path.join(root, x) must not truncate arg capture.
    findings = _scan_js("fs.readFile(path.join(root, req.query.name), cb);\n")
    assert any(f.title == "Path traversal" for f in findings)


def test_js_path_sink_with_constant_join_is_silent():
    assert _scan_js('fs.readFile(path.join(__dirname, "index.html"), cb);\n') == []


def test_js_ssrf_wrapped_url_is_caught():
    findings = _scan_js("const u = req.query.target;\naxios.get(buildUrl(u));\n")
    assert any("SSRF" in f.title for f in findings)


def test_js_req_path_property_source():
    assert any(f.title == "Path traversal" for f in _scan_js("fs.createReadStream(req.path);\n"))
