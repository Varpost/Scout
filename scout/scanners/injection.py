"""Injection scanner — detects SQL injection, command injection, and XSS.

Python files get an AST-based pass (stdlib ``ast``): it kills the regex
false-positive class (constant ``shell=True`` commands, strings that merely
look like calls) and catches multi-line calls regex can't see. Non-Python
files — and Python that doesn't parse — keep the regex patterns.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from scout.models import Finding
from scout.scanners import register_scanner
from scout.scanners.base import PYTHON_JS_SUFFIXES, BaseScanner

# SQL Injection patterns
SQL_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "SQL string concatenation",
        re.compile(
            r"""(?:execute|query|raw|cursor\.execute)\s*\(\s*(?:f['"]|['"].*?['"]\s*[+%]|.*?\.format)""",
            re.IGNORECASE,
        ),
        "Anyone visiting your site can read, modify, or delete your entire database. "
        "The query is built by gluing user input directly into SQL text.",
    ),
    (
        "SQL f-string query",
        re.compile(r"""(?:execute|query)\s*\(\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)""", re.IGNORECASE),
        "SQL query built with f-string. User input goes directly into the query — "
        "an attacker can inject `' OR 1=1 --` to bypass auth or dump data.",
    ),
    (
        "Raw SQL with string format",
        # The gaps are bounded to [^'"\n]* on purpose: unbounded .* here was
        # catastrophic (minutes of backtracking) on single-line minified JS
        # full of quotes and the word "delete" — found by the C1 benchmark
        # on jquery.min.js. Quote-free gaps keep the match linear.
        re.compile(
            r"""['"][^'"\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"\n]*['"]\s*%\s*\(""",
            re.IGNORECASE,
        ),
        "SQL query using %-formatting with variables. This is NOT parameterization — "
        "it's string interpolation that allows SQL injection.",
    ),
    (
        "SQL template literal",
        # JS: db.query(`SELECT … ${userId}`) — a backtick query containing
        # both an interpolation and a SQL keyword, in either order.
        re.compile(
            r"""(?:query|execute)\s*\(\s*`(?=[^`]*\$\{)(?=[^`]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE))""",
            re.IGNORECASE,
        ),
        "SQL query built with a JavaScript template literal. `${...}` interpolation is string "
        "gluing, not parameterization — an attacker can inject `' OR 1=1 --` through any "
        "interpolated value.",
    ),
    (
        "SQL raw() with dynamic input",
        # ORM escape hatches (knex.raw, sequelize literal, …) fed by template
        # interpolation. The concatenation form is already caught by the
        # "SQL string concatenation" pattern above.
        re.compile(r"""\.raw\s*\(\s*`[^`\n]*\$\{"""),
        "An ORM raw() escape hatch fed by interpolation or concatenation bypasses the ORM's "
        "parameterization entirely — this is plain SQL injection.",
    ),
]

# Command Injection patterns
# (Some titles/descriptions below literally contain the code they detect —
# their trailing `scout: ignore` comments keep Scout's CI self-scan clean.)
CMD_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "shell=True with dynamic command",
        # The command must show evidence of dynamism (f-string, variable/call,
        # concatenation, %-formatting, .format) — a fixed string literal with
        # shell=True is reported separately at LOW, not CRITICAL.
        re.compile(
            r"""subprocess\.\w+\(\s*(?:(?:f|rf|fr)['"]|[A-Za-z_][\w.\[\]]*\s*[,(]"""
            r"""|(?:r|b|rb|br)?['"][^'"]*['"]\s*(?:[+%]|\.format\())"""
            r""".*?shell\s*=\s*True""",
            re.IGNORECASE,
        ),
        "subprocess called with shell=True and a command that isn't a fixed string. If any part "
        "of the command comes from user input, attackers can inject additional commands "
        "(e.g., `; rm -rf /`).",
    ),
    (
        "os.system() call",  # scout: ignore
        re.compile(r"""os\.system\s*\("""),
        "os.system() executes commands in a shell. If the command string includes any user input, "  # scout: ignore
        "it's a command injection vulnerability.",
    ),
    (
        "eval() usage",  # scout: ignore
        # (?<![\w.]) — a leading dot means a method call like PyTorch's
        # model.eval(), which has nothing to do with Python's eval().
        re.compile(r"""(?<![\w.])eval\s*\("""),
        "eval() executes arbitrary code. If the input can be influenced by a user in any way, "  # scout: ignore
        "they can execute any code on your server.",
    ),
    (
        "exec() with template literal",
        # JS child_process exec/execSync, usually destructured to a bare name:
        # exec(`ping -c 1 ${host}`). The (?<![\w.]) lookbehind keeps
        # regex.exec(...) method calls from matching.
        re.compile(r"""(?<![\w.])exec(?:Sync)?\s*\(\s*`[^`]*\$\{"""),
        "child_process exec() with an interpolated template literal. Anything a user controls "
        "in `${...}` becomes part of the shell command — `; rm -rf /` included.",
    ),
    (
        "exec() with string concatenation",
        re.compile(r"""(?<![\w.])exec(?:Sync)?\s*\(\s*['"][^'"]*['"]\s*\+"""),
        "child_process exec() with a concatenated command string. User input glued into the "
        "command lets attackers run arbitrary shell commands.",
    ),
    (
        "child_process exec with variable command",
        re.compile(r"""child_process\s*\.\s*exec(?:Sync)?\s*\(\s*[A-Za-z_$]"""),
        "child_process.exec() called with a variable command. If any part of that variable "
        "comes from user input, this is command injection.",
    ),
    (
        "child_process exec (member call)",
        # The (?<![\w.]) lookbehind on the patterns above dodges regexp.exec()
        # but also throws away the *common* forms: cp.exec(...), shell.exec(...),
        # exec(cmd, cb). Node's child_process.exec is async — it takes a
        # callback (or options) SECOND argument; regexp.exec() takes exactly
        # one. So a member/bare exec whose first argument is not a plain string
        # literal AND that has a callback/options second argument is
        # child_process, not a regex test. See OWASP Command Injection.
        re.compile(
            r"""(?<![\w.])(?:[A-Za-z_$][\w$]*\s*\.\s*)?exec(?:Sync)?\s*\("""
            r"""\s*(?!['"][^'"\n]*['"]\s*,)[^,;\n]+,\s*(?:function\b|\([^)\n]*\)\s*=>|\{|[A-Za-z_$])"""
        ),
        "child_process exec() with a dynamic command and a callback/options argument. If any "
        "part of the command string comes from user input, attackers can run arbitrary shell "
        "commands (`; rm -rf /`). Use execFile/spawn with an argument array instead.",
    ),
    (
        "spawn() with shell:true",
        re.compile(r"""\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true""", re.IGNORECASE),
        "spawn() with shell:true routes the command through a shell, re-enabling the exact "
        "injection risk spawn's argument-array form exists to prevent.",
    ),
    (
        "Function constructor with dynamic code",
        # eval by another name (OWASP code-injection sink list). All-string-
        # literal argument lists (a common perf idiom) are vetoed.
        re.compile(r"""\bnew\s+Function\s*\(\s*(?!(?:['"][^'"\n]*['"]\s*,?\s*)*\))"""),
        "The Function constructor compiles strings into executable code — eval by another "  # scout: ignore
        "name. Any user-influenced string here runs as arbitrary code.",
    ),
    (
        "vm.runInContext with dynamic code",
        re.compile(r"""\bvm\.runIn(?:New|This)?Context\s*\(\s*(?!""" + r"""(?:"[^"$\n]*"|'[^'$\n]*')\s*[),])"""),
        "Node's vm module executes its string argument as code. Sandboxes in vm are not a "
        "security boundary — user input reaching this call is code injection.",
    ),
]

# Informational: shell=True on a constant string is a bad habit, not an
# exploitable injection — reported LOW so the first scan of ordinary code
# isn't a wall of false CRITICALs.
CMD_PATTERNS_INFO: list[tuple[str, re.Pattern[str], str]] = [
    (
        "shell=True with constant command",
        re.compile(
            r"""subprocess\.\w+\(\s*(?:r|b|rb|br)?['"][^'"]*['"]\s*,.*?shell\s*=\s*True""",
            re.IGNORECASE,
        ),
        "subprocess called with shell=True on a fixed string. As written there is no injection "
        "risk, but shell=True becomes dangerous the moment any variable joins the command.",
    ),
]

# A string literal with nothing user-controlled in it: quoted (no ${ inside —
# a ${ means we're inside a template literal and the value interpolates) or a
# backtick template with no interpolation. Each alternative consumes every
# character exactly once, so lookaheads built from this stay linear-time.
_CONST_STR = r"""(?:"(?:[^"$\n]|\$(?!\{))*"|'(?:[^'$\n]|\$(?!\{))*'|`(?:[^`$\n]|\$(?!\{))*`)"""  # noqa: E501

# XSS patterns (template/output context). Sink assignments/calls whose value
# is a pure string literal are skipped — a constant can never carry user
# input (same principle as the constant shell=True downgrade).
XSS_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "innerHTML assignment",
        # The \s* lives INSIDE the veto lookahead — placed before it, the
        # engine backtracks \s* to zero width and slips past the veto.
        re.compile(r"""\.innerHTML\s*\+?=(?!=)(?!\s*""" + _CONST_STR + r"""\s*;?\s*(?:\r?\n|$))"""),
        "Setting innerHTML with dynamic content allows attackers to inject malicious scripts "
        "that steal cookies, redirect users, or deface your app.",
    ),
    (
        "outerHTML assignment",
        re.compile(r"""\.outerHTML\s*\+?=(?!=)(?!\s*""" + _CONST_STR + r"""\s*;?\s*(?:\r?\n|$))"""),
        "Setting outerHTML with dynamic content is the same XSS vector as innerHTML — "
        "attacker-controlled markup executes scripts in your users' browsers.",
    ),
    (
        "document.write()",  # scout: ignore
        re.compile(r"""document\.write(?:ln)?\s*\((?!\s*""" + _CONST_STR + r"""\s*[),])"""),
        "document.write() with dynamic content is an XSS vector. "  # scout: ignore
        "Attackers can inject script tags through user-controlled input.",
    ),
    (
        "insertAdjacentHTML with dynamic content",
        re.compile(r"""\.insertAdjacentHTML\s*\(\s*['"][^'"\n]*['"]\s*,(?!\s*""" + _CONST_STR + r"""\s*\))"""),
        "insertAdjacentHTML parses its second argument as HTML — dynamic content here is the "
        "same XSS vector as innerHTML.",
    ),
    (
        "dangerouslySetInnerHTML with dynamic content",
        re.compile(r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:(?!\s*""" + _CONST_STR + r"""\s*\})"""),
        "React renders __html without escaping — the 'dangerously' is literal. Dynamic values "
        "here execute attacker markup unless sanitized first.",
    ),
    (
        "jQuery .html() with dynamic content",
        # Only clear dynamism evidence: a bare identifier/property argument or
        # a string literal being concatenated. `.html()` (getter) and
        # `.html("static")` never match.
        re.compile(r"""\.html\s*\(\s*(?:[A-Za-z_$][\w.$]*\s*[+)]|['"][^'"\n]*['"]\s*\+)"""),
        "jQuery .html() parses its argument as HTML. Passing a variable renders unescaped "
        "user input — use .text() or sanitize first.",
    ),
    (
        "Unescaped template output",
        re.compile(r"""\{\{\{.*?\}\}\}|<%[-=].*?%>|\{\%\s*autoescape\s+false"""),
        "Template rendering without HTML escaping. User input will be rendered as raw HTML, allowing script injection.",
    ),
]


# --- JS taint: lexical, line-ordered, intra-file ---
# The stdlib has no JS parser, so this is deliberately not an AST: a single
# forward pass over lines builds a name→taint map (same True/False/None
# semantics as the Python env below), which then (a) gates the ORM/NoSQL and
# tainted-identifier sinks — those fire ONLY on taint evidence — and
# (b) attaches `reachable` to the regex findings, dropping XSS hits whose
# value is provably an in-file constant.

_JS_TAINT_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})

# Untrusted-input reads: the OWASP DOM-XSS source list plus the standard
# Node/Express/Koa request surfaces.
_JS_SOURCE = re.compile(
    r"""\b(?:req|request|ctx)\.(?:body|query|params|headers|cookies)\b"""
    r"""|(?:\bwindow\.)?\blocation\.(?:hash|search|href|pathname)\b"""
    r"""|\bdocument\.(?:URL|documentURI|referrer|cookie)\b"""
    r"""|\bprocess\.(?:argv|env)\b|\bwindow\.name\b"""
)

_JS_DECL = re.compile(
    r"""^\s*(?:const|let|var)\s+(?P<target>[A-Za-z_$][\w$]*)(?:\s*:\s*[^=\n]+?)?\s*=\s*(?P<rhs>\S.*)$"""
)
_JS_DESTRUCT = re.compile(r"""^\s*(?:const|let|var)\s*[{\[]\s*(?P<names>[^}\]]*)[}\]]\s*=\s*(?P<rhs>\S.*)$""")
_JS_REASSIGN = re.compile(r"""^\s*(?P<target>[A-Za-z_$][\w$]*)\s*\+?=(?!=)\s*(?P<rhs>\S.*)$""")
# Root identifiers only — the lookbehind drops property names (`a.b` taints
# by `a`) and object keys are stripped separately before matching.
_JS_IDENT = re.compile(r"""(?<![\w$.])[A-Za-z_$][\w$]*""")
_JS_OBJECT_KEY = re.compile(r"""[\w$]+\s*:""")
_JS_CONST_RHS = re.compile(r"""^(?:""" + _CONST_STR + r"""|\d+(?:\.\d+)?|true|false|null|undefined)\s*;?\s*$""")
_JS_KEYWORDS = frozenset(
    """await new typeof void delete this true false null undefined function return if else for while do switch
    case break continue in of instanceof let const var async yield class extends super import export default
    document window console Math JSON String Number Boolean Array Object RegExp Date Promise require module""".split()
)

# ponytail: skip minified lines and use one flat namespace (no scopes), same
# as the Python env — upgrade to a real JS parser only if the benchmark shows
# this ceiling matters.
_JS_MAX_LINE = 500

# Whole-file minified/bundled skip for the injection scanner: generated
# artifacts (jquery.min.js, *.bundle.js) are not source you hand-fix — a vuln
# in a vendored bundle is the dependency scanner's job, not an XSS squiggle on
# unreadable code. Standard SAST convention; on the CVE benchmark this drops
# ~460 false positives for a single true positive (itself unfixable in place).
# Secrets still scan these files — a leaked key in a bundle matters.
_MINIFIED_NAME = re.compile(r"[.\-](?:min|bundle|pack)\.", re.IGNORECASE)
_MINIFIED_MAX_LINE = 2000


def _looks_minified(file_path: Path, lines: list[str]) -> bool:
    """True for generated bundles — by name (*.min.js) or a very long line."""
    if _MINIFIED_NAME.search(file_path.name):
        return True
    return any(len(line) > _MINIFIED_MAX_LINE for line in lines)


# MongoDB-style query APIs where a user-controlled *value* is injectable even
# with zero SQL text: a request value that arrives as an object turns into an
# operator injection ({"$gt": ""} matches everything — see PortSwigger/OWASP
# NoSQL injection). SQL query builders (knex .where etc.) parameterize their
# values and are deliberately NOT in this list. The lookahead vetoes callback
# arguments so Array.prototype.find(x => …) never matches.
_JS_NOSQL_SINK = re.compile(
    r"""\.(?:find|findOne(?:And\w+)?|deleteOne|deleteMany|updateOne|updateMany)\s*\("""
    r"""(?!\s*(?:function\b|\([^)\n]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>))(?P<args>[^)\n]*)"""
)
# A bare identifier as the query/command string itself — dangerous only when
# that identifier traces to a source, so these are taint-gated too.
_JS_QUERY_IDENT_SINK = re.compile(r"""\.(?:query|execute)\s*\(\s*(?P<first>[A-Za-z_$][\w$]*)\s*[,)]""")
_JS_EXEC_IDENT_SINK = re.compile(r"""(?<![\w.])exec(?:Sync)?\s*\(\s*(?P<first>[A-Za-z_$][\w$]*)\s*[,)]""")

_JS_NOSQL_DESCRIPTION = (
    "A request-controlled value flows into a MongoDB-style query. If it arrives as an "
    'object instead of a string ({"$gt": ""}), it becomes a query operator — matching '
    "every document, bypassing logins or password-reset checks. Validate the type/shape "
    "before querying (e.g. reject non-strings) or wrap values in $eq."
)
_JS_QUERY_IDENT_DESCRIPTION = (
    "The query text itself comes from user input. This is SQL injection regardless of "
    "parameterized values — the attacker writes the statement. Build queries from "
    "constants and pass user data only as bound parameters."
)
_JS_EXEC_IDENT_DESCRIPTION = (
    "The command passed to exec() traces back to user input in this file — attackers "
    "can append `; rm -rf /` or any shell command. Use execFile/spawn with an "
    "argument array, or validate against an allowlist."
)

# Path traversal (OWASP A01) and SSRF (OWASP A10) share the taint machinery
# with the injection sinks: a user-controlled value reaching a file-path or
# request-URL sink. Both are taint-gated (fire only when the argument traces
# to a source), so they inherit the low false-positive rate of the NoSQL sink.
_PATH_TRAVERSAL_DESCRIPTION = (
    "A user-controlled value is used as a file path. An attacker can send "
    "`../../etc/passwd` or an absolute path to read or overwrite files outside the "
    "intended directory. Resolve the path and confirm it stays within an allowed "
    "base directory (e.g. path.resolve then startsWith the base) before using it."
)
_SSRF_DESCRIPTION = (
    "A user-controlled value is used as a request URL (server-side request forgery). "
    "An attacker can point it at internal services (http://169.254.169.254/ cloud "
    "metadata, localhost admin ports) or the file:// scheme. Validate the URL host "
    "and scheme against an allowlist before fetching."
)

# File-path sinks: fs reads/writes and Express file responses. Taint-gated, so
# a plain fs.readFileSync("config.json") never fires.
_JS_PATH_SINK = re.compile(
    r"""\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|unlink|sendFile|download)"""
    r"""\s*\(\s*(?P<arg>[^,)\n]+)"""
)
# HTTP client sinks: bare fetch/axios/got/superagent, or a .get/.post/... on a
# known client receiver (never a generic Map.get — the receiver list gates it).
_JS_SSRF_SINK = re.compile(
    r"""(?<![\w.$])(?:fetch|axios|got|superagent)\s*\(\s*(?P<arg>[^,)\n]+)"""
    r"""|\b(?:axios|http|https|got|request|superagent|fetch)"""
    r"""\.(?:get|post|put|patch|del|delete|head|request)\s*\(\s*(?P<arg2>[^,)\n]+)"""
)


def _js_rhs_state(rhs: str, env: dict[str, bool | None]) -> bool | None:
    """Taint state of a right-hand side: source/tainted, constant, or unknown."""
    if _JS_SOURCE.search(rhs):
        return True
    names = [n for n in _JS_IDENT.findall(rhs) if n not in _JS_KEYWORDS]
    if any(env.get(n) is True for n in names):
        return True
    if _JS_CONST_RHS.match(rhs):
        return False
    return None


def _js_taint_env(lines: list[str]) -> dict[str, bool | None]:
    """Map JS names to taint state via one forward pass over declarations."""
    env: dict[str, bool | None] = {}

    def record(name: str, state: bool | None) -> None:
        if name not in env:
            env[name] = state
        elif env[name] is True or state is True:
            env[name] = True  # once tainted, always tainted
        elif env[name] != state:
            env[name] = None  # conflicting evidence — undetermined

    for line in lines:
        if len(line) > _JS_MAX_LINE:
            continue
        destruct = _JS_DESTRUCT.match(line)
        if destruct:
            state = _js_rhs_state(destruct.group("rhs"), env)
            for part in destruct.group("names").split(","):
                # `a` binds a; `a: b` binds b; `a = fallback` binds a;
                # `...rest` binds rest — the bound name is the last
                # identifier before any default value.
                names = _JS_IDENT.findall(part.split("=")[0])
                if names:
                    record(names[-1], state)
            continue
        decl = _JS_DECL.match(line) or _JS_REASSIGN.match(line)
        if decl:
            record(decl.group("target"), _js_rhs_state(decl.group("rhs"), env))
    return env


def _js_reachable(text: str, env: dict[str, bool | None]) -> bool | None:
    """Classify a sink expression against the taint env (True/False/None)."""
    if _JS_SOURCE.search(text):
        return True
    names = [n for n in _JS_IDENT.findall(text) if n not in _JS_KEYWORDS]
    if any(env.get(n) is True for n in names):
        return True
    if names and all(env.get(n) is False for n in names):
        return False
    return None


# Titles the AST pass shares with the regex patterns reuse their descriptions.
_DESCRIPTIONS = {title: description for title, _, description in (*SQL_PATTERNS, *CMD_PATTERNS, *CMD_PATTERNS_INFO)}

_PY_EXEC_DESCRIPTION = (
    "exec() executes arbitrary code. If the input can be influenced by a user in any way, "  # scout: ignore
    "they can execute any code on your server."
)
_PY_OS_SYSTEM_CONSTANT_DESCRIPTION = (
    "os.system() with a fixed command string. As written there is no injection risk, "  # scout: ignore
    "but the shell invocation becomes dangerous the moment any variable joins the command."
)

# Method/function names whose first argument is a SQL query.
_SQL_SINK_NAMES = frozenset({"execute", "executemany", "query", "raw"})
# Bare names from `from subprocess import run` — a shell=True keyword on
# anything else (unknown APIs) is not treated as evidence.
_SUBPROCESS_FUNCS = frozenset({"run", "call", "Popen", "check_call", "check_output"})

# Path-traversal sinks: builtin open() and Flask's file responses. Taint-gated,
# so open("config.json") never fires — only a user-controlled path does.
_PY_PATH_SINKS = frozenset({"open", "send_file", "send_from_directory"})
# SSRF sinks: HTTP-client verbs on a known client object, or a bare urlopen.
_PY_SSRF_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "request", "urlopen"})
_PY_SSRF_RECEIVERS = frozenset({"requests", "httpx", "urllib", "session", "aiohttp", "urlopen"})

# (line, title, description, severity, fix_phase, reachable)
_AstHit = tuple[int, str, str, str, int, bool | None]


def _is_constant(node: ast.expr) -> bool:
    """True for literals and containers of literals — nothing user-influenced."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_constant(element) for element in node.elts)
    return False


def _builds_string(node: ast.expr) -> bool:
    """True when the expression assembles a string at runtime.

    Covers f-strings with interpolations, ``+``/``%`` on a string literal
    (recursively, so ``"a" + x + "b"`` counts), and any ``.format()`` call —
    the exact constructions that turn a query or command into an injection.
    """
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _contains_str_literal(node.left) or _contains_str_literal(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _contains_str_literal(node: ast.expr) -> bool:
    """True when a string literal appears anywhere in a concatenation chain."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return _contains_str_literal(node.left) or _contains_str_literal(node.right)
    return False


# --- Reachability: best-effort intra-file source→sink tracking ---


def _is_source_node(node: ast.AST) -> bool:
    """True for expressions that read untrusted input.

    Sources: any attribute/subscript on a ``request`` object (Flask/Django),
    ``sys.argv``, ``os.environ``/``os.getenv``, and ``input()``.
    """
    if isinstance(node, ast.Attribute):
        root: ast.expr = node
        while isinstance(root, (ast.Attribute, ast.Subscript)):
            root = root.value
        if isinstance(root, ast.Name) and root.id == "request":
            return True
        if node.attr == "argv" and isinstance(node.value, ast.Name) and node.value.id == "sys":
            return True
        if node.attr == "environ" and isinstance(node.value, ast.Name) and node.value.id == "os":
            return True
        return False
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "input":
            return True
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "getenv"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            return True
    return False


def _expr_has_source(expr: ast.expr) -> bool:
    """True when an untrusted-input source appears anywhere in the expression."""
    return any(_is_source_node(node) for node in ast.walk(expr))


def _build_taint_env(tree: ast.Module) -> dict[str, bool | None]:
    """Map assigned names to their taint state across the whole file.

    True = ever assigned from an untrusted source, False = only ever assigned
    constants, None = anything else (calls, params, conflicting assignments).
    Single flat namespace — deliberately no scope analysis (best-effort,
    intra-file only).
    """
    env: dict[str, bool | None] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = node.targets
            value: ast.expr | None = node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
            value = node.value
        else:
            continue
        if value is None:  # bare annotation: `x: int`
            continue
        state: bool | None
        if _expr_has_source(value):
            state = True
        elif _is_constant(value):
            state = False
        else:
            state = None
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id not in env:
                env[target.id] = state
            elif env[target.id] is True or state is True:
                env[target.id] = True  # once tainted, always tainted
            elif env[target.id] != state:
                env[target.id] = None  # conflicting evidence — undetermined
    return env


def _reachability(exprs: list[ast.expr], env: dict[str, bool | None]) -> bool | None:
    """Classify sink arguments: fed by untrusted input, constants, or unknown."""
    verdicts: list[bool | None] = []
    for expr in exprs:
        if _expr_has_source(expr):
            verdicts.append(True)
            continue
        names = [node.id for node in ast.walk(expr) if isinstance(node, ast.Name)]
        if any(env.get(name) is True for name in names):
            verdicts.append(True)
        elif any(isinstance(node, ast.Call) for node in ast.walk(expr)):
            verdicts.append(None)  # a call can smuggle in external data
        elif all(env.get(name) is False for name in names):
            verdicts.append(False)  # constants only (vacuously true for literals)
        else:
            verdicts.append(None)
    if True in verdicts:
        return True
    if None in verdicts or not verdicts:
        return None
    return False


class _PySinkVisitor(ast.NodeVisitor):
    """Collects injection sinks from a parsed Python module."""

    def __init__(self, env: dict[str, bool | None] | None = None) -> None:
        self.env = env or {}
        self.hits: list[_AstHit] = []

    def _add(
        self,
        node: ast.AST,
        title: str,
        description: str,
        severity: str,
        fix_phase: int,
        taint_exprs: list[ast.expr] | None = None,
    ) -> None:
        reachable = _reachability(taint_exprs, self.env) if taint_exprs is not None else None
        self.hits.append((getattr(node, "lineno", 1), title, description, severity, fix_phase, reachable))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 — ast.NodeVisitor API
        """Check one call expression against every Python sink."""
        self._check_eval_exec(node)
        self._check_os_system(node)
        self._check_shell_true(node)
        self._check_sql(node)
        self._check_path_traversal(node)
        self._check_ssrf(node)
        self.generic_visit(node)

    def _add_if_tainted(self, node: ast.Call, arg: ast.expr, title: str, description: str) -> None:
        """Add a HIGH taint-gated finding only when the argument reaches a source."""
        if _reachability([arg], self.env) is True:
            self._add(node, title, description, "HIGH", 4, [arg])

    def _check_path_traversal(self, node: ast.Call) -> None:
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if name not in _PY_PATH_SINKS or not node.args:
            return
        # send_from_directory(directory, filename): the user-controlled part is
        # the filename (2nd arg); everything else takes the first argument.
        arg = node.args[1] if name == "send_from_directory" and len(node.args) > 1 else node.args[0]
        self._add_if_tainted(node, arg, "Path traversal", _PATH_TRAVERSAL_DESCRIPTION)

    def _check_ssrf(self, node: ast.Call) -> None:
        func = node.func
        if not node.args:
            return
        is_ssrf = False
        if isinstance(func, ast.Name) and func.id == "urlopen":
            is_ssrf = True
        elif isinstance(func, ast.Attribute) and func.attr in _PY_SSRF_METHODS:
            root: ast.expr = func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            is_ssrf = isinstance(root, ast.Name) and root.id in _PY_SSRF_RECEIVERS
        if is_ssrf:
            self._add_if_tainted(node, node.args[0], "Server-side request forgery (SSRF)", _SSRF_DESCRIPTION)

    def _check_eval_exec(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Name) and func.id in ("eval", "exec")):
            return  # model.eval() and friends are attribute calls — never flagged
        if node.args and not node.keywords and all(_is_constant(arg) for arg in node.args):
            return  # constant expression — nothing injectable
        if func.id == "eval":
            self._add(
                node, "eval() usage", _DESCRIPTIONS["eval() usage"], "CRITICAL", 4, list(node.args)
            )  # scout: ignore
        else:
            self._add(node, "exec() usage", _PY_EXEC_DESCRIPTION, "CRITICAL", 4, list(node.args))  # scout: ignore

    def _check_os_system(self, node: ast.Call) -> None:
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "system"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            return
        if node.args and all(_is_constant(arg) for arg in node.args):
            self._add(
                node, "os.system() with constant command", _PY_OS_SYSTEM_CONSTANT_DESCRIPTION, "LOW", 1, list(node.args)
            )  # scout: ignore
        else:
            self._add(
                node, "os.system() call", _DESCRIPTIONS["os.system() call"], "CRITICAL", 4, list(node.args)
            )  # scout: ignore

    def _check_shell_true(self, node: ast.Call) -> None:
        func = node.func
        is_subprocess_attr = (
            isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "subprocess"
        )
        is_bare_subprocess_func = isinstance(func, ast.Name) and func.id in _SUBPROCESS_FUNCS
        if not (is_subprocess_attr or is_bare_subprocess_func):
            return
        shell = next((kw for kw in node.keywords if kw.arg == "shell"), None)
        if shell is None or not (isinstance(shell.value, ast.Constant) and shell.value.value is True):
            return
        command = node.args[0] if node.args else None
        if command is None or _is_constant(command):
            self._add(
                node,
                "shell=True with constant command",
                _DESCRIPTIONS["shell=True with constant command"],
                "LOW",
                1,
                [command] if command is not None else None,
            )
        else:
            self._add(
                node,
                "shell=True with dynamic command",
                _DESCRIPTIONS["shell=True with dynamic command"],
                "CRITICAL",
                4,
                [command],
            )

    def _check_sql(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        else:
            return
        if name not in _SQL_SINK_NAMES or not node.args:
            return
        query = node.args[0]
        if not _builds_string(query):
            return  # constant query (parameterized) or a prebuilt variable
        if isinstance(query, ast.JoinedStr):
            self._add(node, "SQL f-string query", _DESCRIPTIONS["SQL f-string query"], "CRITICAL", 4, [query])
        else:
            self._add(
                node, "SQL string concatenation", _DESCRIPTIONS["SQL string concatenation"], "CRITICAL", 4, [query]
            )


@register_scanner
class InjectionScanner(BaseScanner):
    """Detects SQL injection, command injection, and XSS vulnerabilities."""

    name = "injection"
    description = "Finds SQL injection, command injection, and cross-site scripting"
    suffixes = PYTHON_JS_SUFFIXES  # Python/JS idioms only — not language-agnostic

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Scan for injection vulnerabilities — AST for Python, regex otherwise."""
        lines = content.splitlines()
        suffix = file_path.suffix.lower()
        if suffix == ".py":
            try:
                tree: ast.Module | None = ast.parse(content)
            except (SyntaxError, ValueError):  # not valid Python 3 — regex still applies
                tree = None
            if tree is not None:
                findings = self._scan_python_ast(tree, file_path, lines)
                # XSS patterns (template markup) are language-agnostic text checks.
                findings.extend(self._scan_regex(file_path, content, lines, [(XSS_PATTERNS, "HIGH", 4)]))
                return findings

        if suffix != ".py" and _looks_minified(file_path, lines):
            return []  # generated bundle — not source to hand-fix

        env = _js_taint_env(lines) if suffix in _JS_TAINT_SUFFIXES else None
        all_patterns = [
            (SQL_PATTERNS, "CRITICAL", 4),  # (patterns, severity, fix_phase)
            (CMD_PATTERNS, "CRITICAL", 4),
            (CMD_PATTERNS_INFO, "LOW", 1),
            (XSS_PATTERNS, "HIGH", 4),
        ]
        findings = self._scan_regex(file_path, content, lines, all_patterns, env=env)
        if env is not None:
            findings.extend(self._scan_js_taint_sinks(file_path, lines, env))
        return findings

    def _finding(
        self,
        file_path: Path,
        lines: list[str],
        line_num: int,
        title: str,
        description: str,
        severity: str,
        fix_phase: int,
        reachable: bool | None = None,
    ) -> Finding:
        """Build a finding with the shared 3-line snippet around the flagged line."""
        start = max(0, line_num - 2)
        end = min(len(lines), line_num + 1)
        return Finding(
            file=str(file_path),
            line=line_num,
            severity=severity,
            title=title,
            description=description,
            scanner=self.name,
            snippet="\n".join(lines[start:end]),
            fix_phase=fix_phase,
            fix_summary="Use parameterized queries / safe APIs instead of string interpolation.",
            reachable=reachable,
        )

    def _scan_python_ast(self, tree: ast.Module, file_path: Path, lines: list[str]) -> list[Finding]:
        """Run the AST sink checks over a parsed Python module."""
        visitor = _PySinkVisitor(env=_build_taint_env(tree))
        visitor.visit(tree)
        return [
            self._finding(file_path, lines, line_num, title, description, severity, fix_phase, reachable)
            for line_num, title, description, severity, fix_phase, reachable in visitor.hits
        ]

    def _scan_regex(
        self,
        file_path: Path,
        content: str,
        lines: list[str],
        pattern_groups: list[tuple[list[tuple[str, re.Pattern[str], str]], str, int]],
        env: dict[str, bool | None] | None = None,
    ) -> list[Finding]:
        """Run the given regex pattern groups over the file content.

        With a JS taint env, each finding gets a ``reachable`` verdict from
        the sink expression's identifiers; XSS findings whose value is
        provably an in-file constant are dropped entirely — a constant can
        never carry user input.
        """
        findings: list[Finding] = []
        for pattern_group, severity, fix_phase in pattern_groups:
            for title, regex, description in pattern_group:
                for match in regex.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Skip if in a comment
                    stripped = line_text.lstrip()
                    if stripped.startswith(("#", "//", "*", "/*")):
                        continue

                    reachable: bool | None = None
                    if env is not None and len(line_text) <= _JS_MAX_LINE:
                        col = match.start() - (content.rfind("\n", 0, match.start()) + 1)
                        reachable = _js_reachable(line_text[col:], env)
                        if reachable is False and pattern_group is XSS_PATTERNS:
                            continue

                    findings.append(
                        self._finding(file_path, lines, line_num, title, description, severity, fix_phase, reachable)
                    )
        return findings

    def _scan_js_taint_sinks(self, file_path: Path, lines: list[str], env: dict[str, bool | None]) -> list[Finding]:
        """Sinks that fire only on taint evidence — never on pattern shape alone."""
        findings: list[Finding] = []
        for line_num, line in enumerate(lines, start=1):
            if len(line) > _JS_MAX_LINE or line.lstrip().startswith(("#", "//", "*", "/*")):
                continue
            for match in _JS_NOSQL_SINK.finditer(line):
                # Object keys are labels, not data — {email: code} taints by
                # `code`, and shorthand {email} taints by `email`.
                args = _JS_OBJECT_KEY.sub("", match.group("args"))
                if _js_reachable(args, env) is True:
                    findings.append(
                        self._finding(
                            file_path,
                            lines,
                            line_num,
                            "NoSQL query with user-controlled value",
                            _JS_NOSQL_DESCRIPTION,
                            "HIGH",
                            4,
                            reachable=True,
                        )
                    )
            for sink, title, description in (
                (_JS_QUERY_IDENT_SINK, "SQL query with user-controlled string", _JS_QUERY_IDENT_DESCRIPTION),
                (_JS_EXEC_IDENT_SINK, "exec() with user-controlled command", _JS_EXEC_IDENT_DESCRIPTION),
            ):
                for match in sink.finditer(line):
                    if env.get(match.group("first")) is True:
                        findings.append(
                            self._finding(file_path, lines, line_num, title, description, "CRITICAL", 4, reachable=True)
                        )
            for sink, title, description in (
                (_JS_PATH_SINK, "Path traversal", _PATH_TRAVERSAL_DESCRIPTION),
                (_JS_SSRF_SINK, "Server-side request forgery (SSRF)", _SSRF_DESCRIPTION),
            ):
                for match in sink.finditer(line):
                    arg = match.group("arg") or match.groupdict().get("arg2")
                    if arg and _js_reachable(arg, env) is True:
                        findings.append(
                            self._finding(file_path, lines, line_num, title, description, "HIGH", 4, reachable=True)
                        )
        return findings
