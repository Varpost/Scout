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
        re.compile(r"""['"].*(?:SELECT|INSERT|UPDATE|DELETE).*['"].*%\s*\(""", re.IGNORECASE),
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
        "spawn() with shell:true",
        re.compile(r"""\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true""", re.IGNORECASE),
        "spawn() with shell:true routes the command through a shell, re-enabling the exact "
        "injection risk spawn's argument-array form exists to prevent.",
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

# XSS patterns (template/output context)
XSS_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "innerHTML assignment",
        re.compile(r"""\.innerHTML\s*=(?!=)"""),
        "Setting innerHTML with dynamic content allows attackers to inject malicious scripts "
        "that steal cookies, redirect users, or deface your app.",
    ),
    (
        "document.write()",  # scout: ignore
        re.compile(r"""document\.write\s*\("""),
        "document.write() with dynamic content is an XSS vector. "  # scout: ignore
        "Attackers can inject script tags through user-controlled input.",
    ),
    (
        "Unescaped template output",
        re.compile(r"""\{\{\{.*?\}\}\}|<%[-=].*?%>|\{\%\s*autoescape\s+false"""),
        "Template rendering without HTML escaping. User input will be rendered as raw HTML, allowing script injection.",
    ),
]


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

# (line, title, description, severity, fix_phase)
_AstHit = tuple[int, str, str, str, int]


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


class _PySinkVisitor(ast.NodeVisitor):
    """Collects injection sinks from a parsed Python module."""

    def __init__(self) -> None:
        self.hits: list[_AstHit] = []

    def _add(self, node: ast.AST, title: str, description: str, severity: str, fix_phase: int) -> None:
        self.hits.append((getattr(node, "lineno", 1), title, description, severity, fix_phase))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 — ast.NodeVisitor API
        """Check one call expression against every Python sink."""
        self._check_eval_exec(node)
        self._check_os_system(node)
        self._check_shell_true(node)
        self._check_sql(node)
        self.generic_visit(node)

    def _check_eval_exec(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Name) and func.id in ("eval", "exec")):
            return  # model.eval() and friends are attribute calls — never flagged
        if node.args and not node.keywords and all(_is_constant(arg) for arg in node.args):
            return  # constant expression — nothing injectable
        if func.id == "eval":
            self._add(node, "eval() usage", _DESCRIPTIONS["eval() usage"], "CRITICAL", 4)  # scout: ignore
        else:
            self._add(node, "exec() usage", _PY_EXEC_DESCRIPTION, "CRITICAL", 4)  # scout: ignore

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
                node, "os.system() with constant command", _PY_OS_SYSTEM_CONSTANT_DESCRIPTION, "LOW", 1
            )  # scout: ignore
        else:
            self._add(node, "os.system() call", _DESCRIPTIONS["os.system() call"], "CRITICAL", 4)  # scout: ignore

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
            )
        else:
            self._add(
                node,
                "shell=True with dynamic command",
                _DESCRIPTIONS["shell=True with dynamic command"],
                "CRITICAL",
                4,
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
            self._add(node, "SQL f-string query", _DESCRIPTIONS["SQL f-string query"], "CRITICAL", 4)
        else:
            self._add(node, "SQL string concatenation", _DESCRIPTIONS["SQL string concatenation"], "CRITICAL", 4)


@register_scanner
class InjectionScanner(BaseScanner):
    """Detects SQL injection, command injection, and XSS vulnerabilities."""

    name = "injection"
    description = "Finds SQL injection, command injection, and cross-site scripting"
    suffixes = PYTHON_JS_SUFFIXES  # Python/JS idioms only — not language-agnostic

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Scan for injection vulnerabilities — AST for Python, regex otherwise."""
        lines = content.splitlines()
        if file_path.suffix.lower() == ".py":
            try:
                tree: ast.Module | None = ast.parse(content)
            except (SyntaxError, ValueError):  # not valid Python 3 — regex still applies
                tree = None
            if tree is not None:
                findings = self._scan_python_ast(tree, file_path, lines)
                # XSS patterns (template markup) are language-agnostic text checks.
                findings.extend(self._scan_regex(file_path, content, lines, [(XSS_PATTERNS, "HIGH", 4)]))
                return findings

        all_patterns = [
            (SQL_PATTERNS, "CRITICAL", 4),  # (patterns, severity, fix_phase)
            (CMD_PATTERNS, "CRITICAL", 4),
            (CMD_PATTERNS_INFO, "LOW", 1),
            (XSS_PATTERNS, "HIGH", 4),
        ]
        return self._scan_regex(file_path, content, lines, all_patterns)

    def _finding(
        self,
        file_path: Path,
        lines: list[str],
        line_num: int,
        title: str,
        description: str,
        severity: str,
        fix_phase: int,
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
        )

    def _scan_python_ast(self, tree: ast.Module, file_path: Path, lines: list[str]) -> list[Finding]:
        """Run the AST sink checks over a parsed Python module."""
        visitor = _PySinkVisitor()
        visitor.visit(tree)
        return [
            self._finding(file_path, lines, line_num, title, description, severity, fix_phase)
            for line_num, title, description, severity, fix_phase in visitor.hits
        ]

    def _scan_regex(
        self,
        file_path: Path,
        content: str,
        lines: list[str],
        pattern_groups: list[tuple[list[tuple[str, re.Pattern[str], str]], str, int]],
    ) -> list[Finding]:
        """Run the given regex pattern groups over the file content."""
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

                    findings.append(self._finding(file_path, lines, line_num, title, description, severity, fix_phase))
        return findings
