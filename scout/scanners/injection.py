"""Injection scanner — detects SQL injection, command injection, and XSS."""

from __future__ import annotations

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


@register_scanner
class InjectionScanner(BaseScanner):
    """Detects SQL injection, command injection, and XSS vulnerabilities."""

    name = "injection"
    description = "Finds SQL injection, command injection, and cross-site scripting"
    suffixes = PYTHON_JS_SUFFIXES  # Python/JS idioms only — not language-agnostic

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Scan for injection vulnerabilities."""
        findings: list[Finding] = []
        lines = content.splitlines()

        all_patterns = [
            (SQL_PATTERNS, "CRITICAL", 4),  # (patterns, severity, fix_phase)
            (CMD_PATTERNS, "CRITICAL", 4),
            (CMD_PATTERNS_INFO, "LOW", 1),
            (XSS_PATTERNS, "HIGH", 4),
        ]

        for pattern_group, severity, fix_phase in all_patterns:
            for title, regex, description in pattern_group:
                for match in regex.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Skip if in a comment
                    stripped = line_text.lstrip()
                    if stripped.startswith(("#", "//", "*", "/*")):
                        continue

                    start = max(0, line_num - 2)
                    end = min(len(lines), line_num + 1)
                    snippet = "\n".join(lines[start:end])

                    findings.append(
                        Finding(
                            file=str(file_path),
                            line=line_num,
                            severity=severity,
                            title=title,
                            description=description,
                            scanner=self.name,
                            snippet=snippet,
                            fix_phase=fix_phase,
                            fix_summary=("Use parameterized queries / safe APIs instead of string interpolation."),
                        )
                    )

        return findings
