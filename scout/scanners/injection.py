"""Injection scanner — detects SQL injection, command injection, and XSS."""

from __future__ import annotations

import re
from pathlib import Path

from scout.models import Finding
from scout.scanners import register_scanner
from scout.scanners.base import BaseScanner

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
]

# Command Injection patterns
CMD_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "shell=True with variable",
        re.compile(r"""subprocess\.\w+\(.*shell\s*=\s*True""", re.IGNORECASE),
        "subprocess called with shell=True. If any part of the command comes from user input, "
        "attackers can inject additional commands (e.g., `; rm -rf /`).",
    ),
    (
        "os.system() call",
        re.compile(r"""os\.system\s*\("""),
        "os.system() executes commands in a shell. If the command string includes any user input, "
        "it's a command injection vulnerability.",
    ),
    (
        "eval() usage",
        re.compile(r"""(?<!\w)eval\s*\("""),
        "eval() executes arbitrary code. If the input can be influenced by a user in any way, "
        "they can execute any code on your server.",
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
        "document.write()",
        re.compile(r"""document\.write\s*\("""),
        "document.write() with dynamic content is an XSS vector. "
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

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Scan for injection vulnerabilities."""
        findings: list[Finding] = []
        lines = content.splitlines()

        all_patterns = [
            (SQL_PATTERNS, "CRITICAL", 4),  # (patterns, severity, fix_phase)
            (CMD_PATTERNS, "CRITICAL", 4),
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
