"""Headers scanner — detects missing security headers and misconfigurations."""

from __future__ import annotations

import re
from pathlib import Path

from scout.models import Finding
from scout.scanners import register_scanner
from scout.scanners.base import BaseScanner

# Patterns indicating a web framework is in use
FRAMEWORK_INDICATORS = {
    "express": re.compile(r"""require\s*\(\s*['"]express['"]\s*\)|from\s+['"]express['"]"""),
    "fastapi": re.compile(r"from\s+fastapi\s+import|import\s+fastapi"),
    "flask": re.compile(r"from\s+flask\s+import|import\s+flask"),
    "django": re.compile(r"from\s+django|import\s+django"),
}

# Security middleware / header checks
HEADER_CHECKS: list[tuple[str, re.Pattern[str], str, str, str]] = [
    (
        "Missing Helmet (Express)",
        re.compile(r"""require\s*\(\s*['"]helmet['"]\s*\)|from\s+['"]helmet['"]"""),
        "MEDIUM",
        "Express app without Helmet. Missing security headers (X-Frame-Options, HSTS, CSP, etc.) make your app vulnerable to clickjacking, XSS, and MIME-sniffing attacks.",
        "Install and use Helmet: `npm install helmet` then `app.use(helmet())`.",
    ),
    (
        "Wildcard CORS",
        re.compile(r"""cors\(\s*\)|origin:\s*['"]?\*['"]?|Access-Control-Allow-Origin.*\*"""),
        "MEDIUM",
        "CORS set to allow all origins (*). Any website can make requests to your API, potentially stealing user data via the browser.",
        "Restrict CORS to specific trusted origins instead of '*'.",
    ),
    (
        "Missing CSRF Protection",
        re.compile(r"""csrf|csurf|CSRFProtect|csrf_protect"""),
        "MEDIUM",
        "No CSRF protection detected in a web app with form handling. Attackers can trick users into submitting unwanted actions.",
        "Add CSRF middleware (csurf for Express, CSRFProtect for Flask/Django).",
    ),
]


@register_scanner
class HeadersScanner(BaseScanner):
    """Detects missing security headers and middleware."""

    name = "headers"
    description = "Finds missing security headers, CORS issues, and middleware gaps"

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Scan for missing security headers in web app files."""
        findings: list[Finding] = []

        # Only scan files that look like web app entry points
        is_web_app = any(pattern.search(content) for pattern in FRAMEWORK_INDICATORS.values())
        if not is_web_app:
            return []

        # Check for Express without Helmet
        if FRAMEWORK_INDICATORS["express"].search(content):
            if not HEADER_CHECKS[0][1].search(content):
                findings.append(Finding(
                    file=str(file_path),
                    line=1,
                    severity="MEDIUM",
                    title="Express app without Helmet security headers",
                    description=HEADER_CHECKS[0][3],
                    scanner=self.name,
                    snippet="// No helmet() middleware found",
                    fix_phase=1,
                    fix_summary=HEADER_CHECKS[0][4],
                ))

        # Check for wildcard CORS
        cors_match = HEADER_CHECKS[1][1].search(content)
        if cors_match:
            line_num = content[:cors_match.start()].count("\n") + 1
            lines = content.splitlines()
            start = max(0, line_num - 2)
            end = min(len(lines), line_num + 1)
            snippet = "\n".join(lines[start:end])

            findings.append(Finding(
                file=str(file_path),
                line=line_num,
                severity="MEDIUM",
                title="Wildcard CORS — any website can call your API",
                description=HEADER_CHECKS[1][3],
                scanner=self.name,
                snippet=snippet,
                fix_phase=2,
                fix_summary=HEADER_CHECKS[1][4],
            ))

        # Check for missing CSRF in apps with form handling
        has_forms = bool(re.search(r"POST|put|patch|form|body", content, re.IGNORECASE))
        has_csrf = bool(HEADER_CHECKS[2][1].search(content))
        if has_forms and not has_csrf:
            findings.append(Finding(
                file=str(file_path),
                line=1,
                severity="MEDIUM",
                title="No CSRF protection detected",
                description=HEADER_CHECKS[2][3],
                scanner=self.name,
                snippet="// No CSRF middleware found",
                fix_phase=2,
                fix_summary=HEADER_CHECKS[2][4],
            ))

        return findings
