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

# Signals that the app uses cookie/session-based auth or renders HTML forms —
# the contexts where CSRF actually matters. Token/Bearer JSON APIs (e.g. a
# Supabase-auth backend) are NOT CSRF-vulnerable, so we only raise CSRF when
# one of these appears anywhere in the project.
SESSION_INDICATORS = re.compile(
    r"set_cookie|response\.cookies|request\.cookies|session\[|flask_login|"
    r"render_template|<form\b|app\.secret_key|SESSION_COOKIE|express-session|"
    r"cookie-session|req\.session",
    re.IGNORECASE,
)

# Presence of any CSRF protection.
CSRF_PRESENT = re.compile(r"csrf|csurf|CSRFProtect|csrf_protect", re.IGNORECASE)


def _comment(file_path: Path, text: str) -> str:
    """Format a placeholder snippet using the file's comment style."""
    hash_style = file_path.suffix.lower() in {".py", ".rb", ".sh", ".bash", ".yml", ".yaml", ".tf"}
    return f"# {text}" if hash_style else f"// {text}"


# Security middleware / header checks
HEADER_CHECKS: list[tuple[str, re.Pattern[str], str, str, str]] = [
    (
        "Missing Helmet (Express)",
        re.compile(r"""require\s*\(\s*['"]helmet['"]\s*\)|from\s+['"]helmet['"]"""),
        "MEDIUM",
        (
            "Express app without Helmet. Missing security headers "
            "(X-Frame-Options, HSTS, CSP, etc.) make your app vulnerable to "
            "clickjacking, XSS, and MIME-sniffing attacks."
        ),
        "Install and use Helmet: `npm install helmet` then `app.use(helmet())`.",
    ),
    (
        "Wildcard CORS",
        re.compile(r"""cors\(\s*\)|origin:\s*['"]?\*['"]?|Access-Control-Allow-Origin.*\*"""),
        "MEDIUM",
        (
            "CORS set to allow all origins (*). Any website can make requests "
            "to your API, potentially stealing user data via the browser."
        ),
        "Restrict CORS to specific trusted origins instead of '*'.",
    ),
    (
        "Missing CSRF Protection",
        re.compile(r"""csrf|csurf|CSRFProtect|csrf_protect"""),
        "MEDIUM",
        (
            "No CSRF protection detected in a web app with form handling. "
            "Attackers can trick users into submitting unwanted actions."
        ),
        "Add CSRF middleware (csurf for Express, CSRFProtect for Flask/Django).",
    ),
]


@register_scanner
class HeadersScanner(BaseScanner):
    """Detects missing security headers and middleware."""

    name = "headers"
    description = "Finds missing security headers, CORS issues, and middleware gaps"

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Per-file header checks (Helmet, wildcard CORS).

        CSRF is handled once per project in ``scan`` — it's an app-level
        concern, not a per-file one.
        """
        findings: list[Finding] = []

        # Only scan files that look like web app entry points
        is_web_app = any(pattern.search(content) for pattern in FRAMEWORK_INDICATORS.values())
        if not is_web_app:
            return []

        # Check for Express without Helmet
        if FRAMEWORK_INDICATORS["express"].search(content):
            if not HEADER_CHECKS[0][1].search(content):
                findings.append(
                    Finding(
                        file=str(file_path),
                        line=1,
                        severity="MEDIUM",
                        title="Express app without Helmet security headers",
                        description=HEADER_CHECKS[0][3],
                        scanner=self.name,
                        snippet=_comment(file_path, "No helmet() middleware found"),
                        fix_phase=1,
                        fix_summary=HEADER_CHECKS[0][4],
                    )
                )

        # Check for wildcard CORS
        cors_match = HEADER_CHECKS[1][1].search(content)
        if cors_match:
            line_num = content[: cors_match.start()].count("\n") + 1
            lines = content.splitlines()
            start = max(0, line_num - 2)
            end = min(len(lines), line_num + 1)
            snippet = "\n".join(lines[start:end])

            findings.append(
                Finding(
                    file=str(file_path),
                    line=line_num,
                    severity="MEDIUM",
                    title="Wildcard CORS — any website can call your API",
                    description=HEADER_CHECKS[1][3],
                    scanner=self.name,
                    snippet=snippet,
                    fix_phase=2,
                    fix_summary=HEADER_CHECKS[1][4],
                )
            )

        return findings

    def scan(self, files: list[Path]) -> list[Finding]:
        """Run per-file checks, then a single project-level CSRF check."""
        findings = super().scan(files)
        findings.extend(self._scan_csrf(files))
        return findings

    def _scan_csrf(self, files: list[Path]) -> list[Finding]:
        """Emit at most one CSRF finding for the whole project.

        Only raised when a web framework is present AND there's evidence of
        cookie/session auth or HTML forms AND no CSRF protection anywhere.
        Token/Bearer JSON APIs are intentionally left alone.
        """
        framework_file: Path | None = None
        has_session_signal = False
        has_csrf = False

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError):
                continue
            if any(pattern.search(content) for pattern in FRAMEWORK_INDICATORS.values()):
                if framework_file is None:
                    framework_file = file_path
            if SESSION_INDICATORS.search(content):
                has_session_signal = True
            if CSRF_PRESENT.search(content):
                has_csrf = True

        if framework_file is None or has_csrf or not has_session_signal:
            return []

        return [
            Finding(
                file=str(framework_file),
                line=1,
                severity="MEDIUM",
                title="No CSRF protection detected",
                description=HEADER_CHECKS[2][3],
                scanner=self.name,
                snippet=_comment(framework_file, "No CSRF middleware found"),
                fix_phase=2,
                fix_summary=HEADER_CHECKS[2][4],
                # line=1 is a synthetic anchor — exempt from line suppression.
                project_level=True,
            )
        ]
