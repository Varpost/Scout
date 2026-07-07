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

# Framework app instantiation — a concrete app to harden (not just an import).
FLASK_APP = re.compile(r"\bFlask\s*\(")
FASTAPI_APP = re.compile(r"\bFastAPI\s*\(")

# Django settings-module fingerprint — settings.py often never imports django.
DJANGO_SETTINGS = re.compile(r"^\s*INSTALLED_APPS\s*=", re.MULTILINE)
DJANGO_CONTRIB = re.compile(r"""['"]django\.(?:contrib|middleware)""")
DJANGO_HARDENED = re.compile(r"SECURE_SSL_REDIRECT|SECURE_HSTS_SECONDS")

# Evidence the app already ships security headers — the Flask/FastAPI escape
# hatch, so a hardened app isn't flagged (keeps the false-positive rate down).
SECURITY_HEADERS_PRESENT = re.compile(
    r"Talisman|flask_talisman|Strict-Transport-Security|Content-Security-Policy|"
    r"X-Frame-Options|X-Content-Type-Options",
    re.IGNORECASE,
)
FASTAPI_SECURITY = re.compile(
    r"add_middleware|HTTPSRedirectMiddleware|TrustedHostMiddleware|"
    r"import\s+secure|from\s+secure|Strict-Transport-Security|Content-Security-Policy",
    re.IGNORECASE,
)


def _comment(file_path: Path, text: str) -> str:
    """Format a placeholder snippet using the file's comment style."""
    hash_style = file_path.suffix.lower() in {".py", ".rb", ".sh", ".bash", ".yml", ".yaml", ".tf"}
    return f"# {text}" if hash_style else f"// {text}"


def _line_of(content: str, pos: int) -> int:
    """1-based line number of a character offset in ``content``."""
    return content[:pos].count("\n") + 1


def _context(content: str, line_num: int) -> str:
    """A few lines of context around a 1-based line number (for the snippet)."""
    lines = content.splitlines()
    return "\n".join(lines[max(0, line_num - 2) : min(len(lines), line_num + 1)])


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
        """Per-file header checks (Helmet/Talisman/middleware, CORS, Django settings).

        CSRF is handled once per project in ``scan`` — it's an app-level
        concern, not a per-file one.
        """
        # Django settings hardening runs regardless of the web-app gate below:
        # a settings module often never imports django itself.
        findings: list[Finding] = self._check_django_settings(file_path, content)

        # Only scan files that look like web app entry points
        is_web_app = any(pattern.search(content) for pattern in FRAMEWORK_INDICATORS.values())
        if not is_web_app:
            return findings

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

        # Flask app without security headers (Flask-Talisman is the Helmet analog)
        flask_app = FLASK_APP.search(content)
        if flask_app and not SECURITY_HEADERS_PRESENT.search(content):
            line_num = _line_of(content, flask_app.start())
            findings.append(
                Finding(
                    file=str(file_path),
                    line=line_num,
                    severity="MEDIUM",
                    title="Flask app without security headers",
                    description=(
                        "Flask sets no security headers on its own and no Flask-Talisman "
                        "(or manual HSTS/CSP/X-Frame-Options) was found. That leaves the app "
                        "open to clickjacking, protocol downgrade, and MIME-sniffing."
                    ),
                    scanner=self.name,
                    snippet=_context(content, line_num),
                    fix_phase=1,
                    fix_summary=(
                        "Add Flask-Talisman: `pip install flask-talisman`, then `Talisman(app)` — "
                        "or set the headers yourself in an `after_request` handler."
                    ),
                )
            )

        # FastAPI app without any security middleware (no canonical single control)
        fastapi_app = FASTAPI_APP.search(content)
        if fastapi_app and not FASTAPI_SECURITY.search(content):
            line_num = _line_of(content, fastapi_app.start())
            findings.append(
                Finding(
                    file=str(file_path),
                    line=line_num,
                    severity="LOW",
                    title="FastAPI app without security middleware",
                    description=(
                        "FastAPI adds no security headers by default and no security middleware "
                        "(HSTS/CSP/frame-options, or the `secure` library) was found."
                    ),
                    scanner=self.name,
                    snippet=_context(content, line_num),
                    fix_phase=1,
                    fix_summary=(
                        "Add security headers via middleware — e.g. `app.add_middleware(...)` for "
                        "HTTPS redirect / trusted-host, or the `secure` library for HSTS/CSP/nosniff."
                    ),
                )
            )

        # Check for wildcard CORS
        cors_match = HEADER_CHECKS[1][1].search(content)
        if cors_match:
            line_num = _line_of(content, cors_match.start())
            findings.append(
                Finding(
                    file=str(file_path),
                    line=line_num,
                    severity="MEDIUM",
                    title="Wildcard CORS — any website can call your API",
                    description=HEADER_CHECKS[1][3],
                    scanner=self.name,
                    snippet=_context(content, line_num),
                    fix_phase=2,
                    fix_summary=HEADER_CHECKS[1][4],
                )
            )

        return findings

    def _check_django_settings(self, file_path: Path, content: str) -> list[Finding]:
        """Flag a Django settings module that lacks HTTPS/HSTS hardening.

        Fires only on a real settings module (``INSTALLED_APPS`` plus a
        ``django.contrib``/``middleware`` reference) that sets neither
        ``SECURE_SSL_REDIRECT`` nor ``SECURE_HSTS_SECONDS`` — the same gap
        ``manage.py check --deploy`` reports. Kept narrow to avoid firing on
        ordinary django imports.
        """
        settings_match = DJANGO_SETTINGS.search(content)
        if settings_match is None or not DJANGO_CONTRIB.search(content):
            return []
        if DJANGO_HARDENED.search(content):
            return []
        line_num = _line_of(content, settings_match.start())
        return [
            Finding(
                file=str(file_path),
                line=line_num,
                severity="MEDIUM",
                title="Django settings missing HTTPS/HSTS hardening",
                description=(
                    "This Django settings module sets neither SECURE_SSL_REDIRECT nor "
                    "SECURE_HSTS_SECONDS, so it doesn't force HTTPS or send HSTS. "
                    "`manage.py check --deploy` flags this."
                ),
                scanner=self.name,
                snippet=_context(content, line_num),
                fix_phase=1,
                fix_summary=(
                    "In your production settings add: SECURE_SSL_REDIRECT=True, "
                    "SECURE_HSTS_SECONDS=31536000, SESSION_COOKIE_SECURE=True, "
                    "CSRF_COOKIE_SECURE=True, SECURE_CONTENT_TYPE_NOSNIFF=True."
                ),
            )
        ]

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
