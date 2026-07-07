"""Secrets scanner — detects hardcoded API keys, tokens, and passwords."""

from __future__ import annotations

import re
from pathlib import Path

from scout.models import Finding
from scout.scanners import register_scanner
from scout.scanners.base import BaseScanner

# Patterns: (name, regex, severity, description, fix_summary)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, str, str]] = [
    (
        "AWS Access Key",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        "CRITICAL",
        (
            "AWS access key hardcoded in source. Anyone with this key can "
            "access your AWS account, spin up resources, read your data."
        ),
        "Move to environment variable. Add to .env (gitignored) and load via os.getenv().",
    ),
    (
        "AWS Secret Key",
        re.compile(r"""(?:aws_secret|secret_access_key|AWS_SECRET)\s*[=:]\s*['"]([A-Za-z0-9/+=]{40})['"]"""),
        "CRITICAL",
        "AWS secret key in source code. Combined with an access key, gives full access to your AWS account.",
        "Move to environment variable. Never commit AWS credentials.",
    ),
    (
        "GitHub Token",
        re.compile(r"(gh[oprsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})"),
        "CRITICAL",
        ("GitHub personal access token in code. Allows pushing code, reading private repos, managing your account."),
        (
            "Move to environment variable. Regenerate this token immediately \u2014 "
            "it may already be revoked by GitHub's secret scanning."
        ),
    ),
    (
        "Stripe Live Key",
        re.compile(r"(sk_live_[A-Za-z0-9]{24,})"),
        "CRITICAL",
        "Stripe live secret key in code. Allows charging customers, issuing refunds, and reading payment data.",
        "Move to environment variable. Rotate this key in Stripe dashboard immediately.",
    ),
    (
        "Stripe Publishable Key (Live)",
        re.compile(r"(pk_live_[A-Za-z0-9]{24,})"),
        "MEDIUM",
        "Stripe publishable key in source. Less dangerous than secret key but reveals your Stripe account identity.",
        "Move to environment variable for flexibility.",
    ),
    (
        "OpenAI API Key",
        re.compile(r"(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"),
        "HIGH",
        "OpenAI API key in code. Anyone can use your API credits and potentially access fine-tuned models.",
        "Move to environment variable.",
    ),
    (
        "OpenAI Project Key",
        re.compile(r"(?<![A-Za-z0-9])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,})"),
        "HIGH",
        (
            "Current-format OpenAI key (project / service-account / admin) in code. "
            "Anyone can spend your API credits and reach your OpenAI resources."
        ),
        "Move to environment variable. Rotate the key in the OpenAI dashboard immediately.",
    ),
    (
        "Anthropic API Key",
        re.compile(r"(?<![A-Za-z0-9])(sk-ant-[A-Za-z0-9_-]{20,})"),
        "HIGH",
        "Anthropic (Claude) API key in code. Anyone can spend your API credits and read your usage.",
        "Move to environment variable. Rotate the key in the Anthropic console immediately.",
    ),
    (
        "Slack Token",
        re.compile(r"(xox[baprs]-[A-Za-z0-9-]{10,})"),
        "HIGH",
        "Slack API token in code. Depending on scope it can read messages, post as your app, or manage the workspace.",
        "Move to environment variable. Revoke and reissue the token in Slack immediately.",
    ),
    (
        "Google API Key",
        re.compile(r"(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])"),
        "MEDIUM",
        (
            "Google API key in code. If unrestricted it can run up billing on Maps/Cloud APIs. "
            "Many such keys are intended to be public, so this is MEDIUM — restrict it by referrer/IP."
        ),
        "Move to environment variable and add API/referrer restrictions in the Google Cloud console.",
    ),
    (
        "GitLab Token",
        re.compile(r"(?<![A-Za-z0-9])(glpat-[A-Za-z0-9_-]{20})(?![A-Za-z0-9_-])"),
        "CRITICAL",
        "GitLab personal access token in code. Allows reading/pushing to your repos and managing your account.",
        "Move to environment variable. Revoke the token in GitLab (Settings → Access Tokens) immediately.",
    ),
    (
        "npm Token",
        re.compile(r"(?<![A-Za-z0-9])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])"),
        "HIGH",
        "npm access token in code. Allows publishing packages as you — a supply-chain compromise risk.",
        "Move to environment variable. Revoke the token at npmjs.com immediately.",
    ),
    (
        "PyPI Token",
        re.compile(r"(pypi-[A-Za-z0-9_-]{50,})"),
        "HIGH",
        "PyPI upload token in code. Allows publishing packages as you — a supply-chain compromise risk.",
        "Move to environment variable. Revoke the token at pypi.org immediately.",
    ),
    (
        "Generic API Key Assignment",
        re.compile(
            r"""(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]""",
            re.IGNORECASE,
        ),
        "HIGH",
        (
            "Possible API key or secret hardcoded. If this is a real credential, "
            "anyone reading this file can impersonate your app."
        ),
        "Move to environment variable. Use .env file with python-dotenv or equivalent.",
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "CRITICAL",
        (
            "Private key embedded in source file. This is the worst kind of "
            "secret leak \u2014 private keys can decrypt traffic, sign code, "
            "or authenticate as your server."
        ),
        "Move to a secure file outside the repo. Load path from environment variable.",
    ),
    (
        "Database URL with Password",
        re.compile(
            r"""(?:mongodb|postgres|mysql|redis|amqp)(?:\+\w+)?://[^:]+:([^@\s'"]{8,})@([\w.-]*)""",
            re.IGNORECASE,
        ),
        "CRITICAL",
        (
            "Database connection string with embedded password. Anyone with "
            "this string has direct access to your database."
        ),
        "Move connection string to environment variable. Use .env file.",
    ),
    (
        "JWT Secret",
        re.compile(
            r"""(?:jwt[_-]?secret|token[_-]?secret|signing[_-]?key)\s*[=:]\s*['"]([^'"]{8,})['"]""",
            re.IGNORECASE,
        ),
        "HIGH",
        "JWT signing secret in code. Anyone with this can forge authentication tokens and impersonate any user.",
        "Move to environment variable. Consider using asymmetric keys (RS256) instead.",
    ),
    (
        "Password in Variable",
        re.compile(
            r"""(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{4,})['"]""",
            re.IGNORECASE,
        ),
        "HIGH",
        "Hardcoded password in source code. If this is a real credential, it's accessible to anyone with repo access.",
        "Move to environment variable or secrets manager.",
    ),
    (
        "Slack Webhook",
        re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"),
        "MEDIUM",
        "Slack webhook URL in code. Anyone can post messages to your Slack channel.",
        "Move to environment variable.",
    ),
    (
        "SendGrid API Key",
        re.compile(r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"),
        "HIGH",
        "SendGrid API key in code. Allows sending emails as your domain — can be used for phishing.",
        "Move to environment variable.",
    ),
    (
        "Twilio Auth Token",
        re.compile(r"""(?:twilio|auth_token)\s*[=:]\s*['"]([a-f0-9]{32})['"]""", re.IGNORECASE),
        "HIGH",
        "Twilio auth token in code. Allows sending SMS and making calls from your account.",
        "Move to environment variable.",
    ),
    (
        "Heroku API Key",
        re.compile(r"""[hH]eroku.*[=:]\s*['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]"""),
        "HIGH",
        "Heroku API key in code. Allows deploying and managing your Heroku apps.",
        "Move to environment variable.",
    ),
]

# File patterns to skip (test files, lock files, etc.)
SKIP_PATTERNS = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
}

# Substrings that mark a captured value as a placeholder / prose, not a real
# credential. Used to suppress false positives like
# `temporary_password="(sent to user email)"`.
PLACEHOLDER_MARKERS = (
    "example",
    "xxxx",
    "changeme",
    "change_me",
    "placeholder",
    "your_",
    "yourpassword",
    "redacted",
    "dummy",
    "sent to",
    "see ",
    "n/a",
    "todo",
    "<",
    ">",
    "{{",
    "}}",
    "${",
    "os.getenv",
    "os.environ",
    "process.env",
    "getenv",
)


# Only freeform "name = value" patterns get placeholder filtering. Strict
# provider-format keys (AWS AKIA…, GitHub ghp_…, Stripe sk_live_…) are NOT
# filtered — their fixed shape is the signal, and AWS's own documented example
# key literally contains "EXAMPLE".
PLACEHOLDER_FILTERED = {
    "Generic API Key Assignment",
    "Password in Variable",
    "JWT Secret",
    "Database URL with Password",
    "AWS Secret Key",
    "Twilio Auth Token",
    "Heroku API Key",
}


# Development-default database credentials and hosts (docker-compose service
# names, loopback). These are real matches but almost never production
# credentials — downgraded to LOW instead of suppressed, so the report still
# mentions them without burying real leaks.
DEV_DB_PASSWORDS = {
    "postgres",
    "password",
    "password1",
    "password123",
    "rootpassword",
    "devpassword",
    "mysqlpassword",
}

DEV_DB_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",  # noqa: S104 — hostname allowlist entry, not a bind address
    "db",
    "database",
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "redis",
    "mongo",
    "mongodb",
    "rabbitmq",
    "host.docker.internal",
}


def _is_local_dev_database_url(match: re.Match[str]) -> bool:
    """True when a matched DB URL looks like a local development default."""
    password = (match.group(1) or "").lower()
    host = (match.group(2) or "").lower()
    return password in DEV_DB_PASSWORDS or host in DEV_DB_HOSTS


def _is_probably_not_a_secret(value: str) -> bool:
    """Heuristic to reject placeholder/prose values captured by a secret regex.

    Real credentials, keys, and tokens never contain whitespace and aren't
    obvious placeholders. This keeps e.g. ``password="(sent to user email)"``
    or ``api_key="<your key here>"`` from being reported as leaked secrets.
    """
    v = value.strip()
    if not v or any(ch.isspace() for ch in v):
        return True
    low = v.lower()
    return any(marker in low for marker in PLACEHOLDER_MARKERS)


# Unquoted KEY=VALUE assignments — the way real .env files are written. The
# quoted-value patterns above can't see them. Gated to env-like files so
# ordinary source code doesn't false-positive. Also matches docker-compose
# `- KEY=value` environment list entries.
UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    r"""^\s*(?:-\s+)?(?:export\s+)?"""
    r"""([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)"""
    r"""\s*=\s*([^\s'"#]{8,})\s*$""",
    re.MULTILINE,
)


def _is_env_like_file(file_path: Path) -> bool:
    """True for files where unquoted KEY=VALUE assignments are the norm."""
    name = file_path.name.lower()
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return True
    return file_path.suffix.lower() in {".yml", ".yaml", ".ini", ".cfg"}


@register_scanner
class SecretsScanner(BaseScanner):
    """Detects hardcoded secrets, API keys, tokens, and passwords."""

    name = "secrets"
    description = "Finds hardcoded API keys, tokens, passwords, and private keys"

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Scan a single file for hardcoded secrets."""
        # Skip lock files and binary-looking content
        if file_path.name in SKIP_PATTERNS:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for pattern_name, regex, severity, description, fix_summary in SECRET_PATTERNS:
            for match in regex.finditer(content):
                # Skip placeholders / prose for freeform value-patterns
                # (e.g. password="(sent to user email)"). Strict provider-format
                # keys are never filtered.
                if pattern_name in PLACEHOLDER_FILTERED and match.groups():
                    captured = match.group(1)
                    if captured is not None and _is_probably_not_a_secret(captured):
                        continue

                # Find line number
                line_start = content[: match.start()].count("\n") + 1

                # Skip if in a comment (basic heuristic)
                line_text = lines[line_start - 1] if line_start <= len(lines) else ""
                stripped = line_text.lstrip()
                if stripped.startswith(("#", "//", "*", "/*")):
                    # Still flag if it looks like a real key (not an example)
                    if "example" in line_text.lower() or "xxx" in line_text.lower():
                        continue

                # Get snippet (the line + 1 above and below for context)
                start = max(0, line_start - 2)
                end = min(len(lines), line_start + 1)
                snippet = "\n".join(lines[start:end])

                # Dev-default DB URLs (postgres:postgres@db etc.) are real
                # matches but not production leaks — downgrade, don't hide.
                finding_severity = severity
                finding_description = description
                if pattern_name == "Database URL with Password" and _is_local_dev_database_url(match):
                    finding_severity = "LOW"
                    finding_description = (
                        description + " This one looks like a local development default "
                        "(dev-standard password or local/compose hostname), so it's "
                        "reported as LOW — make sure it never ships to production."
                    )

                findings.append(
                    Finding(
                        file=str(file_path),
                        line=line_start,
                        severity=finding_severity,
                        title=f"{pattern_name} detected",
                        description=finding_description,
                        scanner=self.name,
                        snippet=snippet,
                        fix_phase=1,
                        fix_summary=fix_summary,
                    )
                )

        if _is_env_like_file(file_path):
            findings.extend(self._scan_unquoted_env_values(file_path, content, lines))

        return findings

    def _scan_unquoted_env_values(self, file_path: Path, content: str, lines: list[str]) -> list[Finding]:
        """Detect unquoted KEY=VALUE secrets in env-style files.

        Args:
            file_path: File being scanned (already gated to env-like files).
            content: Full file content.
            lines: Pre-split lines for snippet extraction.

        Returns:
            Findings for secret-looking unquoted assignments.
        """
        findings: list[Finding] = []
        for match in UNQUOTED_SECRET_ASSIGNMENT.finditer(content):
            if _is_probably_not_a_secret(match.group(2)):
                continue
            line_start = content[: match.start()].count("\n") + 1
            start = max(0, line_start - 2)
            end = min(len(lines), line_start + 1)
            findings.append(
                Finding(
                    file=str(file_path),
                    line=line_start,
                    severity="HIGH",
                    title="Unquoted secret assignment detected",
                    description=(
                        f"`{match.group(1)}` is assigned an unquoted value that looks like a real "
                        "credential. .env and config files are the most commonly leaked secret "
                        "location — if this file is ever committed, the credential is public."
                    ),
                    scanner=self.name,
                    snippet="\n".join(lines[start:end]),
                    fix_phase=1,
                    fix_summary=(
                        "Keep this file out of version control (gitignore it), use placeholder "
                        "values in committed examples, and rotate the credential if the file was "
                        "ever pushed."
                    ),
                )
            )
        return findings
