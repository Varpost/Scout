"""Tests for the secrets scanner."""

from pathlib import Path

from scout.scanners.secrets import SecretsScanner

FIXTURES = Path(__file__).parent.parent / "fixtures"


# --- Provider-specific patterns (inline to avoid GitHub Push Protection) ---


def _build_secret(prefix: str, suffix: str) -> str:
    """Construct a secret string dynamically to avoid push protection detection."""
    return prefix + suffix


def test_detects_aws_access_key():
    scanner = SecretsScanner()
    key = _build_secret("AKIA", "IOSFODNN7EXAMPLE")
    content = f'AWS_KEY = "{key}"'
    findings = scanner.scan_file(Path("fake.py"), content)
    titles = [f.title for f in findings]
    assert any("AWS Access Key" in t for t in titles)


def test_detects_github_token():
    scanner = SecretsScanner()
    key = _build_secret("ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    content = f'GITHUB_TOKEN = "{key}"'
    findings = scanner.scan_file(Path("fake.py"), content)
    titles = [f.title for f in findings]
    assert any("GitHub Token" in t for t in titles)


def test_detects_stripe_live_key():
    scanner = SecretsScanner()
    key = _build_secret("sk_" + "live_", "TESTKEY00exampleTESTKEY00ex")
    content = f'STRIPE_KEY = "{key}"'
    findings = scanner.scan_file(Path("fake.py"), content)
    titles = [f.title for f in findings]
    assert any("Stripe Live Key" in t for t in titles)


def test_detects_current_provider_key_formats():
    # T3.3a: the credential formats Scout's audience most commonly leaks but
    # earlier versions couldn't see. Values are split via _build_secret so the
    # source never contains a whole token (GitHub Push Protection stays quiet).
    scanner = SecretsScanner()
    cases = [
        ("Anthropic API Key", _build_secret("sk-ant-", "api03-" + "A" * 60)),
        ("OpenAI Project Key", _build_secret("sk-" + "proj-", "T3st" + "A" * 60)),
        ("Slack Token", _build_secret("xox" + "b-", "2488-1234567890-ABCDEFghijklmn")),
        ("Google API Key", _build_secret("AIza", "Sy" + "A" * 33)),
        ("GitLab Token", _build_secret("glpat-", "A" * 20)),
        ("npm Token", _build_secret("npm" + "_", "A" * 36)),
        ("PyPI Token", _build_secret("pypi-", "AgEIcHlwaS" + "A" * 50)),
    ]
    for expected_title, key in cases:
        content = f'SECRET = "{key}"'
        titles = [f.title for f in scanner.scan_file(Path("fake.py"), content)]
        assert any(expected_title in t for t in titles), f"{expected_title} not detected: {titles}"


def test_new_provider_key_formats_do_not_false_positive_on_safe_code():
    # The new strict-prefix patterns must not fire on ordinary code.
    scanner = SecretsScanner()
    content = FIXTURES.joinpath("safe_app.py").read_text()
    titles = [f.title for f in scanner.scan_file(FIXTURES / "safe_app.py", content)]
    for name in ("Anthropic API Key", "OpenAI Project Key", "Slack Token", "Google API Key", "GitLab Token"):
        assert not any(name in t for t in titles), f"unexpected {name}: {titles}"


# --- Patterns safe from push protection (tested via fixture) ---


def test_detects_database_url_with_password():
    scanner = SecretsScanner()
    content = FIXTURES.joinpath("has_secrets.py").read_text()
    findings = scanner.scan_file(FIXTURES / "has_secrets.py", content)
    titles = [f.title for f in findings]
    assert any("Database URL" in t for t in titles)


def test_detects_jwt_secret():
    scanner = SecretsScanner()
    content = FIXTURES.joinpath("has_secrets.py").read_text()
    findings = scanner.scan_file(FIXTURES / "has_secrets.py", content)
    titles = [f.title for f in findings]
    assert any("JWT Secret" in t for t in titles)


def test_no_false_positives_on_safe_code():
    scanner = SecretsScanner()
    content = FIXTURES.joinpath("safe_app.py").read_text()
    findings = scanner.scan_file(FIXTURES / "safe_app.py", content)
    # Safe code should produce zero or minimal findings
    critical = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical) == 0, f"False positives: {[f.title for f in critical]}"


def test_password_placeholder_is_not_flagged():
    # Regression: real-world FP — a prose value matched the password pattern.
    scanner = SecretsScanner()
    content = 'temporary_password="(sent to user email)"'
    findings = scanner.scan_file(Path("api_server.py"), content)
    assert not any("Password" in f.title for f in findings), [f.title for f in findings]


def test_api_key_placeholder_is_not_flagged():
    scanner = SecretsScanner()
    content = 'api_key = "<your-api-key-here>"'
    findings = scanner.scan_file(Path("config.py"), content)
    assert findings == []


def test_real_password_is_still_flagged():
    scanner = SecretsScanner()
    content = 'password = "S3cr3tP4ssw0rdValue99"'
    findings = scanner.scan_file(Path("api_server.py"), content)
    assert any("Password" in f.title for f in findings)


def test_dev_default_database_url_is_downgraded_to_low():
    # Regression: docker-compose default creds guaranteed a CRITICAL on scan #1.
    scanner = SecretsScanner()
    content = 'DATABASE_URL = "postgres://postgres:postgres@db:5432/app"'
    findings = scanner.scan_file(Path("docker-compose.yml"), content)
    db = [f for f in findings if "Database URL" in f.title]
    assert db, "dev-default URL should still be reported (downgraded, not hidden)"
    assert db[0].severity == "LOW"
    assert "local development" in db[0].description


def test_localhost_database_url_is_downgraded_to_low():
    scanner = SecretsScanner()
    content = 'url = "mysql://appuser:s0meRealish9@localhost/dev"'
    findings = scanner.scan_file(Path("settings.py"), content)
    db = [f for f in findings if "Database URL" in f.title]
    assert db and db[0].severity == "LOW"


def test_production_looking_database_url_stays_critical():
    scanner = SecretsScanner()
    content = 'DATABASE_URL = "postgres://svc:Xk29fjs8Hqz@db-prod-7.internal:5432/app"'
    findings = scanner.scan_file(Path("settings.py"), content)
    db = [f for f in findings if "Database URL" in f.title]
    assert db and db[0].severity == "CRITICAL"


def test_findings_have_correct_structure():
    scanner = SecretsScanner()
    content = FIXTURES.joinpath("has_secrets.py").read_text()
    findings = scanner.scan_file(FIXTURES / "has_secrets.py", content)
    assert len(findings) > 0
    for f in findings:
        assert f.file
        assert f.line > 0
        assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert f.title
        assert f.description
        assert f.scanner == "secrets"
        assert f.fix_phase == 1


# --- Unquoted KEY=VALUE secrets (.env and friends) -------------------------


def test_unquoted_env_secret_is_detected():
    scanner = SecretsScanner()
    content = "DEBUG=true\nPASSWORD=supersecretvalue123\n"
    findings = scanner.scan_file(Path(".env"), content)
    unquoted = [f for f in findings if "Unquoted" in f.title]
    assert unquoted, [f.title for f in findings]
    assert unquoted[0].line == 2


def test_unquoted_pattern_is_gated_to_env_like_files():
    # Ordinary source code must not get the env-file treatment.
    scanner = SecretsScanner()
    content = "PASSWORD=supersecretvalue123\n"
    findings = scanner.scan_file(Path("app.py"), content)
    assert not any("Unquoted" in f.title for f in findings)


def test_unquoted_placeholders_are_not_flagged():
    scanner = SecretsScanner()
    content = "PASSWORD=changeme123\nAPI_KEY=${REAL_KEY}\n"
    assert scanner.scan_file(Path(".env"), content) == []


def test_compose_environment_list_entry_is_detected():
    scanner = SecretsScanner()
    content = "services:\n  db:\n    environment:\n      - DB_PASSWORD=supersecretvalue123\n"
    findings = scanner.scan_file(Path("docker-compose.yml"), content)
    assert any("Unquoted" in f.title for f in findings)


def test_env_secret_detected_end_to_end(tmp_path):
    # The whole pipeline: .env is collected (T0.6) and its unquoted value
    # is detected (T0.7), landing in the generated report.
    from typer.testing import CliRunner

    from scout.cli import app

    (tmp_path / ".env").write_text("PASSWORD=supersecretvalue123\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "--no-ai", "--fail-on", "never"])
    assert result.exit_code == 0
    report = (tmp_path / "security-report.md").read_text(encoding="utf-8")
    assert "Unquoted secret assignment detected" in report
