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
