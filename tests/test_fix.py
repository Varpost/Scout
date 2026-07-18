"""Tests for `scout fix` — diff-and-confirm fixes for phase-1 findings."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from scout.cli import app
from scout.fix import apply_fix, plan_fixes, render_diff, verify_fix
from scout.models import Finding
from scout.scanners.secrets import SecretsScanner

runner = CliRunner()

# Runtime-built so it never trips push protection; matches the generic
# api_key pattern (20+ chars).
FAKE_KEY = "sk_fake_" + "a1B2" * 5


def _secret_file(tmp_path: Path, newline: str = "\n") -> Path:
    target = tmp_path / "settings.py"
    content = f'api_key = "{FAKE_KEY}"{newline}print(api_key){newline}'
    target.write_bytes(content.encode("utf-8"))
    return target


def _secret_finding(target: Path) -> Finding:
    findings = SecretsScanner().scan_file(target, target.read_text(encoding="utf-8"))
    assert findings, "fixture must trigger the secrets scanner"
    return findings[0]


def test_secret_fix_moves_value_to_env(tmp_path):
    target = _secret_file(tmp_path)
    (proposal,) = plan_fixes([_secret_finding(target)], tmp_path)
    apply_fix(proposal)

    code = target.read_text(encoding="utf-8")
    assert 'api_key = os.environ["API_KEY"]' in code
    assert code.startswith("import os")
    assert FAKE_KEY not in code
    assert f"API_KEY={FAKE_KEY}" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert ".env" in (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert verify_fix(proposal), "re-scan must come back clean"
    assert "rotate" in proposal.warning.lower()


def test_secret_fix_preserves_crlf(tmp_path):
    target = _secret_file(tmp_path, newline="\r\n")
    (proposal,) = plan_fixes([_secret_finding(target)], tmp_path)
    apply_fix(proposal)
    assert b"\r\n" in target.read_bytes()


def test_secret_fix_refuses_non_assignment_lines(tmp_path):
    # A secret inside a function call is not a mechanical rewrite — skip it.
    target = tmp_path / "app.py"
    target.write_text(f'connect(api_key="{FAKE_KEY}")\n', encoding="utf-8")
    findings = SecretsScanner().scan_file(target, target.read_text(encoding="utf-8"))
    assert plan_fixes(findings, tmp_path) == []


def test_dep_fix_bumps_pin(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.0\nflask==2.3.0\n", encoding="utf-8")
    finding = Finding(
        file=str(req),
        line=1,
        severity="HIGH",
        title="Vulnerable package: requests==2.19.0 (CVE-TEST)",
        description="test",
        scanner="deps",
        snippet="requests==2.19.0",
        fix_phase=1,
        fix_summary="Upgrade requests to >=2.20.0",
    )
    (proposal,) = plan_fixes([finding], tmp_path)
    apply_fix(proposal)
    assert req.read_text(encoding="utf-8") == "requests==2.20.0\nflask==2.3.0\n"
    assert verify_fix(proposal)


def test_dep_fix_without_fixed_version_is_skipped(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.0\n", encoding="utf-8")
    finding = Finding(
        file=str(req),
        line=1,
        severity="HIGH",
        title="Vulnerable package: requests==2.19.0 (CVE-TEST)",
        description="test",
        scanner="deps",
        snippet="requests==2.19.0",
        fix_phase=1,
        fix_summary="Upgrade requests to a patched release",
    )
    assert plan_fixes([finding], tmp_path) == []


def test_render_diff_shows_change(tmp_path):
    target = _secret_file(tmp_path)
    (proposal,) = plan_fixes([_secret_finding(target)], tmp_path)
    diff = render_diff(proposal)
    assert f'-api_key = "{FAKE_KEY}"' in diff
    assert '+api_key = os.environ["API_KEY"]' in diff
    assert f"+API_KEY={FAKE_KEY}" in diff  # .env side effect visible in the diff


def test_cli_fix_declined_leaves_file_untouched(tmp_path):
    target = _secret_file(tmp_path)
    before = target.read_bytes()
    result = runner.invoke(app, ["fix", str(tmp_path)], input="n\n")
    assert result.exit_code == 0
    assert target.read_bytes() == before, "declined fix must not modify anything"
    assert not (tmp_path / ".env").exists()


def test_cli_fix_confirmed_applies_and_verifies(tmp_path):
    target = _secret_file(tmp_path)
    result = runner.invoke(app, ["fix", str(tmp_path)], input="y\n")
    assert result.exit_code == 0
    assert 'os.environ["API_KEY"]' in target.read_text(encoding="utf-8")
    assert "re-scan clean" in result.output
    assert "1" in result.output and "applied" in result.output


def test_cli_fix_no_fixable_findings(tmp_path):
    (tmp_path / "app.py").write_text("result = eval(user_input)\n", encoding="utf-8")  # phase 4
    result = runner.invoke(app, ["fix", str(tmp_path)])
    assert result.exit_code == 0
    assert "No auto-fixable findings" in result.output
