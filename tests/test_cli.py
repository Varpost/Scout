"""Tests for CLI startup behavior."""

from typer.testing import CliRunner

from scout import __version__
from scout.cli import _force_utf8_output, app

runner = CliRunner()


def test_force_utf8_output_is_safe_and_idempotent():
    # Must never raise, even when called repeatedly or on captured streams.
    _force_utf8_output()
    _force_utf8_output()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_emits_emoji_summary_without_crashing(tmp_path):
    # A finding-producing file: the summary uses emoji that used to crash on
    # Windows cp1252 streams. The run must complete cleanly.
    target = tmp_path / "app.py"
    target.write_text('os.system("ls " + user_input)\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--fail-on", "never"])
    assert result.exit_code == 0


def test_report_shows_real_scanned_file_count(tmp_path):
    # Regression: the report header rendered an em-dash placeholder instead
    # of the actual number of files scanned.
    target = tmp_path / "app.py"
    target.write_text('os.system("ls " + user_input)\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--fail-on", "never"])
    assert result.exit_code == 0
    report = (tmp_path / "security-report.md").read_text(encoding="utf-8")
    assert "**Files scanned:** 1" in report


def test_stub_commands_hidden_from_help():
    # fix/validate/report are unimplemented stubs — advertising them in
    # --help funnels users into "Coming soon" dead ends.
    result = runner.invoke(app, ["--help"])
    assert "Scan a project" in result.stdout
    assert "Apply fixes for a specific phase" not in result.stdout
    assert "Re-scan changed files and run tests" not in result.stdout
    assert "Re-generate the report from last scan" not in result.stdout


def test_scan_output_does_not_advertise_stub_commands(tmp_path):
    # The post-scan next-step must point at the real workflow (ai-prompt),
    # not the unimplemented `scout fix`.
    target = tmp_path / "app.py"
    target.write_text('os.system("ls " + user_input)\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--fail-on", "never"])
    assert result.exit_code == 0
    assert "scout fix" not in result.output
    assert "ai-prompt" in result.output


# --- Exit codes (--fail-on) -------------------------------------------------


def test_scan_exits_1_on_critical_findings_by_default(tmp_path):
    (tmp_path / "app.py").write_text('os.system("ls " + user_input)\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai"])
    assert result.exit_code == 1


def test_fail_on_never_always_exits_0(tmp_path):
    (tmp_path / "app.py").write_text('os.system("ls " + user_input)\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--fail-on", "never"])
    assert result.exit_code == 0


def test_fail_on_critical_passes_a_high_only_project(tmp_path):
    # An unquoted .env secret is HIGH: above the default threshold,
    # below --fail-on critical.
    (tmp_path / ".env").write_text("PASSWORD=supersecretvalue123\n", encoding="utf-8")
    passing = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--fail-on", "critical"])
    assert passing.exit_code == 0
    failing = runner.invoke(app, ["scan", str(tmp_path), "--no-ai"])
    assert failing.exit_code == 1


def test_clean_project_exits_0(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai"])
    assert result.exit_code == 0


def test_json_format_respects_fail_on(tmp_path):
    (tmp_path / "app.py").write_text('os.system("ls " + user_input)\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--format", "json"])
    assert result.exit_code == 1


def test_invalid_fail_on_exits_2(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--fail-on", "sometimes"])
    assert result.exit_code == 2


# --- --exclude and [tool.scout] config ---------------------------------------


def test_exclude_flag_removes_findings(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "sample.py").write_text("result = eval(user_input)\n", encoding="utf-8")

    failing = runner.invoke(app, ["scan", str(tmp_path), "--no-ai"])
    assert failing.exit_code == 1
    passing = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--exclude", "tests"])
    assert passing.exit_code == 0


def test_config_scanners_runs_only_named_scanner(tmp_path):
    import json

    (tmp_path / "pyproject.toml").write_text('[tool.scout]\nscanners = ["secrets"]\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("result = eval(user_input)\n", encoding="utf-8")
    (tmp_path / ".env").write_text('AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--no-ai", "--format", "json", "-o", str(out), "--fail-on", "never"],
    )
    assert result.exit_code == 0
    findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
    assert findings, "the secrets scanner should still report the AWS key"
    assert {f["scanner"] for f in findings} == {"secrets"}


def test_config_fail_on_is_used_and_cli_flag_overrides_it(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.scout]\nfail_on = "never"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text('os.system("ls " + user_input)\n', encoding="utf-8")

    from_config = runner.invoke(app, ["scan", str(tmp_path), "--no-ai"])
    assert from_config.exit_code == 0
    overridden = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--fail-on", "high"])
    assert overridden.exit_code == 1


def test_invalid_config_fail_on_exits_2(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.scout]\nfail_on = "sometimes"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai"])
    assert result.exit_code == 2


def test_unknown_scanner_in_config_exits_2(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.scout]\nscanners = ["nope"]\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai"])
    assert result.exit_code == 2
