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
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai"])
    assert result.exit_code == 0
