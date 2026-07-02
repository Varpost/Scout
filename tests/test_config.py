"""Tests for [tool.scout] config loading, precedence, and scanner selection."""

from __future__ import annotations

import pytest

from scout.config import load_config
from scout.scanners import get_all_scanners


def _write_pyproject(tmp_path, body: str) -> None:
    (tmp_path / "pyproject.toml").write_text(body, encoding="utf-8")


def test_defaults_without_pyproject(tmp_path):
    config = load_config(project_path=tmp_path)
    assert config.exclude == ()
    assert config.scanners is None
    assert config.fail_on == "high"


def test_defaults_without_project_path():
    # Legacy call shape (AI settings only) must keep working unchanged.
    config = load_config()
    assert config.exclude == ()
    assert config.scanners is None
    assert config.fail_on == "high"


def test_reads_tool_scout_table(tmp_path):
    _write_pyproject(
        tmp_path,
        '[tool.scout]\nexclude = ["tests", "vendor"]\nscanners = ["secrets"]\nfail_on = "medium"\n',
    )
    config = load_config(project_path=tmp_path)
    assert config.exclude == ("tests", "vendor")
    assert config.scanners == ("secrets",)
    assert config.fail_on == "medium"


def test_pyproject_without_tool_scout_is_ignored(tmp_path):
    _write_pyproject(tmp_path, '[project]\nname = "x"\nversion = "0"\n')
    config = load_config(project_path=tmp_path)
    assert config.exclude == ()
    assert config.scanners is None


def test_project_path_file_uses_parent_directory(tmp_path):
    # `scout scan app.py` should still pick up the project's config.
    _write_pyproject(tmp_path, '[tool.scout]\nexclude = ["vendor"]\n')
    target = tmp_path / "app.py"
    target.write_text("print('hi')\n", encoding="utf-8")
    config = load_config(project_path=target)
    assert config.exclude == ("vendor",)


def test_cli_exclude_replaces_config_exclude(tmp_path):
    _write_pyproject(tmp_path, '[tool.scout]\nexclude = ["vendor"]\n')
    config = load_config(project_path=tmp_path, cli_exclude=["dist"])
    assert config.exclude == ("dist",)


def test_cli_fail_on_overrides_config(tmp_path):
    _write_pyproject(tmp_path, '[tool.scout]\nfail_on = "never"\n')
    config = load_config(project_path=tmp_path, cli_fail_on="CRITICAL")
    assert config.fail_on == "critical"


def test_invalid_toml_raises(tmp_path):
    _write_pyproject(tmp_path, "[tool.scout\n")
    with pytest.raises(ValueError, match="invalid TOML"):
        load_config(project_path=tmp_path)


def test_exclude_wrong_type_raises(tmp_path):
    _write_pyproject(tmp_path, '[tool.scout]\nexclude = "tests"\n')
    with pytest.raises(ValueError, match="array of strings"):
        load_config(project_path=tmp_path)


def test_scanners_wrong_element_type_raises(tmp_path):
    _write_pyproject(tmp_path, "[tool.scout]\nscanners = [1]\n")
    with pytest.raises(ValueError, match="array of strings"):
        load_config(project_path=tmp_path)


def test_empty_scanners_list_raises(tmp_path):
    # An empty list would silently scan nothing — almost certainly a typo.
    _write_pyproject(tmp_path, "[tool.scout]\nscanners = []\n")
    with pytest.raises(ValueError, match="at least one"):
        load_config(project_path=tmp_path)


def test_invalid_fail_on_value_raises(tmp_path):
    _write_pyproject(tmp_path, '[tool.scout]\nfail_on = "sometimes"\n')
    with pytest.raises(ValueError, match="fail_on"):
        load_config(project_path=tmp_path)


def test_unknown_keys_warn_but_do_not_fail(tmp_path, capsys):
    _write_pyproject(tmp_path, '[tool.scout]\nexcludes = ["tests"]\n')
    config = load_config(project_path=tmp_path)
    assert config.exclude == ()
    assert "unknown [tool.scout] key" in capsys.readouterr().err


# --- Scanner selection (get_all_scanners) -----------------------------------


def test_get_all_scanners_returns_everything_by_default():
    names = {cls.name for cls in get_all_scanners()}
    assert {"secrets", "injection", "headers", "deps"} <= names


def test_get_all_scanners_filters_by_name():
    names = {cls.name for cls in get_all_scanners(("secrets",))}
    assert names == {"secrets"}


def test_get_all_scanners_unknown_name_raises():
    with pytest.raises(ValueError, match="unknown scanner"):
        get_all_scanners(("secrets", "nope"))
