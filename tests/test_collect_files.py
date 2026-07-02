"""Tests for scannable-file collection."""

from __future__ import annotations

from scout.scanners import collect_files


def test_env_and_dockerfile_are_collected(tmp_path):
    # Regression: Path('.env').suffix == '' — a suffix-only check silently
    # skipped the #1 secret-leak vector.
    (tmp_path / ".env").write_text("API_KEY=x\n", encoding="utf-8")
    (tmp_path / ".env.production").write_text("API_KEY=y\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    names = {f.name for f in collect_files(tmp_path)}
    assert {".env", ".env.production", "Dockerfile", "docker-compose.yml", "app.py"} <= names


def test_env_inside_skip_dirs_is_not_collected(tmp_path):
    node = tmp_path / "node_modules"
    node.mkdir()
    (node / ".env").write_text("X=1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    assert all("node_modules" not in str(f) for f in collect_files(tmp_path))


def test_scanning_a_single_env_file_directly(tmp_path):
    env = tmp_path / ".env"
    env.write_text("API_KEY=x\n", encoding="utf-8")

    assert collect_files(env) == [env]


def test_unrelated_extensionless_files_are_not_collected(tmp_path):
    (tmp_path / "Makefile").write_text("all:\n", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")

    names = {f.name for f in collect_files(tmp_path)}
    assert "Makefile" not in names
    assert "LICENSE" not in names
    assert "app.py" in names
