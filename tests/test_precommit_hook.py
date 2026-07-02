"""Guards for the published pre-commit hook definition."""

from __future__ import annotations

from pathlib import Path

HOOKS_FILE = Path(__file__).resolve().parents[1] / ".pre-commit-hooks.yaml"


def test_hook_file_exists_with_expected_id_and_entry():
    # pre-commit consumers pin `id: scout` — renaming it breaks every
    # downstream .pre-commit-config.yaml.
    text = HOOKS_FILE.read_text(encoding="utf-8")
    assert "- id: scout" in text
    assert "entry: scout scan . --no-ai" in text
    assert "language: python" in text
    # `scout scan` takes one path argument; pre-commit must not append
    # staged filenames to it.
    assert "pass_filenames: false" in text


def test_readme_documents_the_hook():
    readme = (HOOKS_FILE.parent / "README.md").read_text(encoding="utf-8")
    assert "repo: https://github.com/Varpost/Scout" in readme
    assert "id: scout" in readme
