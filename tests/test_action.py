"""Guards for the published composite GitHub Action."""

from __future__ import annotations

from pathlib import Path

ACTION_FILE = Path(__file__).resolve().parents[1] / "action.yml"


def test_action_file_exists_with_expected_shape():
    # Consumers reference `uses: Varpost/Scout@<rev>` — the action must stay
    # at the repo root with these inputs.
    text = ACTION_FILE.read_text(encoding="utf-8")
    assert 'using: "composite"' in text
    for input_name in ("path:", "fail-on:", "format:", "upload-sarif:", "install:"):
        assert input_name in text
    # The threshold must be enforced AFTER the upload step — a failing scan
    # step would skip the SARIF upload entirely.
    assert text.index("upload-sarif@") < text.index("Enforce fail-on threshold")


def test_ci_dogfoods_the_action():
    ci = (ACTION_FILE.parent / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "uses: ./" in ci


def test_readme_documents_the_action():
    readme = (ACTION_FILE.parent / "README.md").read_text(encoding="utf-8")
    assert "uses: Varpost/Scout@" in readme
    assert "security-events: write" in readme
