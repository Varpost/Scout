"""Tests for version metadata consistency."""

from __future__ import annotations

import re
from pathlib import Path

from scout import __version__

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_version_matches_package():
    # cli.py prints scout.__version__, so the two declarations must move together.
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', pyproject, flags=re.MULTILINE)
    assert match is not None
    assert match.group(1) == __version__


def test_docs_example_versions_are_current():
    # README and docs show real CLI output ("Scout vX.Y.Z scanning: …") — any
    # version they display must be the released one, or the docs are stale.
    for doc in ("README.md", "docs/index.html"):
        text = (REPO_ROOT / doc).read_text(encoding="utf-8")
        for shown in re.findall(r"Scout v(\d+\.\d+\.\d+)", text):
            assert shown == __version__, f"{doc} shows stale version {shown}"
