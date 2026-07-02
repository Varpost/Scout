"""Tests for the BaseScanner contract."""

from __future__ import annotations

from pathlib import Path

from scout.models import Finding
from scout.scanners.base import BaseScanner


class _EchoScanner(BaseScanner):
    name = "echo"
    description = "returns one finding per readable file"

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        return [
            Finding(
                file=str(file_path),
                line=1,
                severity="LOW",
                title="echo",
                description=content.strip(),
                scanner=self.name,
            )
        ]


def test_scan_swallows_unreadable_files(tmp_path):
    # The contract: a scan never crashes on an unreadable file — the file is
    # skipped and every other file still gets scanned.
    readable = tmp_path / "ok.py"
    readable.write_text("hello\n", encoding="utf-8")
    missing = tmp_path / "gone.py"

    findings = _EchoScanner().scan([missing, readable])
    assert [f.file for f in findings] == [str(readable)]


def test_scan_aggregates_findings_across_files(tmp_path):
    first = tmp_path / "a.py"
    first.write_text("A\n", encoding="utf-8")
    second = tmp_path / "b.py"
    second.write_text("B\n", encoding="utf-8")

    findings = _EchoScanner().scan([first, second])
    assert {f.description for f in findings} == {"A", "B"}
