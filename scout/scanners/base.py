"""Base scanner interface — all scanners inherit from this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from scout.models import Finding


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Scan a single file's content for vulnerabilities.

        Args:
            file_path: Path to the file being scanned.
            content: Full text content of the file.

        Returns:
            List of findings (may be empty).
        """

    def scan(self, files: list[Path]) -> list[Finding]:
        """Scan multiple files and collect all findings.

        Args:
            files: List of file paths to scan.

        Returns:
            Combined list of findings from all files.
        """
        findings: list[Finding] = []
        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                findings.extend(self.scan_file(file_path, content))
            except (OSError, PermissionError):
                continue
        return findings
