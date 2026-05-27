"""Data models shared across all Scout agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """A single security finding from a scanner."""

    file: str
    line: int
    severity: str
    title: str
    description: str
    scanner: str
    snippet: str = ""
    fix_phase: int = 1
    fix_summary: str = ""
    ai_confirmed: bool | None = None


@dataclass
class Phase:
    """A fix phase grouping related findings."""

    number: int
    name: str
    risk_level: str
    description: str
    findings: list[Finding] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete output of a Scout scan."""

    project_path: str
    total_files_scanned: int
    findings: list[Finding] = field(default_factory=list)
    phases: list[Phase] = field(default_factory=list)
