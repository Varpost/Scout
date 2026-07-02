"""Data models shared across all Scout agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels — declaration order IS the ordering.

    Every severity-ordered or severity-enumerating piece of code (sort keys,
    exit-code thresholds, count/display loops, badge and SARIF level maps)
    derives from this enum; nothing else may hardcode the list.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_SEVERITY_RANK = {severity: index for index, severity in enumerate(Severity)}


def severity_rank(value: str) -> int:
    """Sort key for a severity string: CRITICAL first, unknown values last.

    Args:
        value: A severity name, e.g. ``"HIGH"``.

    Returns:
        Position in the canonical ordering; ``len(Severity)`` when unknown.
    """
    try:
        return _SEVERITY_RANK[Severity(value)]
    except ValueError:
        return len(Severity)


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
    references: list[str] = field(default_factory=list)
    ai_confirmed: bool | None = None
    # Project-level findings (the app-wide CSRF check) have synthetic line
    # anchors, so line-based `scout: ignore` suppression must never apply
    # to them.
    project_level: bool = False


# Phase and ScanResult dataclasses used to live here — never referenced.
# ScanOutcome (scout.agents.scout_agent) is the live scan-result type.
