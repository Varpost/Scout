"""External engine registry — orchestrates best-of-breed OSS scanners.

Engines wrap an installed third-party binary (semgrep, gitleaks, …) and map
its output onto Scout's ``Finding`` model. They are strictly opt-in via
``--engine`` / ``[tool.scout] engines``, so the zero-dependency core scan is
unchanged when none are requested, and a missing binary degrades to a visible
note — never a crash (the deps-scanner fail-open pattern).
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from scout.models import Finding


class BaseEngine(ABC):
    """Abstract base class for external scan engines."""

    name: str = "base"
    # Executable resolved on PATH; availability is just "is it installed".
    binary: str = "base"

    def available(self) -> bool:
        """Check whether the engine's binary is installed.

        Returns:
            True when the binary resolves on PATH.
        """
        return shutil.which(self.binary) is not None

    @abstractmethod
    def run(self, path: Path) -> list[Finding]:
        """Run the engine against a path and map its results to findings.

        Implementations must never raise on engine failure — warn to stderr
        and return an empty list instead, so an engine hiccup can never take
        down the native scan.

        Args:
            path: Root directory or file to scan.

        Returns:
            Findings mapped onto Scout's model (may be empty).
        """


_registry: list[type[BaseEngine]] = []


def register_engine(cls: type[BaseEngine]) -> type[BaseEngine]:
    """Decorator to register an engine class."""
    _registry.append(cls)
    return cls


def get_engines(only: Sequence[str]) -> list[BaseEngine]:
    """Return engine instances for the requested names.

    Args:
        only: Engine names from ``--engine`` / ``[tool.scout] engines``.

    Returns:
        Engine instances in registration order.

    Raises:
        ValueError: If a name doesn't match a registered engine.
    """
    # Import engine modules to trigger registration  # noqa: I001
    from scout.engines import semgrep  # noqa: F401

    known = {cls.name for cls in _registry}
    unknown = sorted(set(only) - known)
    if unknown:
        raise ValueError(f"unknown engine(s): {', '.join(unknown)}. Available: {', '.join(sorted(known))}")
    wanted = set(only)
    return [cls() for cls in _registry if cls.name in wanted]
