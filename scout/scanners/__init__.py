"""Scanner registry — auto-discovers and runs all scanners."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scout.scanners.base import BaseScanner

_registry: list[type[BaseScanner]] = []


def register_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Decorator to register a scanner class."""
    _registry.append(cls)
    return cls


def get_all_scanners() -> list[type[BaseScanner]]:
    """Return all registered scanner classes."""
    # Import scanner modules to trigger registration  # noqa: I001
    from scout.scanners import deps, headers, injection, secrets  # noqa: F401

    return list(_registry)


def _is_security_relevant_filename(name: str) -> bool:
    """Match security-relevant files that a suffix check can't catch.

    ``Path('.env').suffix == ''`` and Dockerfiles have no extension at all,
    so a suffix-only check silently skips the #1 secret-leak vector.

    Args:
        name: Bare filename (no directory part).

    Returns:
        True for ``.env``/``.env.*``, ``Dockerfile``/``Dockerfile.*``, and
        ``docker-compose*`` files.
    """
    lower = name.lower()
    if lower == ".env" or lower.startswith(".env."):
        return True
    if lower == "dockerfile" or lower.startswith("dockerfile."):
        return True
    return lower.startswith("docker-compose")


def collect_files(path: Path, extensions: set[str] | None = None) -> list[Path]:
    """Collect all scannable files in a directory tree.

    Files are matched by extension, plus a filename allowlist for
    security-relevant files without a usable suffix (`.env*`, `Dockerfile*`,
    `docker-compose*`).

    Args:
        path: Root directory to scan.
        extensions: File extensions to include (e.g., {'.py', '.js'}).
                    If None, includes common source files.

    Returns:
        List of file paths.
    """
    if extensions is None:
        extensions = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".mjs",
            ".cjs",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".rs",
            ".c",
            ".cpp",
            ".h",
            ".yml",
            ".yaml",
            ".toml",
            ".json",
            ".env",
            ".cfg",
            ".ini",
            ".sh",
            ".bash",
            ".zsh",
            ".ps1",
            ".bat",
            ".cmd",
            ".dockerfile",
            ".tf",
            ".hcl",
        }

    files: list[Path] = []
    skip_dirs = {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "coverage",
    }

    if path.is_file():
        return [path] if path.suffix.lower() in extensions or _is_security_relevant_filename(path.name) else []

    for item in path.rglob("*"):
        if item.is_file() and (item.suffix.lower() in extensions or _is_security_relevant_filename(item.name)):
            # Skip files in ignored directories
            if not any(part in skip_dirs for part in item.parts):
                files.append(item)

    return files
