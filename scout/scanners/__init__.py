"""Scanner registry — auto-discovers and runs all scanners."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

import pathspec

if TYPE_CHECKING:
    from collections.abc import Sequence

    from scout.scanners.base import BaseScanner

_registry: list[type[BaseScanner]] = []


def register_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Decorator to register a scanner class."""
    _registry.append(cls)
    return cls


def get_all_scanners(only: Sequence[str] | None = None) -> list[type[BaseScanner]]:
    """Return registered scanner classes, optionally filtered by name.

    Args:
        only: Scanner names to keep (e.g. from ``[tool.scout] scanners``).
            None returns every registered scanner.

    Returns:
        Scanner classes in registration order.

    Raises:
        ValueError: If ``only`` names a scanner that doesn't exist.
    """
    # Import scanner modules to trigger registration  # noqa: I001
    from scout.scanners import custom, deps, headers, injection, secrets  # noqa: F401

    if only is None:
        return list(_registry)
    known = {cls.name for cls in _registry}
    unknown = sorted(set(only) - known)
    if unknown:
        raise ValueError(f"unknown scanner(s): {', '.join(unknown)}. Available: {', '.join(sorted(known))}")
    wanted = set(only)
    return [cls for cls in _registry if cls.name in wanted]


def _is_excluded(rel_path: str, exclude: Sequence[str]) -> bool:
    """Check a root-relative POSIX path against exclude patterns.

    A pattern excludes the path itself, anything under it as a directory
    prefix, and any fnmatch glob match (e.g. ``*.min.js``).

    Args:
        rel_path: File path relative to the scan root, in POSIX form.
        exclude: Patterns from ``--exclude`` / ``[tool.scout] exclude``.

    Returns:
        True if the file should be skipped.
    """
    for raw in exclude:
        pattern = raw.replace("\\", "/").strip("/")
        if not pattern:
            continue
        if rel_path == pattern or rel_path.startswith(pattern + "/"):
            return True
        if fnmatch(rel_path, pattern):
            return True
    return False


def _load_gitignore(root: Path) -> pathspec.PathSpec[pathspec.Pattern] | None:
    """Parse the scan root's ``.gitignore`` into a matcher, if present.

    Honors the root ``.gitignore`` only — not nested ``.gitignore`` files,
    ``.git/info/exclude``, or the global excludesfile. That covers the common
    case (keeping build artifacts and vendored code out of a scan) without
    reimplementing git's full ignore resolution.

    Args:
        root: Directory being scanned.

    Returns:
        A compiled PathSpec, or None when there is no readable ``.gitignore``.
    """
    try:
        lines = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


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


def collect_files(
    path: Path,
    extensions: set[str] | None = None,
    exclude: Sequence[str] = (),
) -> list[Path]:
    """Collect all scannable files in a directory tree.

    Files are matched by extension, plus a filename allowlist for
    security-relevant files without a usable suffix (`.env*`, `Dockerfile*`,
    `docker-compose*`).

    Args:
        path: Root directory to scan.
        extensions: File extensions to include (e.g., {'.py', '.js'}).
                    If None, includes common source files.
        exclude: Paths (relative to ``path``) or glob patterns to skip,
                 e.g. ``["tests/fixtures", "*.min.js"]``. Ignored when
                 ``path`` is a single file — an explicitly named file is
                 always scanned.

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
    # Baseline always-skip set: VCS/tooling/build dirs that are never source
    # and are unsafe to scan even in a repo with no .gitignore. Deliberately
    # excludes "env" — a legit source dir can be named env; a virtualenv named
    # env/ is caught by .gitignore instead (the T3.2 fix).
    skip_dirs = {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
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

    gitignore = _load_gitignore(path)

    for item in path.rglob("*"):
        if not (item.is_file() and (item.suffix.lower() in extensions or _is_security_relevant_filename(item.name))):
            continue
        # Skip files in ignored directories
        if any(part in skip_dirs for part in item.parts):
            continue
        rel = item.relative_to(path).as_posix()
        # Honor the project's .gitignore (build artifacts, vendored code, …).
        if gitignore is not None and gitignore.match_file(rel):
            continue
        if exclude and _is_excluded(rel, exclude):
            continue
        files.append(item)

    return files
