"""Configuration loading for Scout."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

# Shared with the CLI's --fail-on validation.
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "never")

_KNOWN_KEYS = {"exclude", "scanners", "fail_on"}


@dataclass
class ScoutConfig:
    """Runtime configuration for Scout.

    Attributes:
        ai_provider: "anthropic" | "openai" | "ollama" | "none".
        anthropic_key: API key for Anthropic, if set.
        openai_key: API key for OpenAI, if set.
        ollama_host: Ollama server URL.
        ollama_model: Ollama model name.
        exclude: Paths/globs (relative to the scan root) to skip.
        scanners: Scanner names to run; None means all registered scanners.
        fail_on: Severity threshold for exit code 1 (or "never").
        ai_model: Override the confirmation-pass model for the selected
            provider; None uses that provider's built-in default.
    """

    ai_provider: str
    anthropic_key: str | None
    openai_key: str | None
    ollama_host: str
    ollama_model: str
    exclude: tuple[str, ...] = ()
    scanners: tuple[str, ...] | None = None
    fail_on: str = "high"
    ai_model: str | None = None

    @property
    def ai_enabled(self) -> bool:
        """Check if AI pass is configured and available."""
        if self.ai_provider == "none":
            return False
        if self.ai_provider == "anthropic" and not self.anthropic_key:
            return False
        if self.ai_provider == "openai" and not self.openai_key:
            return False
        return True


def _read_tool_scout(project_path: Path) -> dict[str, Any]:
    """Read the ``[tool.scout]`` table from the project's pyproject.toml.

    Args:
        project_path: Scan target — a directory, or a file whose parent
            directory is used.

    Returns:
        The raw table; empty when pyproject.toml is absent or unreadable.

    Raises:
        ValueError: If pyproject.toml exists but is not valid TOML.
    """
    root = project_path if project_path.is_dir() else project_path.parent
    pyproject = root / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except OSError:
        return {}
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid TOML in {pyproject}: {exc}") from exc

    tool = data.get("tool")
    if not isinstance(tool, dict):
        return {}
    table = tool.get("scout")
    if table is None:
        return {}
    if not isinstance(table, dict):
        raise ValueError(f"[tool.scout] in {pyproject} must be a table")
    return table


def _string_tuple(value: object, key: str) -> tuple[str, ...]:
    """Validate a [tool.scout] value as an array of strings."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"[tool.scout] {key} must be an array of strings")
    return tuple(value)


def load_config(
    ai_provider: str = "none",
    ollama_model: str = "llama3",
    project_path: Path | None = None,
    cli_exclude: list[str] | None = None,
    cli_fail_on: str | None = None,
) -> ScoutConfig:
    """Load configuration from CLI flags, ``[tool.scout]``, and environment.

    Precedence for overlapping settings: CLI flag > ``[tool.scout]`` in the
    scanned project's pyproject.toml > built-in default. ``--exclude`` flags
    replace the config list entirely rather than merging with it.

    Args:
        ai_provider: Override AI provider selection.
        ollama_model: Override Ollama model name.
        project_path: Scan target; its pyproject.toml supplies [tool.scout].
        cli_exclude: --exclude values; None when the flag wasn't passed.
        cli_fail_on: --fail-on value; None when the flag wasn't passed.

    Returns:
        ScoutConfig with all resolved values.

    Raises:
        ValueError: If [tool.scout] is malformed — invalid TOML, wrong value
            types, an empty scanners list, or an unknown fail_on value.
    """
    # Load .env from current directory if present
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        load_dotenv(env_path)

    # Resolve AI provider (CLI flag > env var > default)
    provider = ai_provider if ai_provider != "none" else os.getenv("SCOUT_AI_PROVIDER", "none")

    table = _read_tool_scout(project_path) if project_path is not None else {}
    unknown = sorted(set(table) - _KNOWN_KEYS)
    if unknown:
        print(
            f"scout: warning: ignoring unknown [tool.scout] key(s): {', '.join(unknown)}",
            file=sys.stderr,
        )

    exclude: tuple[str, ...] = ()
    if "exclude" in table:
        exclude = _string_tuple(table["exclude"], "exclude")
    if cli_exclude is not None:
        exclude = tuple(cli_exclude)

    scanners: tuple[str, ...] | None = None
    if "scanners" in table:
        scanners = _string_tuple(table["scanners"], "scanners")
        if not scanners:
            raise ValueError("[tool.scout] scanners must name at least one scanner")

    fail_on = "high"
    if "fail_on" in table:
        value = table["fail_on"]
        if not isinstance(value, str) or value.lower() not in FAIL_ON_CHOICES:
            raise ValueError(f"[tool.scout] fail_on must be one of: {', '.join(FAIL_ON_CHOICES)}")
        fail_on = value.lower()
    if cli_fail_on is not None:
        fail_on = cli_fail_on.lower()

    return ScoutConfig(
        ai_provider=provider,
        anthropic_key=os.getenv("ANTHROPIC_API_KEY"),
        openai_key=os.getenv("OPENAI_API_KEY"),
        ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        ollama_model=os.getenv("OLLAMA_MODEL", ollama_model),
        exclude=exclude,
        scanners=scanners,
        fail_on=fail_on,
        ai_model=os.getenv("SCOUT_AI_MODEL"),
    )
