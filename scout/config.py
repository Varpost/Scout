"""Configuration loading for Scout."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class ScoutConfig:
    """Runtime configuration for Scout."""

    ai_provider: str  # "anthropic" | "openai" | "ollama" | "none"
    anthropic_key: str | None
    openai_key: str | None
    ollama_host: str
    ollama_model: str

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


def load_config(
    ai_provider: str = "none",
    ollama_model: str = "llama3",
) -> ScoutConfig:
    """Load configuration from environment and .env file.

    Args:
        ai_provider: Override AI provider selection.
        ollama_model: Override Ollama model name.

    Returns:
        ScoutConfig with all resolved values.
    """
    # Load .env from current directory if present
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        load_dotenv(env_path)

    # Resolve AI provider (CLI flag > env var > default)
    provider = ai_provider if ai_provider != "none" else os.getenv("SCOUT_AI_PROVIDER", "none")

    return ScoutConfig(
        ai_provider=provider,
        anthropic_key=os.getenv("ANTHROPIC_API_KEY"),
        openai_key=os.getenv("OPENAI_API_KEY"),
        ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        ollama_model=os.getenv("OLLAMA_MODEL", ollama_model),
    )
