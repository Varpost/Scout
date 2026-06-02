"""Unified AI client — supports Anthropic, OpenAI, and Ollama."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from scout.config import ScoutConfig


@dataclass
class AIResponse:
    """Parsed response from an AI call."""

    raw: str
    parsed: dict[str, Any] | None = None
    error: str | None = None


class AIClient:
    """Unified interface for Anthropic, OpenAI, and Ollama APIs.

    Sends only snippets, never full files. Each call is under 2000 tokens.
    """

    def __init__(self, config: ScoutConfig) -> None:
        self.config = config

    def confirm_finding(
        self,
        file: str,
        lines: str,
        issue_type: str,
        code: str,
    ) -> AIResponse:
        """Ask AI to confirm/rate a potential vulnerability.

        Args:
            file: Filename (for context).
            lines: Line range (e.g., "23-45").
            issue_type: Category (e.g., "missing_auth", "sql_injection").
            code: The code snippet (ONLY the flagged lines, never full files).

        Returns:
            AIResponse with severity rating and explanation.
        """
        system = (
            "You are a security code reviewer. Analyze this snippet only. "
            "Respond in JSON only. No preamble. "
            'Format: {"severity": "HIGH", "confirmed": true, '
            '"explanation": "...", "fix_summary": "..."}'
        )
        user_msg = json.dumps(
            {
                "file": file,
                "lines": lines,
                "issue_type": issue_type,
                "code": code,
            }
        )

        return self._call(system, user_msg)

    def generate_fix(
        self,
        file: str,
        lines: str,
        original_code: str,
        fix_summary: str,
        phase: int,
        context_above: str = "",
        context_below: str = "",
    ) -> AIResponse:
        """Ask AI to write a code fix.

        Args:
            file: Filename.
            lines: Line range to fix.
            original_code: The vulnerable code.
            fix_summary: What needs to change.
            phase: Current fix phase (1-5).
            context_above: 5 lines before the snippet.
            context_below: 5 lines after the snippet.

        Returns:
            AIResponse with the replacement code.
        """
        system = (
            "You are a security engineer writing minimal safe code fixes. "
            "Return only the modified code for the exact lines specified. "
            "No explanation. No markdown. Just the replacement code."
        )
        user_msg = json.dumps(
            {
                "file": file,
                "lines": lines,
                "original_code": original_code,
                "fix_summary": fix_summary,
                "phase": phase,
                "context_above": context_above,
                "context_below": context_below,
            }
        )

        return self._call(system, user_msg)

    def _call(self, system: str, user_msg: str) -> AIResponse:
        """Route to the configured AI provider."""
        provider = self.config.ai_provider

        if provider == "anthropic":
            return self._call_anthropic(system, user_msg)
        elif provider == "openai":
            return self._call_openai(system, user_msg)
        elif provider == "ollama":
            return self._call_ollama(system, user_msg)
        else:
            return AIResponse(raw="", error="No AI provider configured")

    def _call_anthropic(self, system: str, user_msg: str) -> AIResponse:
        """Call Anthropic Claude API."""
        try:
            import anthropic
        except ImportError:
            return AIResponse(raw="", error="anthropic package not installed. Run: pip install scout-security[ai]")

        if not self.config.anthropic_key:
            return AIResponse(raw="", error="ANTHROPIC_API_KEY not set")

        try:
            client = anthropic.Anthropic(api_key=self.config.anthropic_key)
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=500,
                system=system,
                messages=[{"role": "user", "content": user_msg}],
            )
            raw = response.content[0].text
            return AIResponse(raw=raw, parsed=self._try_parse_json(raw))
        except Exception as e:
            return AIResponse(raw="", error=str(e))

    def _call_openai(self, system: str, user_msg: str) -> AIResponse:
        """Call OpenAI API."""
        try:
            import openai
        except ImportError:
            return AIResponse(raw="", error="openai package not installed. Run: pip install scout-security[ai]")

        if not self.config.openai_key:
            return AIResponse(raw="", error="OPENAI_API_KEY not set")

        try:
            client = openai.OpenAI(api_key=self.config.openai_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                max_tokens=500,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
            )
            raw = response.choices[0].message.content or ""
            return AIResponse(raw=raw, parsed=self._try_parse_json(raw))
        except Exception as e:
            return AIResponse(raw="", error=str(e))

    def _call_ollama(self, system: str, user_msg: str) -> AIResponse:
        """Call local Ollama API."""
        url = f"{self.config.ollama_host}/api/chat"
        payload = {
            "model": self.config.ollama_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            "stream": False,
        }

        try:
            resp = httpx.post(url, json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            raw = data.get("message", {}).get("content", "")
            return AIResponse(raw=raw, parsed=self._try_parse_json(raw))
        except httpx.ConnectError:
            return AIResponse(raw="", error=f"Cannot connect to Ollama at {self.config.ollama_host}. Is it running?")
        except Exception as e:
            return AIResponse(raw="", error=str(e))

    def _try_parse_json(self, text: str) -> dict[str, Any] | None:
        """Attempt to parse JSON from AI response."""
        try:
            result = json.loads(text)
            return result if isinstance(result, dict) else None
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            if "```" in text:
                start = text.find("{")
                end = text.rfind("}") + 1
                if start >= 0 and end > start:
                    try:
                        result = json.loads(text[start:end])
                        return result if isinstance(result, dict) else None
                    except json.JSONDecodeError:
                        pass
            return None
