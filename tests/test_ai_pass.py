"""AI confirmation pass wiring (T2.1) — mocked providers, no network."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from scout.agents.scout_agent import _ai_reviewable, _run_ai_pass, run_scout
from scout.ai.client import AIClient, AIResponse
from scout.config import ScoutConfig
from scout.models import Finding


def _cfg(provider: str = "anthropic", anthropic_key: str | None = "k", **kw: object) -> ScoutConfig:
    return ScoutConfig(
        ai_provider=provider,
        anthropic_key=anthropic_key,
        openai_key=None,
        ollama_host="http://localhost:11434",
        ollama_model="llama3",
        **kw,  # type: ignore[arg-type]
    )


def _finding(
    severity: str = "CRITICAL",
    scanner: str = "injection",
    snippet: str = "eval(x)",
    line: int = 5,
    project_level: bool = False,
) -> Finding:
    return Finding(
        file="app.py",
        line=line,
        severity=severity,
        title="Eval usage",
        description="d",
        scanner=scanner,
        snippet=snippet,
        project_level=project_level,
    )


def _stub_verdict(monkeypatch: pytest.MonkeyPatch, response: AIResponse) -> None:
    monkeypatch.setattr(AIClient, "confirm_finding", lambda self, **kw: response)


def test_ai_dismisses_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_verdict(monkeypatch, AIResponse(raw="", parsed={"confirmed": False}))
    assert _run_ai_pass([_finding()], _cfg(), quiet=True) == []


def test_ai_downgrades_severity(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_verdict(monkeypatch, AIResponse(raw="", parsed={"confirmed": True, "severity": "LOW"}))
    out = _run_ai_pass([_finding(severity="CRITICAL")], _cfg(), quiet=True)
    assert len(out) == 1
    assert out[0].severity == "LOW"
    assert out[0].ai_confirmed is True


def test_ai_cannot_escalate_severity(monkeypatch: pytest.MonkeyPatch) -> None:
    # AI may lower severity but never raise it — a hallucinated escalation is ignored.
    _stub_verdict(monkeypatch, AIResponse(raw="", parsed={"confirmed": True, "severity": "CRITICAL"}))
    out = _run_ai_pass([_finding(severity="LOW")], _cfg(), quiet=True)
    assert out[0].severity == "LOW"


def test_provider_error_keeps_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_verdict(monkeypatch, AIResponse(raw="", error="boom"))
    f = _finding()
    out = _run_ai_pass([f], _cfg(), quiet=True)
    assert out == [f]
    assert out[0].ai_confirmed is None


def test_unparseable_response_keeps_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_verdict(monkeypatch, AIResponse(raw="not json", parsed=None))
    assert len(_run_ai_pass([_finding()], _cfg(), quiet=True)) == 1


def test_deterministic_findings_bypass_ai(monkeypatch: pytest.MonkeyPatch) -> None:
    # The fake would dismiss everything; deps (OSV) and project-level must survive untouched.
    _stub_verdict(monkeypatch, AIResponse(raw="", parsed={"confirmed": False}))
    deps = _finding(scanner="deps", snippet="lodash==4.17.20", line=8)
    csrf = _finding(scanner="headers", project_level=True, snippet="app", line=1)
    out = _run_ai_pass([deps, csrf], _cfg(), quiet=True)
    assert out == [deps, csrf]
    assert all(f.ai_confirmed is None for f in out)


def test_snippetless_finding_bypasses_ai(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_verdict(monkeypatch, AIResponse(raw="", parsed={"confirmed": False}))
    f = _finding(snippet="")
    assert _run_ai_pass([f], _cfg(), quiet=True) == [f]


def test_ai_reviewable_predicate() -> None:
    assert _ai_reviewable(_finding())
    assert not _ai_reviewable(_finding(scanner="deps"))
    assert not _ai_reviewable(_finding(project_level=True))
    assert not _ai_reviewable(_finding(snippet=""))


def test_no_ai_never_calls_provider(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # provider=none → ai_enabled is False → the pass is skipped entirely (deterministic default).
    calls = {"n": 0}

    def _boom(self: AIClient, **kw: object) -> AIResponse:
        calls["n"] += 1
        return AIResponse(raw="", parsed={"confirmed": False})

    monkeypatch.setattr(AIClient, "confirm_finding", _boom)
    (tmp_path / "leak.py").write_text('AWS_SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"\n')
    run_scout(tmp_path, _cfg(provider="none", anthropic_key=None), quiet=True)
    assert calls["n"] == 0


def test_anthropic_model_default_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock the anthropic SDK module so no network call happens.
    recorded: dict[str, object] = {}

    class _Messages:
        def create(self, **kw: object) -> object:
            recorded.update(kw)
            block = types.SimpleNamespace(text='{"confirmed": true, "severity": "LOW"}')
            return types.SimpleNamespace(content=[block])

    class _Anthropic:
        def __init__(self, api_key: str | None) -> None:
            self.messages = _Messages()

    fake = types.ModuleType("anthropic")
    fake.Anthropic = _Anthropic  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    resp = AIClient(_cfg()).confirm_finding(file="a.py", lines="1", issue_type="x", code="c")
    assert recorded["model"] == "claude-haiku-4-5"
    assert resp.parsed == {"confirmed": True, "severity": "LOW"}

    recorded.clear()
    AIClient(_cfg(ai_model="claude-opus-4-8")).confirm_finding(file="a.py", lines="1", issue_type="x", code="c")
    assert recorded["model"] == "claude-opus-4-8"
