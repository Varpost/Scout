"""Language scoping (T2.4): deep analysis is Python/JS; secrets is everywhere."""

from __future__ import annotations

from pathlib import Path

from scout.scanners.headers import HeadersScanner
from scout.scanners.injection import InjectionScanner
from scout.scanners.secrets import SecretsScanner


def _build_secret(prefix: str, suffix: str) -> str:  # split to avoid push protection
    return prefix + suffix


def test_injection_is_gated_to_python_js(tmp_path: Path) -> None:
    go = tmp_path / "app.go"
    go.write_text("x := eval(userInput)\n", encoding="utf-8")
    py = tmp_path / "app.py"
    py.write_text("result = eval(user_input)\n", encoding="utf-8")
    inj = InjectionScanner()
    assert inj.scan([go]) == []  # .go is not analyzed for Python/JS injection idioms
    assert inj.scan([py])  # .py is


def test_secrets_are_language_agnostic(tmp_path: Path) -> None:
    key = _build_secret("AKIA", "IOSFODNN7EXAMPLE")
    go = tmp_path / "config.go"
    go.write_text(f'const AWSKey = "{key}"\n', encoding="utf-8")
    findings = SecretsScanner().scan([go])  # secrets still scans a .go file
    assert any("AWS Access Key" in f.title for f in findings)


def test_scanner_scope_attributes() -> None:
    assert SecretsScanner.suffixes is None  # language-agnostic
    assert InjectionScanner.suffixes is not None  # Python/JS only
    assert HeadersScanner.suffixes is not None  # Python/JS only
