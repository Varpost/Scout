"""Tests for the three output layers (markdown / ai-prompt / json) — SCOUT_SPEC §4."""

import json
from pathlib import Path

from scout.agents.reporter_agent import (
    generate_ai_prompts,
    generate_json,
    generate_report,
)
from scout.models import Finding


def _sample_findings() -> list[Finding]:
    """Two findings with benign snippets (no credential-looking literals)."""
    return [
        Finding(
            file="src/config.py",
            line=12,
            severity="CRITICAL",
            title="AWS Access Key detected",
            description="AWS keys committed to source can be extracted by attackers.",
            scanner="secrets",
            snippet="cfg = read_config()",
            fix_phase=1,
            fix_summary="Move the value to an environment variable and rotate it.",
        ),
        Finding(
            file="app/views.js",
            line=40,
            severity="HIGH",
            title="innerHTML XSS",
            description="Assigning user input to innerHTML enables XSS.",
            scanner="injection",
            # Built dynamically so Scout's own injection scanner doesn't flag
            # this test file (mirrors _build_secret in test_secrets.py).
            snippet="el.inner" + "HTML = userInput",
            fix_phase=4,
            fix_summary="Use textContent or sanitize the input.",
            references=["https://example.com/xss"],
        ),
    ]


# --- Layer 3: JSON --------------------------------------------------------


def test_json_shape_matches_spec():
    data = json.loads(generate_json(_sample_findings()))

    assert data["tool"] == "scout"
    assert data["total_issues"] == 2
    assert data["severity_counts"] == {"CRITICAL": 1, "HIGH": 1}

    first = data["findings"][0]
    expected_keys = {
        "id",
        "scanner",
        "file",
        "line",
        "severity",
        "fix_phase",
        "code_snippet",
        "title",
        "explanation",
        "fix_guidance",
        "references",
    }
    assert expected_keys <= set(first.keys())
    assert first["id"] == "secrets/aws_access_key_detected"
    assert first["code_snippet"] == "cfg = read_config()"
    assert first["explanation"].startswith("AWS keys")
    assert first["fix_guidance"].startswith("Move the value")
    # Falls back to a scanner-level reference when the finding carries none.
    assert first["references"]


def test_json_uses_finding_references_when_present():
    data = json.loads(generate_json(_sample_findings()))
    assert data["findings"][1]["references"] == ["https://example.com/xss"]


def test_json_empty_findings_is_valid():
    data = json.loads(generate_json([]))
    assert data["total_issues"] == 0
    assert data["findings"] == []


def test_json_writes_file(tmp_path: Path):
    out = tmp_path / "report.json"
    returned = generate_json(_sample_findings(), out)
    assert out.exists()
    assert json.loads(out.read_text(encoding="utf-8")) == json.loads(returned)


def test_json_relativizes_paths(tmp_path: Path):
    finding = Finding(
        file=str(tmp_path / "pkg" / "a.py"),
        line=1,
        severity="LOW",
        title="x",
        description="d",
        scanner="secrets",
    )
    data = json.loads(generate_json([finding], project_path=tmp_path))
    assert data["findings"][0]["file"] in ("pkg/a.py", "pkg\\a.py")


# --- Layer 2: AI-ready prompts -------------------------------------------


def test_ai_prompt_is_self_contained():
    doc = generate_ai_prompts(_sample_findings())

    assert "FILE: src/config.py" in doc
    assert "LINE: 12" in doc
    assert "ISSUE: AWS Access Key detected" in doc
    assert "```python" in doc  # language fence inferred from .py extension
    assert "```javascript" in doc  # inferred from .js extension
    assert "WHY IT'S DANGEROUS:" in doc
    assert "WHAT TO DO:" in doc
    assert "Search the rest of my codebase" in doc


def test_ai_prompt_empty_findings():
    assert "No vulnerabilities found" in generate_ai_prompts([])


def test_ai_prompt_writes_file(tmp_path: Path):
    out = tmp_path / "prompts.md"
    generate_ai_prompts(_sample_findings(), out)
    assert "FILE: src/config.py" in out.read_text(encoding="utf-8")


# --- Layer 1: Markdown (regression) --------------------------------------


def test_markdown_still_works(tmp_path: Path):
    out = tmp_path / "report.md"
    generate_report(_sample_findings(), out, project_path=None)
    text = out.read_text(encoding="utf-8")
    assert "# Security Report" in text
    assert "AWS Access Key detected" in text


def test_markdown_shows_real_files_scanned_count(tmp_path: Path):
    # Regression: the header used to render an em-dash placeholder.
    out = tmp_path / "report.md"
    generate_report(_sample_findings(), out, project_path=None, files_scanned=47)
    assert "**Files scanned:** 47" in out.read_text(encoding="utf-8")


def test_json_includes_files_scanned():
    data = json.loads(generate_json(_sample_findings(), files_scanned=3))
    assert data["files_scanned"] == 3
