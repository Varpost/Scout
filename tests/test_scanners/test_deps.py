"""Tests for the deps scanner — OSV-backed Python path, fully mocked (no network)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from scout.scanners.deps import DepsScanner

GHSA_ID = "GHSA-test-0001"


def osv_response(request: httpx.Request) -> httpx.Response:
    # Canned OSV verdict: examplepkg is vulnerable, everything else is clean.
    query = json.loads(request.content)
    if query["package"]["name"] == "examplepkg":
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": GHSA_ID,
                        "summary": "Remote code execution in examplepkg",
                        "database_specific": {"severity": "CRITICAL"},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "examplepkg"},
                                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}],
                            }
                        ],
                    }
                ]
            },
        )
    return httpx.Response(200, json={"vulns": []})


def make_scanner(handler) -> DepsScanner:
    return DepsScanner(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def project(tmp_path: Path, requirements: str) -> list[Path]:
    # A minimal scanned project: the scanner receives source files and
    # discovers requirements.txt in their parent directory.
    (tmp_path / "requirements.txt").write_text(requirements, encoding="utf-8")
    app = tmp_path / "app.py"
    app.write_text("print('hi')\n", encoding="utf-8")
    return [app]


def test_vulnerable_pin_produces_finding_with_real_line_number(tmp_path):
    files = project(tmp_path, "# deps\nexamplepkg==2.0.0\n")
    findings = make_scanner(osv_response).scan(files)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "CRITICAL"
    assert finding.line == 2  # the pinned requirement's actual line
    assert finding.file.endswith("requirements.txt")
    assert GHSA_ID in finding.title
    assert "2.0.1" in finding.fix_summary
    assert finding.snippet == "examplepkg==2.0.0"


def test_two_vulnerable_packages_survive_scan_dedupe_key(tmp_path):
    # Both pins must yield findings with distinct (file, line, scanner) keys,
    # so run_scout's dedupe cannot silently drop one (line=0 regression guard).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [{"id": "OSV-1", "summary": "bad"}]})

    files = project(tmp_path, "examplepkg==2.0.0\n\notherpkg==1.0.0\n")
    findings = make_scanner(handler).scan(files)
    assert len(findings) == 2
    assert sorted(finding.line for finding in findings) == [1, 3]
    dedupe_keys = {(finding.file, finding.line, finding.scanner) for finding in findings}
    assert len(dedupe_keys) == 2


def test_clean_project_yields_no_findings(tmp_path):
    files = project(tmp_path, "cleanpkg==1.2.3\n")
    assert make_scanner(osv_response).scan(files) == []


def test_unpinned_comment_and_option_lines_are_skipped(tmp_path):
    queried: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        queried.append(json.loads(request.content)["package"]["name"])
        return httpx.Response(200, json={"vulns": []})

    files = project(tmp_path, "# comment\nflask>=2.0\n-r other.txt\n-e .\nexamplepkg==2.0.0  # pinned\n")
    make_scanner(handler).scan(files)
    assert queried == ["examplepkg"]


def test_missing_severity_label_defaults_to_high(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [{"id": "OSV-2", "summary": "no label"}]})

    files = project(tmp_path, "examplepkg==2.0.0\n")
    assert make_scanner(handler).scan(files)[0].severity == "HIGH"


def test_http_error_warns_instead_of_silently_passing(tmp_path, capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down")

    files = project(tmp_path, "examplepkg==2.0.0\n")
    assert make_scanner(handler).scan(files) == []
    assert "deps scanner" in capsys.readouterr().err


def test_non_200_response_warns(tmp_path, capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    files = project(tmp_path, "examplepkg==2.0.0\n")
    assert make_scanner(handler).scan(files) == []
    assert "HTTP 500" in capsys.readouterr().err


def test_invalid_json_warns(tmp_path, capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    files = project(tmp_path, "examplepkg==2.0.0\n")
    assert make_scanner(handler).scan(files) == []
    assert "invalid JSON" in capsys.readouterr().err


def test_project_without_requirements_makes_no_queries(tmp_path):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"vulns": []})

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    app = tmp_path / "app.py"
    app.write_text("print('hi')\n", encoding="utf-8")
    assert make_scanner(handler).scan([app]) == []
    assert calls == []
