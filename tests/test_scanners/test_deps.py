"""Tests for the deps scanner — OSV-backed pip + npm paths, fully mocked (no network)."""

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


# --- npm lockfile path --------------------------------------------------------

NPM_GHSA_ID = "GHSA-npm-0001"

LOCK_V3 = json.dumps(
    {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash"},
            "node_modules/safe-pkg": {"version": "1.0.0"},
            "node_modules/git-dep": {"version": "git+https://example.com/repo.git"},
            "node_modules/workspace-pkg": {"link": True, "resolved": "packages/workspace-pkg"},
        },
    },
    indent=2,
)

LOCK_V1 = json.dumps(
    {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "safe-pkg": {"version": "1.0.0", "requires": {"minimist": "^0.0.8"}},
            "nested-parent": {
                "version": "2.0.0",
                "dependencies": {"minimist": {"version": "0.0.8"}},
            },
        },
    },
    indent=2,
)


def npm_handler(vulnerable: str):
    """Canned OSV backend: `vulnerable` has NPM_GHSA_ID, all else is clean."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/querybatch"):
            queries = json.loads(request.content)["queries"]
            results = [
                {"vulns": [{"id": NPM_GHSA_ID, "modified": "2026-01-01T00:00:00Z"}]}
                if query["package"]["name"] == vulnerable
                else {}
                for query in queries
            ]
            return httpx.Response(200, json={"results": results})
        if url.endswith(f"/vulns/{NPM_GHSA_ID}"):
            return httpx.Response(
                200,
                json={
                    "id": NPM_GHSA_ID,
                    "summary": f"Prototype pollution in {vulnerable}",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": vulnerable},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
                        }
                    ],
                },
            )
        return httpx.Response(200, json={"vulns": []})  # pip /query calls

    return handler


def npm_project(tmp_path: Path, lock_text: str, lock_name: str = "package-lock.json") -> list[Path]:
    (tmp_path / "package.json").write_text('{"name": "demo", "version": "1.0.0"}\n', encoding="utf-8")
    (tmp_path / lock_name).write_text(lock_text, encoding="utf-8")
    app = tmp_path / "index.js"
    app.write_text("console.log('hi')\n", encoding="utf-8")
    return [app]


def test_v3_lockfile_vulnerable_package_has_real_line_number(tmp_path):
    files = npm_project(tmp_path, LOCK_V3)
    findings = make_scanner(npm_handler("lodash")).scan(files)

    assert len(findings) == 1
    finding = findings[0]
    expected_line = next(
        index for index, line in enumerate(LOCK_V3.splitlines(), start=1) if '"node_modules/lodash":' in line
    )
    assert finding.line == expected_line
    assert finding.line > 1  # a real anchor, not a synthetic one
    assert finding.file.endswith("package-lock.json")
    assert "lodash@4.17.20" in finding.title
    assert NPM_GHSA_ID in finding.title
    assert finding.severity == "HIGH"
    assert "9.9.9" in finding.fix_summary
    assert "node_modules/lodash" in finding.snippet


def test_v3_lockfile_skips_root_git_and_link_entries(tmp_path):
    queried: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/querybatch"):
            queries = json.loads(request.content)["queries"]
            queried.extend(query["package"]["name"] for query in queries)
            return httpx.Response(200, json={"results": [{} for _ in queries]})
        return httpx.Response(200, json={"vulns": []})

    make_scanner(handler).scan(npm_project(tmp_path, LOCK_V3))
    assert sorted(queried) == ["lodash", "safe-pkg"]  # no root, git dep, or workspace link


def test_v1_lockfile_finds_nested_dependency(tmp_path):
    files = npm_project(tmp_path, LOCK_V1)
    findings = make_scanner(npm_handler("minimist")).scan(files)

    assert len(findings) == 1
    assert "minimist@0.0.8" in findings[0].title
    assert findings[0].line > 1


def test_npm_shrinkwrap_is_scanned_too(tmp_path):
    files = npm_project(tmp_path, LOCK_V3, lock_name="npm-shrinkwrap.json")
    findings = make_scanner(npm_handler("lodash")).scan(files)
    assert len(findings) == 1
    assert findings[0].file.endswith("npm-shrinkwrap.json")


def test_package_json_without_lockfile_warns(tmp_path, capsys):
    (tmp_path / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
    app = tmp_path / "index.js"
    app.write_text("console.log('hi')\n", encoding="utf-8")

    assert make_scanner(npm_handler("lodash")).scan([app]) == []
    assert "lockfile" in capsys.readouterr().err


def test_batch_query_failure_warns_not_raises(tmp_path, capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down")

    assert make_scanner(handler).scan(npm_project(tmp_path, LOCK_V3)) == []
    assert "batch query failed" in capsys.readouterr().err


def test_detail_fetch_failure_still_reports_the_finding(tmp_path, capsys):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/querybatch"):
            queries = json.loads(request.content)["queries"]
            results = [
                {"vulns": [{"id": NPM_GHSA_ID}]} if query["package"]["name"] == "lodash" else {} for query in queries
            ]
            return httpx.Response(200, json={"results": results})
        return httpx.Response(500)

    findings = make_scanner(handler).scan(npm_project(tmp_path, LOCK_V3))
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"  # default when details are unavailable
    assert "details unavailable" in findings[0].description
    assert "HTTP 500" in capsys.readouterr().err


def test_malformed_lockfile_warns(tmp_path, capsys):
    assert make_scanner(npm_handler("lodash")).scan(npm_project(tmp_path, "not json")) == []
    assert "not valid JSON" in capsys.readouterr().err


def test_no_subprocess_remains_in_deps_scanner():
    # T1.12's acceptance: the npm binary path is gone — lockfiles are parsed
    # directly, so `subprocess` must not appear anywhere in the scanner.
    import scout.scanners.deps as deps_module

    source = Path(deps_module.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
