"""Dependency scanner — checks for known vulnerable packages."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx

from scout.models import Finding
from scout.scanners import register_scanner
from scout.scanners.base import BaseScanner

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 10.0

# Only exact pins (`name==version`) can be checked against a vulnerability
# database. Extras and trailing markers/comments are tolerated; unpinned,
# editable, and option lines are skipped.
PINNED_REQUIREMENT = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*(?P<version>[^\s;#]+)")

# OSV `severity` entries are CVSS vector strings, not labels; the GHSA-style
# label in `database_specific.severity` is the practical source. Unknown or
# missing labels default to HIGH — the severity this scanner advertises.
OSV_SEVERITY_LABELS = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def _normalize_name(name: str) -> str:
    """Apply PEP 503 package-name normalization, as used by OSV's PyPI ecosystem."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _first_fixed_version(vuln: Any, normalized_name: str) -> str:
    """Return the first fixed version OSV reports for this package, or ''."""
    for affected in vuln.get("affected") or []:
        package = affected.get("package", {})
        if package.get("ecosystem") != "PyPI":
            continue
        if _normalize_name(str(package.get("name", ""))) != normalized_name:
            continue
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


@register_scanner
class DepsScanner(BaseScanner):
    """Detects vulnerable dependencies.

    The Python path parses the project's `requirements.txt` and queries the
    OSV.dev API per exact pin — auditing the scanned project rather than
    whatever happens to be installed in the current environment. The Node
    path still shells out to `npm audit` (lockfile parsing replaces it in a
    later task).
    """

    name = "deps"
    description = "Finds known CVEs in project dependencies"

    def __init__(self, http_client: httpx.Client | None = None) -> None:
        """Initialize the scanner.

        Args:
            http_client: Optional pre-configured HTTP client. Tests inject an
                `httpx.MockTransport`-backed client; when omitted, a real one
                is created (and closed) per scan.
        """
        self._http_client = http_client

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Not used — deps scanner works at project level."""
        return []

    def scan(self, files: list[Path]) -> list[Finding]:
        """Scan for vulnerable dependencies at project level."""
        if not files:
            return []

        # Determine project root from first file
        project_root = files[0].parent
        while project_root != project_root.parent:
            if any(
                (project_root / f).exists() for f in ["requirements.txt", "pyproject.toml", "package.json", "Pipfile"]
            ):
                break
            project_root = project_root.parent

        findings: list[Finding] = []
        findings.extend(self._scan_python(project_root))
        findings.extend(self._scan_node(project_root))
        return findings

    def _warn(self, message: str) -> None:
        """Emit a visible warning — dependency-scan failures must never be silent."""
        print(f"scout: deps scanner: {message}", file=sys.stderr)

    def _scan_python(self, project_root: Path) -> list[Finding]:
        """Check pinned requirements.txt entries against the OSV.dev database."""
        req_path = project_root / "requirements.txt"
        if not req_path.exists():
            return []

        try:
            content = req_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            self._warn(f"cannot read {req_path}: {exc}")
            return []

        pins = self._parse_requirements(content)
        if not pins:
            return []

        findings: list[Finding] = []
        owns_client = self._http_client is None
        client = self._http_client or httpx.Client(timeout=OSV_TIMEOUT_SECONDS)
        try:
            for name, version, line_no, raw_line in pins:
                findings.extend(self._query_osv(client, req_path, name, version, line_no, raw_line))
        finally:
            if owns_client:
                client.close()
        return findings

    def _parse_requirements(self, content: str) -> list[tuple[str, str, int, str]]:
        """Extract exact pins as (name, version, line number, raw line) tuples."""
        pins: list[tuple[str, str, int, str]] = []
        for line_no, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith(("#", "-")):
                continue
            match = PINNED_REQUIREMENT.match(line)
            if match:
                pins.append((match.group("name"), match.group("version"), line_no, line))
        return pins

    def _query_osv(
        self,
        client: httpx.Client,
        req_path: Path,
        name: str,
        version: str,
        line_no: int,
        raw_line: str,
    ) -> list[Finding]:
        """Query OSV.dev for one pinned package; failures warn, never raise."""
        query = {"package": {"name": _normalize_name(name), "ecosystem": "PyPI"}, "version": version}
        try:
            response = client.post(OSV_QUERY_URL, json=query)
        except httpx.HTTPError as exc:
            self._warn(f"OSV query failed for {name}=={version}: {exc}")
            return []

        if response.status_code != 200:
            self._warn(f"OSV returned HTTP {response.status_code} for {name}=={version}")
            return []

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            self._warn(f"OSV returned invalid JSON for {name}=={version}: {exc}")
            return []

        findings: list[Finding] = []
        for vuln in payload.get("vulns") or []:
            vuln_id = str(vuln.get("id", "unknown"))
            text = str(vuln.get("summary") or vuln.get("details") or "Known vulnerability.").strip()
            summary = text.splitlines()[0] if text else "Known vulnerability."
            fixed = _first_fixed_version(vuln, _normalize_name(name))
            fix_summary = f"Upgrade {name} to >={fixed}" if fixed else f"Upgrade {name} to a patched release"
            findings.append(
                Finding(
                    file=str(req_path),
                    line=line_no,
                    severity=OSV_SEVERITY_LABELS.get(
                        str(vuln.get("database_specific", {}).get("severity", "")).upper(), "HIGH"
                    ),
                    title=f"Vulnerable package: {name}=={version} ({vuln_id})",
                    description=f"{summary} (source: OSV.dev)",
                    scanner=self.name,
                    snippet=raw_line,
                    fix_phase=1,
                    fix_summary=fix_summary,
                    references=[f"https://osv.dev/vulnerability/{vuln_id}"],
                )
            )
        return findings

    def _scan_node(self, project_root: Path) -> list[Finding]:
        """Run npm audit if package.json exists."""
        if not (project_root / "package.json").exists():
            return []

        try:
            # S607: 'npm' is a well-known CLI tool; absolute paths vary per
            # install. Args are list-form, not shell.
            result = subprocess.run(  # noqa: S603, S607
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(project_root),
            )
        except FileNotFoundError:
            self._warn("npm not found on PATH; skipping Node dependency audit")
            return []
        except subprocess.TimeoutExpired:
            self._warn("npm audit timed out; skipping Node dependency audit")
            return []

        findings: list[Finding] = []
        try:
            data = json.loads(result.stdout)
            vulns = data.get("vulnerabilities", {})
            for pkg_name, info in vulns.items():
                severity = info.get("severity", "moderate").upper()
                if severity == "MODERATE":
                    severity = "MEDIUM"
                via = info.get("via", [])
                if via and isinstance(via[0], dict):
                    desc = via[0].get("title", "Known vulnerability")
                else:
                    desc = f"Vulnerable dependency: {pkg_name}"
                fix_cmd = info.get("fixAvailable", "npm audit fix")

                findings.append(
                    Finding(
                        file=str(project_root / "package.json"),
                        line=0,
                        severity=severity,
                        title=f"Vulnerable package: {pkg_name}",
                        description=desc,
                        scanner=self.name,
                        snippet=f'"{pkg_name}": ...',
                        fix_phase=1,
                        fix_summary=(f"Run `npm audit fix` or manually update {pkg_name}. Fix: {fix_cmd}"),
                    )
                )
        except (json.JSONDecodeError, KeyError) as exc:
            self._warn(f"npm audit output could not be parsed: {exc}")

        return findings
