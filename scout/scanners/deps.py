"""Dependency scanner — checks for known vulnerable packages."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import httpx

from scout.models import Finding
from scout.scanners import register_scanner
from scout.scanners.base import BaseScanner

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_TIMEOUT_SECONDS = 10.0
# OSV accepts up to 1000 queries per batch call; one round trip covers a
# typical lockfile instead of one request per package.
OSV_BATCH_SIZE = 500

# Lockfile "version" values that aren't concrete registry versions (git URLs,
# npm aliases, workspace links) can't be queried against OSV.
_CONCRETE_VERSION = re.compile(r"^\d+\.\d+\.\d+")

# (name, version, line number, raw line) — shared by both ecosystems.
_DepEntry = tuple[str, str, int, str]

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


def _first_fixed_version(vuln: Any, name: str, ecosystem: str) -> str:
    """Return the first fixed version OSV reports for this package, or ''."""

    def canonical(value: str) -> str:
        # npm names are exact; PyPI names compare after PEP 503 normalization.
        return _normalize_name(value) if ecosystem == "PyPI" else value

    target = canonical(name)
    for affected in vuln.get("affected") or []:
        package = affected.get("package", {})
        if package.get("ecosystem") != ecosystem:
            continue
        if canonical(str(package.get("name", ""))) != target:
            continue
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def _find_entry_line(lines: list[str], anchor: str) -> tuple[int, str]:
    """Locate the first 1-based line containing the anchor text."""
    for index, line in enumerate(lines, start=1):
        if anchor in line:
            return index, line.strip()
    return 1, anchor


@register_scanner
class DepsScanner(BaseScanner):
    """Detects vulnerable dependencies via the OSV.dev database.

    The Python path parses `requirements.txt` exact pins; the Node path
    parses `package-lock.json` / `npm-shrinkwrap.json` directly (lockfile
    v1's nested `dependencies` and v2/v3's flat `packages` map). Both audit
    the scanned project itself — no environment introspection and no
    shelling out to package managers.
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
            fixed = _first_fixed_version(vuln, name, "PyPI")
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
        """Check npm lockfile entries against the OSV.dev database."""
        candidates = ("package-lock.json", "npm-shrinkwrap.json")
        lock_path = next((project_root / name for name in candidates if (project_root / name).exists()), None)
        if lock_path is None:
            if (project_root / "package.json").exists():
                self._warn(
                    "package.json without a lockfile; npm dependencies not scanned "
                    "(generate one with `npm install --package-lock-only`)"
                )
            return []

        try:
            content = lock_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            self._warn(f"cannot read {lock_path}: {exc}")
            return []

        entries = self._parse_lockfile(content)
        if not entries:
            return []

        findings: list[Finding] = []
        owns_client = self._http_client is None
        client = self._http_client or httpx.Client(timeout=OSV_TIMEOUT_SECONDS)
        try:
            vuln_ids_per_entry = self._query_osv_batch(client, entries)
            vuln_cache: dict[str, Any] = {}
            for entry, vuln_ids in zip(entries, vuln_ids_per_entry, strict=True):
                for vuln_id in vuln_ids:
                    findings.append(self._npm_finding(client, lock_path, entry, vuln_id, vuln_cache))
        finally:
            if owns_client:
                client.close()
        return findings

    def _parse_lockfile(self, content: str) -> list[_DepEntry]:
        """Extract (name, version, line, raw line) entries from an npm lockfile.

        Handles lockfileVersion 2/3 (flat ``packages`` map keyed by
        ``node_modules/...`` paths) and v1 (recursively nested
        ``dependencies``). Non-registry versions (git URLs, aliases) and
        workspace links are skipped.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            self._warn(f"lockfile is not valid JSON: {exc}")
            return []
        if not isinstance(data, dict):
            return []

        lines = content.splitlines()
        entries: list[_DepEntry] = []
        seen: set[tuple[str, str]] = set()

        def add(name: str, version: str, anchor: str) -> None:
            if (name, version) in seen or not _CONCRETE_VERSION.match(version):
                return
            seen.add((name, version))
            line_no, raw = _find_entry_line(lines, anchor)
            entries.append((name, version, line_no, raw))

        packages = data.get("packages")
        if isinstance(packages, dict):  # lockfileVersion 2/3
            for key, meta in packages.items():
                # "" is the project itself; links point at workspace dirs.
                if not key or not isinstance(meta, dict) or meta.get("link"):
                    continue
                version = meta.get("version")
                if not isinstance(version, str):
                    continue
                name = key.rsplit("node_modules/", 1)[-1]
                add(name, version, f'"{key}":')
            return entries

        def walk(deps: object) -> None:  # lockfileVersion 1
            if not isinstance(deps, dict):
                return
            for name, meta in deps.items():
                if not isinstance(meta, dict):
                    continue
                version = meta.get("version")
                if isinstance(version, str):
                    # The entry line opens an object — `"name": {` — which
                    # distinguishes it from `"name": "^1.0"` requires-refs.
                    add(str(name), version, f'"{name}": {{')
                walk(meta.get("dependencies"))

        walk(data.get("dependencies"))
        return entries

    def _query_osv_batch(self, client: httpx.Client, entries: list[_DepEntry]) -> list[list[str]]:
        """Resolve vulnerability ids per lockfile entry via OSV querybatch.

        Returns a list positionally aligned with ``entries``. Failures warn
        and yield empty lists for the affected chunk — never raise.
        """
        ids_per_entry: list[list[str]] = []
        for start in range(0, len(entries), OSV_BATCH_SIZE):
            chunk = entries[start : start + OSV_BATCH_SIZE]
            queries = [
                {"package": {"name": name, "ecosystem": "npm"}, "version": version} for name, version, _, _ in chunk
            ]
            try:
                response = client.post(OSV_QUERYBATCH_URL, json={"queries": queries})
            except httpx.HTTPError as exc:
                self._warn(f"OSV batch query failed: {exc}")
                ids_per_entry.extend([] for _ in chunk)
                continue
            if response.status_code != 200:
                self._warn(f"OSV returned HTTP {response.status_code} for a lockfile batch")
                ids_per_entry.extend([] for _ in chunk)
                continue
            try:
                results = response.json().get("results") or []
            except json.JSONDecodeError as exc:
                self._warn(f"OSV returned invalid JSON for a lockfile batch: {exc}")
                ids_per_entry.extend([] for _ in chunk)
                continue
            for index in range(len(chunk)):
                result = results[index] if index < len(results) and isinstance(results[index], dict) else {}
                vulns = result.get("vulns") or []
                ids_per_entry.append([str(vuln["id"]) for vuln in vulns if isinstance(vuln, dict) and "id" in vuln])
        return ids_per_entry

    def _fetch_vuln(self, client: httpx.Client, vuln_id: str) -> Any:
        """GET full vulnerability details; warn and return None on failure."""
        try:
            response = client.get(OSV_VULN_URL.format(id=vuln_id))
        except httpx.HTTPError as exc:
            self._warn(f"OSV vuln fetch failed for {vuln_id}: {exc}")
            return None
        if response.status_code != 200:
            self._warn(f"OSV returned HTTP {response.status_code} for {vuln_id}")
            return None
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            self._warn(f"OSV returned invalid JSON for {vuln_id}: {exc}")
            return None

    def _npm_finding(
        self,
        client: httpx.Client,
        lock_path: Path,
        entry: _DepEntry,
        vuln_id: str,
        cache: dict[str, Any],
    ) -> Finding:
        """Build a finding for one (package, vulnerability) pair.

        A failed detail fetch still produces a finding — once the id is
        known, dropping the signal would be worse than reporting without
        details.
        """
        name, version, line_no, raw_line = entry
        if vuln_id not in cache:
            cache[vuln_id] = self._fetch_vuln(client, vuln_id)
        vuln = cache[vuln_id]

        if vuln is None:
            summary = "Known vulnerability (details unavailable)."
            severity = "HIGH"
            fixed = ""
        else:
            text = str(vuln.get("summary") or vuln.get("details") or "Known vulnerability.").strip()
            summary = text.splitlines()[0] if text else "Known vulnerability."
            label = str(vuln.get("database_specific", {}).get("severity", "")).upper()
            severity = OSV_SEVERITY_LABELS.get(label, "HIGH")
            fixed = _first_fixed_version(vuln, name, "npm")

        fix_summary = f"Upgrade {name} to >={fixed}" if fixed else f"Upgrade {name} to a patched release"
        return Finding(
            file=str(lock_path),
            line=line_no,
            severity=severity,
            title=f"Vulnerable package: {name}@{version} ({vuln_id})",
            description=f"{summary} (source: OSV.dev)",
            scanner=self.name,
            snippet=raw_line,
            fix_phase=1,
            fix_summary=fix_summary,
            references=[f"https://osv.dev/vulnerability/{vuln_id}"],
        )
