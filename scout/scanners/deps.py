"""Dependency scanner — checks for known vulnerable packages."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scout.models import Finding
from scout.scanners import register_scanner
from scout.scanners.base import BaseScanner


@register_scanner
class DepsScanner(BaseScanner):
    """Detects vulnerable dependencies via pip audit and npm audit."""

    name = "deps"
    description = "Finds known CVEs in project dependencies"

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
            if any((project_root / f).exists() for f in [
                "requirements.txt", "pyproject.toml", "package.json", "Pipfile"
            ]):
                break
            project_root = project_root.parent

        findings: list[Finding] = []
        findings.extend(self._scan_python(project_root))
        findings.extend(self._scan_node(project_root))
        return findings

    def _scan_python(self, project_root: Path) -> list[Finding]:
        """Run pip audit if requirements exist."""
        req_files = [
            project_root / "requirements.txt",
            project_root / "pyproject.toml",
        ]
        if not any(f.exists() for f in req_files):
            return []

        try:
            result = subprocess.run(
                ["pip", "audit", "--format=json", "--desc"],
                capture_output=True, text=True, timeout=60,
                cwd=str(project_root),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if result.returncode == 0:
            return []

        findings: list[Finding] = []
        try:
            data = json.loads(result.stdout)
            for vuln in data.get("vulnerabilities", []):
                pkg = vuln.get("name", "unknown")
                version = vuln.get("version", "?")
                vuln_id = vuln.get("id", "")
                desc = vuln.get("description", "No description available.")
                fix_version = vuln.get("fix_versions", ["latest"])[0] if vuln.get("fix_versions") else "latest"

                severity = self._map_severity(vuln.get("aliases", []))
                findings.append(Finding(
                    file=str(project_root / "requirements.txt"),
                    line=0,
                    severity=severity,
                    title=f"Vulnerable package: {pkg}=={version} ({vuln_id})",
                    description=f"{desc} Upgrade to fix.",
                    scanner=self.name,
                    snippet=f"{pkg}=={version}",
                    fix_phase=1,
                    fix_summary=f"Upgrade {pkg} to >={fix_version}",
                ))
        except (json.JSONDecodeError, KeyError):
            pass

        return findings

    def _scan_node(self, project_root: Path) -> list[Finding]:
        """Run npm audit if package.json exists."""
        if not (project_root / "package.json").exists():
            return []

        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True, timeout=60,
                cwd=str(project_root),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
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
                desc = via[0].get("title", "Known vulnerability") if via and isinstance(via[0], dict) else f"Vulnerable dependency: {pkg_name}"
                fix_cmd = info.get("fixAvailable", "npm audit fix")

                findings.append(Finding(
                    file=str(project_root / "package.json"),
                    line=0,
                    severity=severity,
                    title=f"Vulnerable package: {pkg_name}",
                    description=desc,
                    scanner=self.name,
                    snippet=f'"{pkg_name}": ...',
                    fix_phase=1,
                    fix_summary=f"Run `npm audit fix` or manually update {pkg_name}. Fix: {fix_cmd}",
                ))
        except (json.JSONDecodeError, KeyError):
            pass

        return findings

    def _map_severity(self, aliases: list[str]) -> str:
        """Map CVE aliases to severity (rough heuristic)."""
        for alias in aliases:
            if "CRITICAL" in alias.upper():
                return "CRITICAL"
        return "HIGH"
