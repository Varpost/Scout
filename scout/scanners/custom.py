"""Custom scanner — user-defined YAML detection rules.

Rules are grep-with-metadata on purpose: an id, a regex, a message, and a
severity. Users needing metavariables or taint analysis should reach for
``--engine semgrep`` — Scout's custom rules stay simple enough to write in a
minute and impossible to get catastrophically wrong. Every malformed rule
warns and is skipped individually; a bad rule file can never break a scan.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from scout.config import _read_tool_scout
from scout.models import Finding, Severity
from scout.scanners import register_scanner
from scout.scanners.base import BaseScanner

_VALID_SEVERITIES = {severity.value for severity in Severity}


def _warn(message: str) -> None:
    """Emit a visible warning — rule problems must never be silent."""
    print(f"scout: custom rules: {message}", file=sys.stderr)


@dataclass
class CustomRule:
    """One validated user rule."""

    id: str
    pattern: re.Pattern[str]
    message: str
    severity: str
    fix_phase: int
    suffixes: frozenset[str] | None
    fix: str


def _parse_rule(raw: object, source: Path, seen_ids: set[str]) -> CustomRule | None:
    """Validate one raw rule mapping; warn and return None on any problem."""
    if not isinstance(raw, dict):
        _warn(f"{source}: rule entries must be mappings, got {type(raw).__name__} — skipped")
        return None
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        _warn(f"{source}: rule missing a string `id` — skipped")
        return None
    if rule_id in seen_ids:
        _warn(f"{source}: duplicate rule id '{rule_id}' — skipped")
        return None

    pattern_raw = raw.get("pattern")
    if not isinstance(pattern_raw, str) or not pattern_raw:
        _warn(f"{source}: rule '{rule_id}' missing a string `pattern` — skipped")
        return None
    try:
        pattern = re.compile(pattern_raw)
    except re.error as exc:
        _warn(f"{source}: rule '{rule_id}' has an invalid regex: {exc} — skipped")
        return None
    if pattern.match(""):
        _warn(f"{source}: rule '{rule_id}' pattern matches the empty string — skipped")
        return None

    message = raw.get("message")
    if not isinstance(message, str) or not message.strip():
        _warn(f"{source}: rule '{rule_id}' missing a string `message` — skipped")
        return None

    severity = str(raw.get("severity", "")).upper()
    if severity not in _VALID_SEVERITIES:
        _warn(f"{source}: rule '{rule_id}' severity must be one of {', '.join(sorted(_VALID_SEVERITIES))} — skipped")
        return None

    fix_phase = raw.get("fix_phase", 3)
    if not isinstance(fix_phase, int) or isinstance(fix_phase, bool) or not 1 <= fix_phase <= 5:
        _warn(f"{source}: rule '{rule_id}' fix_phase must be an integer 1-5 — skipped")
        return None

    suffixes_raw = raw.get("suffixes")
    suffixes: frozenset[str] | None = None
    if suffixes_raw is not None:
        if not isinstance(suffixes_raw, list) or not all(isinstance(s, str) for s in suffixes_raw):
            _warn(f"{source}: rule '{rule_id}' suffixes must be a list of strings — skipped")
            return None
        suffixes = frozenset(s.lower() for s in suffixes_raw)

    fix = raw.get("fix", "")
    if not isinstance(fix, str):
        _warn(f"{source}: rule '{rule_id}' fix must be a string — skipped")
        return None

    return CustomRule(
        id=rule_id,
        pattern=pattern,
        message=message,
        severity=severity,
        fix_phase=fix_phase,
        suffixes=suffixes,
        fix=fix,
    )


def load_rules(rule_paths: list[Path]) -> list[CustomRule]:
    """Load and validate rules from YAML files — per-rule fail-open.

    Args:
        rule_paths: Absolute paths to rule files.

    Returns:
        Every rule that validated; problems warn to stderr and are skipped.
    """
    rules: list[CustomRule] = []
    seen_ids: set[str] = set()
    for path in rule_paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            _warn(f"cannot read {path}: {exc}")
            continue
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            _warn(f"{path} is not valid YAML: {exc}")
            continue
        if data is None:
            continue
        raw_rules = data.get("rules") if isinstance(data, dict) else None
        if not isinstance(raw_rules, list):
            _warn(f"{path}: expected a top-level `rules:` list")
            continue
        for raw in raw_rules:
            rule = _parse_rule(raw, path, seen_ids)
            if rule is not None:
                seen_ids.add(rule.id)
                rules.append(rule)
    return rules


@register_scanner
class CustomScanner(BaseScanner):
    """Runs user-defined YAML rules from ``[tool.scout] rules``."""

    name = "custom"
    description = "Runs your own YAML detection rules"

    def __init__(self) -> None:
        """Initialize with no rules; ``scan`` loads them from the project."""
        self._rules: list[CustomRule] = []

    def scan(self, files: list[Path]) -> list[Finding]:
        """Load the scanned project's rule files, then run the base loop."""
        if not files:
            return []
        root = self._project_root(files[0])
        self._rules = load_rules(self._rule_paths(root))
        if not self._rules:
            return []
        return super().scan(files)

    def _project_root(self, first_file: Path) -> Path:
        """Walk up from the first scanned file to the pyproject.toml root."""
        root = first_file.parent
        while root != root.parent:
            if (root / "pyproject.toml").exists():
                break
            root = root.parent
        return root

    def _rule_paths(self, root: Path) -> list[Path]:
        """Resolve ``[tool.scout] rules`` entries relative to the project root."""
        try:
            table = _read_tool_scout(root)
        except ValueError as exc:
            _warn(str(exc))
            return []
        raw = table.get("rules")
        if raw is None:
            return []
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            _warn("[tool.scout] rules must be an array of file paths")
            return []
        return [root / item for item in raw]

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Run every loaded rule over one file."""
        findings: list[Finding] = []
        lines = content.splitlines()
        suffix = file_path.suffix.lower()
        for rule in self._rules:
            if rule.suffixes is not None and suffix not in rule.suffixes:
                continue
            for match in rule.pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 1)
                findings.append(
                    Finding(
                        file=str(file_path),
                        line=line_num,
                        severity=rule.severity,
                        title=rule.id,
                        description=rule.message,
                        scanner=self.name,
                        snippet="\n".join(lines[start:end]),
                        fix_phase=rule.fix_phase,
                        fix_summary=rule.fix,
                    )
                )
        return findings
