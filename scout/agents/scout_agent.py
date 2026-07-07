"""Scout Agent — orchestrates all scanners and optional AI confirmation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from scout.agents.reporter_agent import _finding_id
from scout.config import ScoutConfig
from scout.models import Finding, Severity, severity_rank
from scout.scanners import collect_files, get_all_scanners

console = Console()

# Trailing comment that silences the finding(s) on its line:
#   scout: ignore              — every finding on the line
#   scout: ignore[injection]   — only the named scanner or finding id
_INLINE_IGNORE = re.compile(r"scout:\s*ignore(?:\[([^\]]+)\])?")


def _apply_inline_suppressions(findings: list[Finding]) -> list[Finding]:
    """Drop findings whose flagged line carries a ``scout: ignore`` comment.

    A bare ``scout: ignore`` suppresses every finding on that line;
    ``scout: ignore[<scanner-or-finding-id>]`` suppresses only the named one.
    Project-level findings and findings without a real line anchor are never
    suppressed, and unreadable files keep their findings.

    Args:
        findings: Raw findings from all scanners.

    Returns:
        Findings with suppressed entries removed.
    """
    file_lines: dict[str, list[str] | None] = {}
    kept: list[Finding] = []
    for finding in findings:
        if finding.line < 1 or finding.project_level:
            kept.append(finding)
            continue
        if finding.file not in file_lines:
            try:
                text = Path(finding.file).read_text(encoding="utf-8", errors="ignore")
                file_lines[finding.file] = text.splitlines()
            except OSError:
                file_lines[finding.file] = None
        lines = file_lines[finding.file]
        if lines is None or finding.line > len(lines):
            kept.append(finding)
            continue
        match = _INLINE_IGNORE.search(lines[finding.line - 1])
        if match is None:
            kept.append(finding)
            continue
        scope = match.group(1)
        if scope is not None:
            token = scope.strip()
            if token not in (finding.scanner, _finding_id(finding)):
                kept.append(finding)
    return kept


@dataclass
class ScanOutcome:
    """Combined result of a scan run.

    Attributes:
        findings: Deduplicated findings, sorted by severity.
        files_scanned: Number of files that were collected and scanned.
    """

    findings: list[Finding]
    files_scanned: int


def run_scout(path: Path, config: ScoutConfig, quiet: bool = False) -> ScanOutcome:
    """Run all scanners against the target path.

    Args:
        path: Root directory or file to scan.
        config: Runtime configuration (AI settings, etc.).
        quiet: Suppress decorative progress output (used when piping
            machine-readable output to stdout).

    Returns:
        ScanOutcome with deduplicated findings (sorted by severity) and the
        number of files scanned.
    """
    files = collect_files(path, exclude=config.exclude)
    if not files:
        if not quiet:
            console.print("[yellow]No scannable files found.[/yellow]")
        return ScanOutcome(findings=[], files_scanned=0)

    if not quiet:
        console.print(f"  Scanning [bold]{len(files)}[/bold] files...\n")

    all_findings: list[Finding] = []
    scanners = get_all_scanners(config.scanners)

    if quiet:
        for scanner_cls in scanners:
            all_findings.extend(scanner_cls().scan(files))
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for scanner_cls in scanners:
                scanner = scanner_cls()
                task = progress.add_task(f"Running {scanner.name} scanner...", total=None)
                findings = scanner.scan(files)
                all_findings.extend(findings)
                progress.update(task, completed=True)

    # Inline `scout: ignore` comments silence their line's findings.
    all_findings = _apply_inline_suppressions(all_findings)

    # Optional AI confirmation pass
    if config.ai_enabled:
        all_findings = _run_ai_pass(all_findings, config, quiet=quiet)

    # Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
    all_findings.sort(key=lambda f: severity_rank(f.severity))

    return ScanOutcome(findings=_dedupe_findings(all_findings), files_scanned=len(files))


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse exact duplicates, preserving order.

    The key includes the title: two different patterns hitting the same line
    are both real findings — a (file, line, scanner) key used to silently
    drop the second one.

    Args:
        findings: Findings sorted by severity.

    Returns:
        Findings with exact duplicates removed.
    """
    seen: set[tuple[str, int, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.file, finding.line, finding.scanner, finding.title)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


_VALID_SEVERITIES = {s.value for s in Severity}


def _ai_reviewable(finding: Finding) -> bool:
    """True when a snippet-only AI reviewer can meaningfully judge a finding.

    Excludes project-level checks (synthetic anchors, app-wide) and dependency
    findings (deterministic OSV advisory data, not a heuristic pattern match) —
    a reviewer that only sees a snippet cannot fairly confirm or dismiss those,
    and must never dismiss a real CVE it never got to look at.
    """
    return bool(finding.snippet) and not finding.project_level and finding.scanner != "deps"


def _run_ai_pass(findings: list[Finding], config: ScoutConfig, quiet: bool = False) -> list[Finding]:
    """Confirm heuristic findings with the configured AI provider.

    Sends only the flagged snippet (never whole files) for each pattern-matched
    finding and applies the verdict: drop dismissed findings, apply a returned
    severity when it is a downgrade (the AI may lower severity but never
    escalate it), and mark survivors ``ai_confirmed``. Any provider or parse
    error leaves the finding untouched — failing open, so an API hiccup can
    never silently hide a real finding.

    Args:
        findings: Post-suppression findings.
        config: Runtime config with the resolved AI provider and keys.
        quiet: Suppress the progress line when piping machine-readable output.

    Returns:
        Confirmed and downgraded findings, with dismissed ones removed.
    """
    from scout.ai.client import AIClient

    client = AIClient(config)
    if not quiet:
        count = sum(1 for f in findings if _ai_reviewable(f))
        if count:
            console.print(f"  [dim]AI pass: confirming {count} finding(s) via {config.ai_provider}...[/dim]")

    kept: list[Finding] = []
    for finding in findings:
        if not _ai_reviewable(finding):
            kept.append(finding)
            continue
        response = client.confirm_finding(
            file=finding.file,
            lines=str(finding.line),
            issue_type=_finding_id(finding),
            code=finding.snippet,
        )
        verdict = response.parsed
        if response.error or verdict is None:
            kept.append(finding)  # fail open on any provider/parse failure
            continue
        if verdict.get("confirmed") is False:
            continue  # AI dismissed it as a false positive
        finding.ai_confirmed = True
        severity = verdict.get("severity")
        if (
            isinstance(severity, str)
            and severity.upper() in _VALID_SEVERITIES
            and severity_rank(severity.upper()) >= severity_rank(finding.severity)
        ):
            finding.severity = severity.upper()  # downgrade only
        kept.append(finding)
    return kept
