"""Scout Agent — orchestrates all scanners and optional AI confirmation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from scout.agents.reporter_agent import _finding_id
from scout.config import ScoutConfig
from scout.models import Finding
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
    files = collect_files(path)
    if not files:
        if not quiet:
            console.print("[yellow]No scannable files found.[/yellow]")
        return ScanOutcome(findings=[], files_scanned=0)

    if not quiet:
        console.print(f"  Scanning [bold]{len(files)}[/bold] files...\n")

    all_findings: list[Finding] = []
    scanners = get_all_scanners()

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
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    # Deduplicate (same file + same line + same scanner)
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for finding in all_findings:
        key = (finding.file, finding.line, finding.scanner)
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return ScanOutcome(findings=unique, files_scanned=len(files))


def _run_ai_pass(findings: list[Finding], config: ScoutConfig, quiet: bool = False) -> list[Finding]:
    """Send flagged snippets to AI for confirmation and severity rating.

    Only sends snippets — never full files. Each call is under 2000 tokens.
    """
    # TODO: Implement AI confirmation when ai/client.py is ready
    # For now, return findings as-is (static scan is already useful)
    if not quiet:
        console.print("  [dim]AI pass: not yet implemented (static results only)[/dim]")
    return findings
