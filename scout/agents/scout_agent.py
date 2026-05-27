"""Scout Agent — orchestrates all scanners and optional AI confirmation."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from scout.config import ScoutConfig
from scout.models import Finding
from scout.scanners import collect_files, get_all_scanners

console = Console()


def run_scout(path: Path, config: ScoutConfig) -> list[Finding]:
    """Run all scanners against the target path.

    Args:
        path: Root directory or file to scan.
        config: Runtime configuration (AI settings, etc.).

    Returns:
        Combined list of findings from all scanners, sorted by severity.
    """
    files = collect_files(path)
    if not files:
        console.print("[yellow]No scannable files found.[/yellow]")
        return []

    console.print(f"  Scanning [bold]{len(files)}[/bold] files...\n")

    all_findings: list[Finding] = []
    scanners = get_all_scanners()

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

    # Optional AI confirmation pass
    if config.ai_enabled:
        all_findings = _run_ai_pass(all_findings, config)

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

    return unique


def _run_ai_pass(findings: list[Finding], config: ScoutConfig) -> list[Finding]:
    """Send flagged snippets to AI for confirmation and severity rating.

    Only sends snippets — never full files. Each call is under 2000 tokens.
    """
    # TODO: Implement AI confirmation when ai/client.py is ready
    # For now, return findings as-is (static scan is already useful)
    console.print("  [dim]AI pass: not yet implemented (static results only)[/dim]")
    return findings
