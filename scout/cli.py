"""Scout CLI — entry point for all commands."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from scout import __version__
from scout.config import FAIL_ON_CHOICES as _FAIL_ON_CHOICES
from scout.models import Finding, Severity, severity_rank

# Presentation per severity, iterated in canonical (most-severe-first) order.
_SEVERITY_STYLES: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("bold red", "🔴"),
    Severity.HIGH: ("red", "🟠"),
    Severity.MEDIUM: ("yellow", "🟡"),
    Severity.LOW: ("blue", "🔵"),
}


def _exit_code_for(findings: list[Finding], fail_on: str) -> int:
    """Exit 1 when any finding is at or above the --fail-on severity.

    Args:
        findings: Findings from the scan.
        fail_on: Lowercase threshold ('critical' … 'low') or 'never'.

    Returns:
        Process exit code (0 or 1).
    """
    if fail_on == "never":
        return 0
    threshold = severity_rank(fail_on.upper())
    return 1 if any(severity_rank(f.severity) <= threshold for f in findings) else 0


def _force_utf8_output() -> None:
    """Make stdout/stderr UTF-8 so Scout never crashes on Windows.

    Windows consoles and pipes default to cp1252, which cannot encode Scout's
    progress spinner glyphs and severity emoji — rich then raises
    UnicodeEncodeError mid-scan. Reconfiguring the streams to UTF-8 fixes both
    the interactive and the piped/redirected cases.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (ValueError, OSError):  # detached or non-reconfigurable stream
            pass


_force_utf8_output()

app = typer.Typer(
    name="scout",
    help="AI security team in a CLI. Find, plan, fix, and verify vulnerabilities.",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"Scout v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Scout — Your AI security team in a CLI."""


@app.command()
def scan(
    path: Path = typer.Argument(
        ".",
        help="Path to the project to scan.",
        exists=True,
        resolve_path=True,
    ),
    model: str = typer.Option(
        "none",
        "--model",
        "-m",
        help="Optional AI confirmation provider: none (default) | anthropic | openai | ollama. "
        "Confirms/downgrades/dismisses heuristic findings; needs the matching API key. "
        "The core scan is always static and deterministic.",
    ),
    ollama_model: str = typer.Option(
        "llama3",
        "--ollama-model",
        help="Ollama model to use when --model ollama (default: llama3).",
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Force the AI confirmation pass off (overrides --model and SCOUT_AI_PROVIDER).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path. Omit with --format json/sarif to pipe to stdout.",
    ),
    output_format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format: markdown (default) | ai-prompt | json | sarif.",
    ),
    exclude: list[str] | None = typer.Option(
        None,
        "--exclude",
        help="Path or glob (relative to the scan root) to skip; repeatable. Replaces [tool.scout] exclude.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Baseline file of accepted findings to filter out (write one with --write-baseline). "
        "Only findings not in the baseline are reported and gate the exit code.",
    ),
    write_baseline: bool = typer.Option(
        False,
        "--write-baseline",
        help="Accept all current findings: write them to the baseline file (--baseline path, or "
        ".scout-baseline.json in the scan root) and exit 0 without writing a report.",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 when findings at or above this severity exist: critical | high | medium | low | never. "
        "Default: high, or [tool.scout] fail_on.",
    ),
) -> None:
    """Scan a project for security vulnerabilities."""
    from scout import baseline as baseline_io
    from scout.agents.reporter_agent import generate_ai_prompts, generate_json, generate_report, generate_sarif
    from scout.agents.scout_agent import run_scout
    from scout.config import load_config
    from scout.scanners import get_all_scanners

    fmt = output_format.lower()
    if fmt not in {"markdown", "ai-prompt", "json", "sarif"}:
        console.print(
            f"[bold red]Error:[/bold red] invalid --format '{output_format}'. "
            "Choose: markdown | ai-prompt | json | sarif."
        )
        raise typer.Exit(code=2)

    if fail_on is not None and fail_on.lower() not in _FAIL_ON_CHOICES:
        console.print(
            f"[bold red]Error:[/bold red] invalid --fail-on '{fail_on}'. "
            "Choose: critical | high | medium | low | never."
        )
        raise typer.Exit(code=2)

    try:
        config = load_config(
            ai_provider="none" if no_ai else model,
            ollama_model=ollama_model,
            project_path=path,
            cli_exclude=list(exclude) if exclude else None,
            cli_fail_on=fail_on,
        )
        get_all_scanners(config.scanners)  # fail fast on unknown scanner names
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from None

    # Load the baseline before scanning so a bad file fails fast.
    known_baseline: set[baseline_io.BaselineKey] | None = None
    if baseline is not None and not write_baseline:
        try:
            known_baseline = baseline_io.load_baseline(baseline)
        except ValueError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(code=2) from None

    # `--format json`/`--format sarif` with no -o pipe the document to stdout;
    # decorative output then goes to stderr so the pipe stays machine-readable.
    pipe_to_stdout = fmt in {"json", "sarif"} and output is None
    msg = Console(stderr=True) if pipe_to_stdout else console

    msg.print(f"\n[bold blue]Scout v{__version__}[/bold blue] scanning: {path}\n")

    outcome = run_scout(path, config, quiet=pipe_to_stdout)
    findings = outcome.findings
    root = path if path.is_dir() else path.parent

    if write_baseline:
        baseline_path = baseline if baseline is not None else root / baseline_io.DEFAULT_BASELINE_NAME
        try:
            count = baseline_io.write_baseline(findings, root, baseline_path)
        except OSError as exc:
            msg.print(f"[bold red]Error:[/bold red] cannot write baseline: {exc}")
            raise typer.Exit(code=2) from None
        msg.print(f"[bold green]Baseline written:[/bold green] {baseline_path} ({count} finding(s) accepted)")
        msg.print("[dim]Commit this file; scans with --baseline then report only new findings.[/dim]\n")
        raise typer.Exit()

    if known_baseline is not None:
        findings = baseline_io.filter_baselined(findings, root, known_baseline)

    exit_code = _exit_code_for(findings, config.fail_on)

    if findings:
        msg.print(f"Found [bold red]{len(findings)}[/bold red] issues:\n")
        for severity in Severity:
            count = sum(1 for f in findings if f.severity == severity.value)
            if count:
                style, emoji = _SEVERITY_STYLES[severity]
                msg.print(f"  [{style}]{emoji} {count} {severity.value.lower()}[/{style}]")
    elif fmt == "markdown":
        # Nothing to report — json/sarif/ai-prompt still emit a valid (empty) document.
        msg.print("[bold green]No vulnerabilities found. Ship it![/bold green]\n")
        raise typer.Exit()

    if fmt == "json":
        text = generate_json(findings, output, project_path=path, files_scanned=outcome.files_scanned)
        if pipe_to_stdout:
            print(text)
        else:
            msg.print(f"\n[bold green]JSON written to:[/bold green] {output}")
        raise typer.Exit(code=exit_code)

    if fmt == "sarif":
        text = generate_sarif(findings, output, project_path=path, files_scanned=outcome.files_scanned)
        if pipe_to_stdout:
            print(text)
        else:
            msg.print(f"\n[bold green]SARIF written to:[/bold green] {output}")
        raise typer.Exit(code=exit_code)

    if fmt == "ai-prompt":
        prompts_path = output or path / "security-prompts.md"
        generate_ai_prompts(findings, prompts_path, project_path=path)
        msg.print(f"\n[bold green]AI fix prompts written to:[/bold green] {prompts_path}")
        msg.print("[dim]Paste each block into your AI assistant (Cursor, Claude, Copilot, …).[/dim]\n")
        raise typer.Exit(code=exit_code)

    # markdown (default)
    report_path = output or path / "security-report.md"
    generate_report(findings, report_path, project_path=path, files_scanned=outcome.files_scanned)
    msg.print(f"\n[bold green]Report written to:[/bold green] {report_path}")
    msg.print("[dim]Next: run `scout scan --format ai-prompt` and paste the prompts into your AI assistant.[/dim]\n")
    raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()
