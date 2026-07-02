"""Scout CLI — entry point for all commands."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from scout import __version__
from scout.config import FAIL_ON_CHOICES as _FAIL_ON_CHOICES
from scout.models import Finding

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


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
    threshold = _SEVERITY_RANK[fail_on.upper()]
    return 1 if any(_SEVERITY_RANK.get(f.severity, 99) <= threshold for f in findings) else 0


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
        help="Reserved — AI confirmation pass not yet implemented. Every scan is currently static-only.",
    ),
    ollama_model: str = typer.Option(
        "llama3",
        "--ollama-model",
        help="Reserved — AI confirmation pass not yet implemented.",
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Skip the AI pass (currently a no-op — the AI pass is not yet implemented).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path. Omit with --format json to pipe to stdout.",
    ),
    output_format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format: markdown (default) | ai-prompt | json.",
    ),
    exclude: list[str] | None = typer.Option(
        None,
        "--exclude",
        help="Path or glob (relative to the scan root) to skip; repeatable. Replaces [tool.scout] exclude.",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 when findings at or above this severity exist: critical | high | medium | low | never. "
        "Default: high, or [tool.scout] fail_on.",
    ),
) -> None:
    """Scan a project for security vulnerabilities."""
    from scout.agents.reporter_agent import generate_ai_prompts, generate_json, generate_report
    from scout.agents.scout_agent import run_scout
    from scout.config import load_config
    from scout.scanners import get_all_scanners

    fmt = output_format.lower()
    if fmt not in {"markdown", "ai-prompt", "json"}:
        console.print(
            f"[bold red]Error:[/bold red] invalid --format '{output_format}'. Choose: markdown | ai-prompt | json."
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

    # `--format json` with no -o pipes clean JSON to stdout; decorative output
    # then goes to stderr so the pipe stays machine-readable.
    json_to_stdout = fmt == "json" and output is None
    msg = Console(stderr=True) if json_to_stdout else console

    msg.print(f"\n[bold blue]Scout v{__version__}[/bold blue] scanning: {path}\n")

    outcome = run_scout(path, config, quiet=json_to_stdout)
    findings = outcome.findings
    exit_code = _exit_code_for(findings, config.fail_on)

    if findings:
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        medium = sum(1 for f in findings if f.severity == "MEDIUM")
        low = sum(1 for f in findings if f.severity == "LOW")

        msg.print(f"Found [bold red]{len(findings)}[/bold red] issues:\n")
        if critical:
            msg.print(f"  [bold red]🔴 {critical} critical[/bold red]")
        if high:
            msg.print(f"  [red]🟠 {high} high[/red]")
        if medium:
            msg.print(f"  [yellow]🟡 {medium} medium[/yellow]")
        if low:
            msg.print(f"  [blue]🔵 {low} low[/blue]")
    elif fmt == "markdown":
        # Nothing to report — JSON/ai-prompt still emit a valid (empty) document.
        msg.print("[bold green]No vulnerabilities found. Ship it![/bold green]\n")
        raise typer.Exit()

    if fmt == "json":
        text = generate_json(findings, output, project_path=path, files_scanned=outcome.files_scanned)
        if json_to_stdout:
            print(text)
        else:
            msg.print(f"\n[bold green]JSON written to:[/bold green] {output}")
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


# Hidden until implemented (T3.4 decides implement-vs-delete): advertising
# "Coming soon" stubs in --help funnels users into dead ends.
@app.command(hidden=True)
def fix(
    phase: int = typer.Option(
        ...,
        "--phase",
        "-p",
        min=1,
        max=5,
        help="Which phase to implement (1-5).",
    ),
    path: Path = typer.Argument(
        ".",
        help="Path to the project.",
        exists=True,
        resolve_path=True,
    ),
) -> None:
    """Apply fixes for a specific phase (requires prior scan)."""
    report_path = path / "security-report.md"
    if not report_path.exists():
        console.print("[bold red]Error:[/bold red] No security-report.md found. Run `scout scan` first.\n")
        raise typer.Exit(code=1)

    console.print(f"\n[bold blue]Implementer Agent[/bold blue] — Phase {phase}")
    console.print("[yellow]Coming soon.[/yellow] Phase 1 focuses on the scanner.\n")


@app.command(hidden=True)
def validate(
    path: Path = typer.Argument(
        ".",
        help="Path to the project.",
        exists=True,
        resolve_path=True,
    ),
) -> None:
    """Re-scan changed files and run tests to verify fixes."""
    console.print("\n[bold blue]Validator Agent[/bold blue]")
    console.print("[yellow]Coming soon.[/yellow]\n")


@app.command(hidden=True)
def report(
    path: Path = typer.Argument(
        ".",
        help="Path to the project.",
        exists=True,
        resolve_path=True,
    ),
) -> None:
    """Re-generate the report from last scan without re-scanning."""
    console.print("\n[bold blue]Reporter Agent[/bold blue]")
    console.print("[yellow]Coming soon.[/yellow]\n")


if __name__ == "__main__":
    app()
