"""Scout CLI — entry point for all commands."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from scout import __version__

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
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Scout — Your AI security team in a CLI."""


@app.command()
def scan(
    path: Path = typer.Argument(
        ".", help="Path to the project to scan.", exists=True, resolve_path=True,
    ),
    model: str = typer.Option(
        "none", "--model", "-m",
        help="AI provider: anthropic | openai | ollama | none (static only).",
    ),
    ollama_model: str = typer.Option(
        "llama3", "--ollama-model", help="Ollama model name (if using ollama).",
    ),
    no_ai: bool = typer.Option(
        False, "--no-ai", help="Skip AI pass entirely (static scan only).",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output path for the report.",
    ),
) -> None:
    """Scan a project for security vulnerabilities."""
    from scout.agents.scout_agent import run_scout
    from scout.agents.reporter_agent import generate_report
    from scout.config import load_config

    config = load_config(
        ai_provider="none" if no_ai else model,
        ollama_model=ollama_model,
    )

    console.print(f"\n[bold blue]Scout v{__version__}[/bold blue] scanning: {path}\n")

    findings = run_scout(path, config)

    if not findings:
        console.print("[bold green]No vulnerabilities found. Ship it![/bold green]\n")
        raise typer.Exit()

    # Summarize findings
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    console.print(f"Found [bold red]{len(findings)}[/bold red] issues:\n")
    if critical:
        console.print(f"  [bold red]🔴 {critical} critical[/bold red]")
    if high:
        console.print(f"  [red]🟠 {high} high[/red]")
    if medium:
        console.print(f"  [yellow]🟡 {medium} medium[/yellow]")
    if low:
        console.print(f"  [blue]🔵 {low} low[/blue]")

    # Generate report
    report_path = output or path / "security-report.md"
    generate_report(findings, report_path, project_path=path)
    console.print(f"\n[bold green]Report written to:[/bold green] {report_path}")
    console.print("[dim]Next: open the report, then run `scout fix --phase 1`[/dim]\n")


@app.command()
def fix(
    phase: int = typer.Option(
        ..., "--phase", "-p", min=1, max=5,
        help="Which phase to implement (1-5).",
    ),
    path: Path = typer.Argument(
        ".", help="Path to the project.", exists=True, resolve_path=True,
    ),
) -> None:
    """Apply fixes for a specific phase (requires prior scan)."""
    report_path = path / "security-report.md"
    if not report_path.exists():
        console.print(
            "[bold red]Error:[/bold red] No security-report.md found. "
            "Run `scout scan` first.\n"
        )
        raise typer.Exit(code=1)

    console.print(f"\n[bold blue]Implementer Agent[/bold blue] — Phase {phase}")
    console.print("[yellow]Coming soon.[/yellow] Phase 1 focuses on the scanner.\n")


@app.command()
def validate(
    path: Path = typer.Argument(
        ".", help="Path to the project.", exists=True, resolve_path=True,
    ),
) -> None:
    """Re-scan changed files and run tests to verify fixes."""
    console.print("\n[bold blue]Validator Agent[/bold blue]")
    console.print("[yellow]Coming soon.[/yellow]\n")


@app.command()
def report(
    path: Path = typer.Argument(
        ".", help="Path to the project.", exists=True, resolve_path=True,
    ),
) -> None:
    """Re-generate the report from last scan without re-scanning."""
    console.print("\n[bold blue]Reporter Agent[/bold blue]")
    console.print("[yellow]Coming soon.[/yellow]\n")


if __name__ == "__main__":
    app()
