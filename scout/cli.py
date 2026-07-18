"""Scout CLI — entry point for all commands."""

from __future__ import annotations

import sys
import time
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


def _mtime_snapshot(path: Path, exclude: tuple[str, ...], skip: set[Path]) -> dict[Path, float]:
    """Snapshot mtimes of every scannable file, for --watch change detection.

    Args:
        path: Scan root (directory or single file).
        exclude: Exclude patterns from the resolved config.
        skip: Absolute paths to ignore — Scout's own output artifacts, so
            writing the report never re-triggers the watch loop.

    Returns:
        Mapping of file path to mtime; a change in keys or values means
        something was added, removed, or saved.
    """
    from scout.scanners import collect_files

    snapshot: dict[Path, float] = {}
    for file in collect_files(path, exclude=exclude):
        if file in skip:
            continue
        try:
            snapshot[file] = file.stat().st_mtime
        except OSError:  # deleted between collect and stat
            continue
    return snapshot


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
    engine: list[str] | None = typer.Option(
        None,
        "--engine",
        help="External engine to run and merge into the report (currently: semgrep); repeatable. "
        "Needs the engine's binary installed — a missing engine is skipped with a note. "
        "Replaces [tool.scout] engines.",
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
    watch: bool = typer.Option(
        False,
        "--watch",
        help="Re-scan whenever a file in the scanned path changes (1s poll). "
        "Ctrl-C stops and exits 0; the --fail-on exit gate does not apply while watching.",
    ),
    git_history: bool = typer.Option(
        False,
        "--git-history",
        help="Audit git commit history (all branches) for leaked secrets instead of scanning "
        "the working tree. A removed secret is still compromised — rotate anything found. "
        "For a deep history audit use Gitleaks or TruffleHog; this is the built-in convenience pass.",
    ),
) -> None:
    """Scan a project for security vulnerabilities."""
    from scout import baseline as baseline_io
    from scout.agents.reporter_agent import generate_ai_prompts, generate_json, generate_report, generate_sarif
    from scout.agents.scout_agent import run_scout
    from scout.config import load_config
    from scout.git_history import scan_git_history
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

    if watch and write_baseline:
        console.print("[bold red]Error:[/bold red] --watch cannot be combined with --write-baseline.")
        raise typer.Exit(code=2)

    # History findings live in commits, not the working tree — a watch loop,
    # baseline identity, or baseline write can't apply to them.
    if git_history and (watch or write_baseline or baseline is not None):
        console.print("[bold red]Error:[/bold red] --git-history cannot be combined with --watch or baselines.")
        raise typer.Exit(code=2)

    try:
        config = load_config(
            ai_provider="none" if no_ai else model,
            ollama_model=ollama_model,
            project_path=path,
            cli_exclude=list(exclude) if exclude else None,
            cli_fail_on=fail_on,
            cli_engines=list(engine) if engine else None,
        )
        get_all_scanners(config.scanners)  # fail fast on unknown scanner names
        if config.engines:
            from scout.engines import get_engines

            get_engines(config.engines)  # fail fast on unknown engine names
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

    def run_once() -> int:
        """Scan once and emit the configured output; returns the exit code."""
        msg.print(f"\n[bold blue]Scout v{__version__}[/bold blue] scanning: {path}\n")

        if git_history:
            try:
                outcome = scan_git_history(path if path.is_dir() else path.parent)
            except ValueError as exc:
                msg.print(f"[bold red]Error:[/bold red] {exc}")
                raise typer.Exit(code=2) from None
        else:
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
            return 0

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
            return 0

        if fmt == "json":
            text = generate_json(findings, output, project_path=path, files_scanned=outcome.files_scanned)
            if pipe_to_stdout:
                print(text)
            else:
                msg.print(f"\n[bold green]JSON written to:[/bold green] {output}")
            return exit_code

        if fmt == "sarif":
            text = generate_sarif(findings, output, project_path=path, files_scanned=outcome.files_scanned)
            if pipe_to_stdout:
                print(text)
            else:
                msg.print(f"\n[bold green]SARIF written to:[/bold green] {output}")
            return exit_code

        if fmt == "ai-prompt":
            prompts_path = output or path / "security-prompts.md"
            generate_ai_prompts(findings, prompts_path, project_path=path)
            msg.print(f"\n[bold green]AI fix prompts written to:[/bold green] {prompts_path}")
            msg.print("[dim]Paste each block into your AI assistant (Cursor, Claude, Copilot, …).[/dim]\n")
            return exit_code

        # markdown (default)
        report_path = output or path / "security-report.md"
        generate_report(findings, report_path, project_path=path, files_scanned=outcome.files_scanned)
        msg.print(f"\n[bold green]Report written to:[/bold green] {report_path}")
        msg.print(
            "[dim]Next: run `scout scan --format ai-prompt` and paste the prompts into your AI assistant.[/dim]\n"
        )
        return exit_code

    if not watch:
        raise typer.Exit(code=run_once())

    # ponytail: naive 1s mtime poll — swap in watchdog only if poll cost shows up on large trees.
    # Scout's own artifacts are skipped so writing a report/-o file in-tree
    # can't re-trigger the loop.
    artifacts = {
        p.resolve() for p in (output, path / "security-report.md", path / "security-prompts.md") if p is not None
    }
    try:
        snapshot = _mtime_snapshot(path, config.exclude, artifacts)
        run_once()
        msg.print("[dim]Watching for changes — Ctrl-C to stop.[/dim]")
        while True:
            time.sleep(1.0)
            current = _mtime_snapshot(path, config.exclude, artifacts)
            if current != snapshot:
                snapshot = current
                run_once()
                msg.print("[dim]Watching for changes — Ctrl-C to stop.[/dim]")
    except KeyboardInterrupt:
        msg.print("\n[dim]Watch stopped.[/dim]")
        raise typer.Exit() from None


@app.command()
def fix(
    path: Path = typer.Argument(
        ".",
        help="Path to the project to fix.",
        exists=True,
        resolve_path=True,
    ),
    exclude: list[str] | None = typer.Option(
        None,
        "--exclude",
        help="Path or glob (relative to the scan root) to skip; repeatable. Replaces [tool.scout] exclude.",
    ),
) -> None:
    """Apply zero-risk fixes for phase-1 findings — each one shown as a diff and confirmed.

    Scope is the mechanical class only: hardcoded secrets in Python files move
    to a gitignored .env + os.environ lookup, and vulnerable requirements.txt
    pins bump to the first fixed release. Nothing is written without a yes.
    """
    from scout.agents.scout_agent import run_scout
    from scout.config import load_config
    from scout.fix import apply_fix, plan_fixes, render_diff, verify_fix

    try:
        config = load_config(project_path=path, cli_exclude=list(exclude) if exclude else None)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from None

    console.print(f"\n[bold blue]Scout v{__version__}[/bold blue] scanning for fixable findings: {path}\n")
    outcome = run_scout(path, config)
    root = path if path.is_dir() else path.parent
    proposals = plan_fixes(outcome.findings, root)

    if not proposals:
        console.print(
            f"[bold green]No auto-fixable findings.[/bold green] "
            f"({len(outcome.findings)} finding(s) total — run `scout scan` for the full report.)\n"
        )
        raise typer.Exit()

    applied = 0
    for index, proposal in enumerate(proposals, start=1):
        console.print(f"[bold]{index}/{len(proposals)}[/bold] {proposal.summary}")
        console.print(render_diff(proposal), markup=False, highlight=False)
        if not typer.confirm("Apply this fix?", default=False):
            console.print("[dim]Skipped.[/dim]\n")
            continue
        try:
            apply_fix(proposal)
        except OSError as exc:
            console.print(f"[bold red]Error:[/bold red] could not write fix: {exc}\n")
            continue
        applied += 1
        if verify_fix(proposal):
            console.print("[bold green]Applied — re-scan clean for this finding.[/bold green]")
        else:
            console.print("[bold yellow]Applied, but the finding still triggers — review manually.[/bold yellow]")
        if proposal.warning:
            console.print(f"[yellow]⚠ {proposal.warning}[/yellow]")
        console.print()

    console.print(f"[bold]{applied}[/bold] of {len(proposals)} fix(es) applied. Re-run `scout scan` to verify.\n")


if __name__ == "__main__":
    app()
