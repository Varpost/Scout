"""Tests for --git-history: secrets in past commits, not just HEAD."""

from __future__ import annotations

import subprocess
from pathlib import Path

from typer.testing import CliRunner

from scout.cli import app
from scout.git_history import scan_git_history

runner = CliRunner()

# Runtime-built so it is never a real credential and never trips push protection.
FAKE_AWS_KEY = "AKIA" + "ABCD" * 4


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=scout@test.invalid",
            "-c",
            "user.name=scout-test",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _repo_with_removed_secret(tmp_path: Path) -> tuple[Path, str]:
    """Build a repo whose secret exists only in a non-HEAD commit.

    Returns:
        The repo path and the SHA of the commit that introduced the secret.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    target = repo / "config.py"
    target.write_text(f'aws_key = "{FAKE_AWS_KEY}"\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add config")
    target.write_text("aws_key = None\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "remove the secret")
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--max-parents=0", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return repo, sha


def test_secret_in_non_head_commit_is_flagged_with_its_sha(tmp_path):
    repo, sha = _repo_with_removed_secret(tmp_path)

    # HEAD is clean — the working-tree scanner would find nothing.
    assert FAKE_AWS_KEY not in (repo / "config.py").read_text(encoding="utf-8")

    outcome = scan_git_history(repo)
    aws = [f for f in outcome.findings if "AWS Access Key" in f.title]
    assert aws, "secret in a removed commit must be found"
    finding = aws[0]
    assert finding.file == f"config.py @ {sha[:12]}"
    assert sha in finding.description
    assert finding.line == 1  # real line number in that commit's file version
    # The removal commit's diff has no added secret line — one finding, not two.
    assert len(aws) == 1


def test_clean_history_yields_nothing(tmp_path):
    repo = tmp_path / "clean"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "harmless")

    outcome = scan_git_history(repo)
    assert outcome.findings == []


def test_cli_git_history_reports_and_gates(tmp_path):
    repo, sha = _repo_with_removed_secret(tmp_path)

    # AWS key is CRITICAL: the default --fail-on high must gate on it.
    gated = runner.invoke(app, ["scan", str(repo), "--no-ai", "--git-history"])
    assert gated.exit_code == 1

    result = runner.invoke(app, ["scan", str(repo), "--no-ai", "--git-history", "--fail-on", "never"])
    assert result.exit_code == 0
    report = (repo / "security-report.md").read_text(encoding="utf-8")
    assert f"config.py @ {sha[:12]}" in report


def test_cli_git_history_outside_a_repo_exits_2(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--git-history"])
    assert result.exit_code == 2


def test_cli_git_history_rejects_watch_and_baselines(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    for extra in (["--watch"], ["--write-baseline"], ["--baseline", "x.json"]):
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-ai", "--git-history", *extra])
        assert result.exit_code == 2
