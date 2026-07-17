<!-- mcp-name: io.github.Varpost/scout -->
# Scout

**AI security team in a CLI.** Find vulnerabilities before hackers do — free, local, no signup.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/scout-security)](https://pypi.org/project/scout-security/)

---

## Why Scout?

AI coding assistants write insecure code constantly — hardcoded secrets, SQL injection, missing auth. Solo developers ship it because they don't have a security team.

**Scout is that team.** Static analysis catches the most common mistakes AI assistants make — leaked keys, string-built SQL, `shell=True`, missing security headers. No API keys, no config, no cost.

## Install

Zero-install — try it in one command with [uv](https://docs.astral.sh/uv/) (no venv, ~1s cold start):

```bash
uvx scout-security scan ./my-project
```

Or install it permanently:

```bash
pip install scout-security
```

> **Using NCC ScoutSuite too?** It also installs a `scout` command, and whichever package you installed last owns the name. Scout additionally installs **`scoutsec`** — same tool, collision-proof name: `scoutsec scan ./my-project`.

## Usage

```bash
# Scan a project — deterministic static analysis: no API keys, no tokens, no signup
scout scan ./my-project

# Turn the findings into ready-to-paste fix prompts for your AI assistant
scout scan ./my-project --format ai-prompt
```

## Output Formats

One scan, four views — choose with `--format` (`-f`):

```bash
# Layer 1 — human-readable Markdown report (default)
scout scan ./my-app
scout scan ./my-app -o security-report.md

# Layer 2 — ready-to-paste prompts for your own AI (Cursor, Claude, Copilot…)
scout scan ./my-app --format ai-prompt          # writes security-prompts.md
scout scan ./my-app --format ai-prompt -o prompts.md

# Layer 3 — machine-readable JSON for piping into agentic tooling / CI
scout scan ./my-app --format json               # prints JSON to stdout
scout scan ./my-app --format json -o report.json
scout scan ./my-app --format json | jq '.findings[]'

# Layer 4 — SARIF 2.1.0 for GitHub Code Scanning (PR annotations)
scout scan ./my-app --format sarif -o scout.sarif
```

The same engine powers all of them — Scout finds the problem; your own AI (which already knows your codebase) applies the fix.

## Use as a CI Gate

`scout scan` exits **1** when findings at or above `--fail-on` (default: `high`) exist, so your pipeline fails on real problems:

```bash
scout scan . --fail-on high        # default — fail on HIGH or CRITICAL findings
scout scan . --fail-on critical    # fail only on CRITICAL
scout scan . --fail-on never       # report-only mode — always exit 0
```

The GitHub Action wraps install + scan + SARIF upload, so findings show up as PR annotations via GitHub Code Scanning:

```yaml
jobs:
  scout:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: Varpost/Scout@v0.1.7
        with:
          fail-on: high            # also: path, format, upload-sarif
```

Prefer plain steps? The same thing by hand (the job still needs `security-events: write`):

```yaml
- run: |
    pip install scout-security
    scout scan . --no-ai --format sarif -o scout.sarif --fail-on never
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: scout.sarif
```

## Pre-commit Hook

Catch findings before they're ever committed:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Varpost/Scout
    rev: v0.1.7        # use the latest tag
    hooks:
      - id: scout
```

The hook runs `scout scan . --no-ai --fail-on high` from your repo root on every commit, so your `[tool.scout]` config applies. Tune the threshold with `args: ["--fail-on", "critical"]`. When it fails, Scout writes `security-report.md` with the details — worth adding to your `.gitignore`.

## Suppressing Findings

Silence a false positive with a trailing comment on the flagged line:

```python
result = eval(trusted_expression)  # scout: ignore
result = eval(trusted_expression)  # scout: ignore[injection]
```

Bare `scout: ignore` silences every finding on that line. The scoped form silences only the named scanner (`secrets`, `injection`, `headers`, `deps`) or finding id (e.g. `injection/eval_usage` — the `id` field in `--format json`). Findings that can't carry an inline comment — the app-wide CSRF check has no meaningful line, and lockfile findings live in generated JSON — are handled by turning the scanner off via `[tool.scout] scanners` (below) or accepting them into a baseline (below).

## Configuration

Skip paths with `--exclude` (repeatable; relative to the scan root, globs allowed):

```bash
scout scan . --exclude tests/fixtures --exclude "*.min.js"
```

Or set project defaults in `pyproject.toml` — Scout reads `[tool.scout]` from the scanned project:

```toml
[tool.scout]
exclude = ["tests/fixtures", "vendor"]   # paths or glob patterns to skip
scanners = ["secrets", "injection"]      # run a subset: secrets, injection, headers, deps
engines = ["semgrep"]                    # external engines to run and merge (optional)
fail_on = "medium"                       # default threshold for --fail-on
```

CLI flags win: `--exclude` replaces the config list, `--engine` replaces `engines`, and `--fail-on` overrides `fail_on`.

## External Engines (optional)

Scout can orchestrate industrial OSS engines and merge their findings into its report, JSON, and SARIF output — same phased remediation plan, wider coverage:

```bash
pip install semgrep                # or brew install semgrep
scout scan . --engine semgrep      # native scanners + semgrep, merged & deduped
```

Engines are strictly opt-in: the default scan stays zero-dependency and fully deterministic. A requested engine that isn't installed is skipped with a one-line note — never a crash. Engine findings that land on a line a native scanner already flagged are dropped in favor of Scout's own fix guidance.

## Adopting Scout on an Existing Codebase (Baseline)

Don't want to fix years of findings before turning the CI gate on? Accept the current state, then fail only on new findings:

```bash
scout scan . --write-baseline                   # accept current findings → .scout-baseline.json
scout scan . --baseline .scout-baseline.json   # report and fail only on NEW findings
```

Commit `.scout-baseline.json`. Finding identity is content-based — the rule, the file, and a hash of the flagged line, deliberately **no line numbers** — so baselined findings stay accepted when unrelated edits shift them up or down a file. Changing the flagged line itself brings the finding back for review.

## Scanning Git History for Secrets

A secret committed and later removed is still compromised — a scan of today's code can't see it:

```bash
scout scan . --git-history        # secrets in every added line of every commit, all branches
```

Findings are anchored to the commit that introduced them (`config.py @ 1a2b3c4d5e6f`) — **rotate anything it reports**; deleting the line doesn't un-leak the credential. Needs `git` on PATH; scans history *instead of* the working tree.

Honest scope: [Gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) do deep, fast history auditing as their core job — Scout's pass is the built-in convenience, not a replacement.

## What It Finds

| Scanner | Detects | Severity |
|---------|---------|----------|
| `secrets` | AWS/Google keys, GitHub/GitLab tokens, Anthropic & OpenAI keys, Slack/npm/PyPI tokens, Stripe keys, DB URLs, private keys, passwords | CRITICAL |
| `injection` | SQL injection, command injection, eval(), XSS | CRITICAL |
| `headers` | Missing security headers (Express/Flask/Django/FastAPI), wildcard CORS, missing CSRF | LOW–MEDIUM |
| `deps` | Known vulnerabilities in pip + npm dependencies (via OSV.dev) | HIGH |

### Language scope

Deep analysis — **injection** (SQL/command/XSS) and **security headers** — targets **Python and JS/TS**, where the detection patterns are idiom-specific. **Secret detection is language-agnostic**: it runs on every common source and config file Scout collects (Go, Java, Ruby, PHP, C/C++, Rust, shell, `.env`, `Dockerfile`, `docker-compose`, Terraform, …), so a hardcoded key is caught whatever language leaked it. Dependency scanning covers `requirements.txt` and `package-lock.json`.

## Example Output

```
$ scout scan ./my-app

Scout v0.1.7 scanning: ./my-app

  Scanning 47 files...

Found 6 issues:

  🔴 2 critical
  🟠 3 high
  🟡 1 medium

Report written to: ./my-app/security-report.md
```

The report includes:
- Every vulnerability explained in plain English
- Severity ratings with context (why it's dangerous)
- Exact fix instructions for each issue
- Phased remediation plan (zero-risk fixes first)

## Optional: AI Confirmation Pass

**The core scan is always static, deterministic, offline, and zero-token — same scan, same findings, no API key.** That is the default and it never changes.

If you want an extra false-positive filter, Scout can optionally send *only the flagged snippet* (never whole files) of each heuristic finding to an AI provider, which can **downgrade** its severity or **dismiss** it as a false positive. Dependency (OSV) and project-level findings are deterministic facts and are never second-guessed. Any provider error leaves findings untouched — the pass fails open, so it can never hide a real issue.

It is **off by default**. Enable it per run:

```bash
# Anthropic (needs ANTHROPIC_API_KEY) — uses the cheap Haiku tier by default
scout scan . --model anthropic

# OpenAI (needs OPENAI_API_KEY)
scout scan . --model openai

# Local Ollama (no key, no cloud) — nothing leaves your machine
scout scan . --model ollama --ollama-model llama3
```

Provider resolution is `--model` > `SCOUT_AI_PROVIDER` env > `none`. Override the model per provider with `SCOUT_AI_MODEL`. `--no-ai` forces the pass off regardless of config. Install the SDKs with `pip install "scout-security[ai]"` (Ollama needs no extra).

## MCP Server (agent verifier)

Run Scout as an [MCP](https://modelcontextprotocol.io) tool your coding agent can call in a scan → fix → rescan loop — deterministic, offline, zero-token, no inference cost. Scout finds it; your agent fixes it; Scout re-verifies.

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Scout_MCP-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect/mcp/install?name=scout&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22--from%22%2C%22scout-security%5Bmcp%5D%22%2C%22scout-mcp%22%5D%7D)
[![Add to Cursor](https://img.shields.io/badge/Cursor-Add_Scout_MCP-111111?style=flat-square&logoColor=white)](https://varpost.github.io/Scout/#ai-assistant)

*(GitHub strips `cursor://` deep links, so the Cursor badge goes via the site's one-click button.)*

### Install as a Claude Code plugin

The one-command path — the plugin bundles the MCP server, so no separate `claude mcp add` is needed:

```text
/plugin marketplace add Varpost/Scout
/plugin install scout@scout
```

That registers the `scan_path` tool and a `/scout-scan [path]` command. Requires [uv](https://docs.astral.sh/uv/) on your PATH — the plugin launches the server with `uvx` (first run downloads the package; later runs hit the cache). No uv? Use the manual setup below with `pip install "scout-security[mcp]"` and `"command": "scout-mcp"` instead.

### Manual setup (any MCP host)

Every MCP host takes the same server definition — zero-install via [uv](https://docs.astral.sh/uv/):

```json
{
  "mcpServers": {
    "scout": {
      "command": "uvx",
      "args": ["--from", "scout-security[mcp]", "scout-mcp"]
    }
  }
}
```

No uv? `pip install "scout-security[mcp]"`, then use `"command": "scout-mcp"` with no `args`.

Where that definition goes:

| Host | Where |
|------|-------|
| **Claude Code** | The [plugin](#install-as-a-claude-code-plugin) above, or `claude mcp add scout -- uvx --from "scout-security[mcp]" scout-mcp` |
| **Cursor** | `.cursor/mcp.json` in your project, or `~/.cursor/mcp.json` for all projects |
| **Claude Desktop** | `claude_desktop_config.json` (Settings → Developer → Edit Config) |
| **Cline** | `cline_mcp_settings.json` (MCP Servers → Configure MCP Servers) |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` |
| **VS Code** (native MCP) | `.vscode/mcp.json` — same server object, but under a `"servers"` key instead of `"mcpServers"` |

It exposes one tool — **`scan_path(path)`** — returning the same Layer-3 JSON as `--format json` (findings with file, line, severity, stable id, explanation, and fix guidance). Point the agent's fix loop at it and call again to confirm the issue is gone.

## Using Scout with Your AI Assistant

The whole idea in one line: **Scout finds deterministically → your AI fixes → Scout re-verifies.** Same scan, same findings, zero tokens on every pass — so re-checking a fix never costs inference. Pick the surface that matches how you work; all three run the same engine.

### 1. You + a chat assistant (Claude, Cursor, Copilot Chat)

```bash
scout scan . --format ai-prompt      # writes security-prompts.md
```

Open `security-prompts.md` and paste a block into your assistant. Each one is self-contained — the finding, the fix, and an instruction to sweep the rest of your code for the same class of issue. After it edits, re-verify:

```bash
scout scan .                         # clean? the loop is closed
```

### 2. An agent that calls Scout itself (Claude Code, Cursor Agent)

Wire up the [MCP server](#mcp-server-agent-verifier), then hand the agent the loop:

> Scan this project with Scout, fix every finding, then scan again — repeat until it reports zero.

The agent calls `scan_path`, applies fixes, and calls again. Scout is the deterministic, zero-token verifier *inside* the loop, so each re-check is free.

### 3. CI / pre-commit (make the loop mandatory)

Turn the loop into a gate — the build fails until findings are fixed:

```bash
scout scan . --fail-on high          # exit 1 on HIGH+ findings
```

See [Use as a CI Gate](#use-as-a-ci-gate) for the GitHub Action and [Pre-commit Hook](#pre-commit-hook) to catch findings before they're committed. Adopting on an existing repo? A [baseline](#adopting-scout-on-an-existing-codebase-baseline) accepts today's findings and fails only on new ones.

## Add a Custom Scanner

```python
from scout.scanners import register_scanner
from scout.scanners.base import BaseScanner
from scout.models import Finding
from pathlib import Path

@register_scanner
class MyScanner(BaseScanner):
    name = "my-scanner"
    description = "Detects my custom pattern"

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        findings = []
        # detection logic here
        return findings
```

Add one import in `scout/scanners/__init__.py` → done.

## Development

```bash
git clone https://github.com/Varpost/Scout.git
cd Scout
pip install -e ".[dev,ai]"
pytest
ruff check scout/ tests/
```

## Documentation

Full docs and interactive guide: [https://varpost.github.io/Scout/](https://varpost.github.io/Scout/)

## License

MIT — free forever.