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
      - uses: Varpost/Scout@v0.1.15
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
    rev: v0.1.15        # use the latest tag
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

Bare `scout: ignore` silences every finding on that line. The scoped form silences only the named scanner (`secrets`, `injection`, `headers`, `deps`, `custom`) or finding id (e.g. `injection/eval_usage` — the `id` field in `--format json`). Findings that can't carry an inline comment — the app-wide CSRF check has no meaningful line, and lockfile findings live in generated JSON — are handled by turning the scanner off via `[tool.scout] scanners` (below) or accepting them into a baseline (below).

## Configuration

Skip paths with `--exclude` (repeatable; relative to the scan root, globs allowed):

```bash
scout scan . --exclude tests/fixtures --exclude "*.min.js"
```

Or set project defaults in `pyproject.toml` — Scout reads `[tool.scout]` from the scanned project:

```toml
[tool.scout]
exclude = ["tests/fixtures", "vendor"]   # paths or glob patterns to skip
scanners = ["secrets", "injection"]      # run a subset: secrets, injection, headers, deps, custom
engines = ["semgrep"]                    # external engines to run and merge (optional)
rules = ["scout-rules.yml"]              # your own YAML detection rules (optional)
fail_on = "medium"                       # default threshold for --fail-on
```

CLI flags win: `--exclude` replaces the config list, `--engine` replaces `engines`, and `--fail-on` overrides `fail_on`.

## Custom Rules (optional)

Teach Scout project-specific patterns with a YAML file — an id, a regex, a message, a severity:

```yaml
# scout-rules.yml — referenced from [tool.scout] rules
rules:
  - id: internal-api-host
    pattern: "internal\\.corp\\.example"
    message: "Internal hostname committed to source."
    severity: HIGH          # CRITICAL | HIGH | MEDIUM | LOW
    fix_phase: 1            # optional, 1-5 (default 3)
    suffixes: [".py", ".ts"] # optional — default: every scanned file
    fix: "Move the hostname to configuration."
```

Rules are deliberately grep-with-metadata — need metavariables or taint analysis? That's what `--engine semgrep` is for. A malformed rule warns on stderr and is skipped; it can never break the scan. Custom findings work everywhere native ones do: `scout: ignore[custom]`, baselines, severity gating, JSON/SARIF.

## External Engines (optional)

Scout can orchestrate industrial OSS engines and merge their findings into its report, JSON, and SARIF output — same phased remediation plan, wider coverage:

```bash
pip install semgrep                # or brew install semgrep
scout scan . --engine semgrep      # native scanners + semgrep, merged & deduped

# CodeQL — GitHub's semantic analysis engine (CLI from
# https://github.com/github/codeql-cli-binaries, on PATH as `codeql`)
scout scan . --engine codeql       # builds a CodeQL DB per language (python/js),
                                   # runs the official security queries, merges the SARIF
```

`--engine codeql` runs the same query suite GitHub code scanning uses, so a Scout report can carry full semantic-analysis findings — expect it to take minutes, not seconds (database extraction is CodeQL's design, not Scout overhead).

Engines are strictly opt-in: the default scan stays zero-dependency and fully deterministic. A requested engine that isn't installed is skipped with a one-line note — never a crash. Engine findings that land on a line a native scanner already flagged are dropped in favor of Scout's own fix guidance.

## VS Code Extension

[scout-vscode/](scout-vscode/) wraps the CLI as a VS Code extension: saving a Python/JS/TS file scans just that file (sub-second) and shows findings as inline squiggles, with taint-traced ones marked *reachable from user input*. A **Scout: Scan Workspace** command fills the Problems panel for the whole project. It shells out to `scoutsec`, so your `[tool.scout]` config applies unchanged.

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
| `injection` | SQL injection, NoSQL operator injection, command injection, eval()/Function/vm, XSS | CRITICAL |
| `injection` (taint-gated) | Path traversal (file reads/writes, `sendFile`), SSRF (`fetch`/`requests`/`axios`), insecure deserialization (`pickle`/`yaml.load`/`unserialize`), open redirect (`redirect(...)`) — fire only when user input reaches the sink | HIGH |
| `injection` (keyword-gated) | Weak randomness for tokens/secrets (`Math.random`/`random.*` used for a token/password/OTP) | MEDIUM |
| `headers` | Missing security headers (Express/Flask/Django/FastAPI), wildcard CORS, missing CSRF | LOW–MEDIUM |
| `deps` | Known vulnerabilities in pip + npm dependencies (via OSV.dev) | HIGH |

### Language scope

Deep analysis — **injection** (SQL/command/XSS) and **security headers** — targets **Python and JS/TS**, where the detection patterns are idiom-specific. Both languages get intra-file **taint tracking** (Python via the stdlib AST, JS/TS via a lexical pass): findings carry a `reachable` verdict when a sink traces back to user input (`request.*`, `req.body`, `location.hash`, …), ORM/NoSQL sinks fire *only* on taint evidence, and XSS sinks fed by provable in-file constants are dropped instead of reported. The same taint engine powers **path traversal** (`open`/`fs.readFile`/`sendFile`), **SSRF** (`requests`/`fetch`/`axios`), **insecure deserialization** (`pickle`/`yaml.load`/`unserialize`), and **open redirect** (`redirect(...)`) detection — all gated on reachability, so `open("config.json")` and `axios.get("https://api.example.com")` never fire. **Weak randomness** for tokens/secrets (`Math.random`/`random.*`) is keyword-gated instead — flagged only alongside a token/password/OTP name. **Secret detection is language-agnostic**: it runs on every common source and config file Scout collects (Go, Java, Ruby, PHP, C/C++, Rust, shell, `.env`, `Dockerfile`, `docker-compose`, Terraform, …), so a hardcoded key is caught whatever language leaked it. Dependency scanning covers `requirements.txt` and `package-lock.json`.

### Measured accuracy

Scout's injection scanner is measured against 104 real CVEs from the [OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) — real vulnerable commits in real JS/TS projects, no synthetic test cases. Full methodology, caveats, and reproduction steps live in [benchmarks/](benchmarks/); results are versioned per release, and this README only ever cites numbers present in a committed results file.

Honest reading of the [v0.1.13 results](benchmarks/results/0.1.14/summary-native.md): overall recall is **24.7%** at **2.4%** precision — both up release over release (16.5% / 1.3% in v0.1.9). Command injection is the standout at **39.6%** recall (essentially level with CodeQL's published 40% on this corpus), from recognizing `child_process.exec(cmd, callback)` member calls; SQL/NoSQL injection holds at 25% (matching CodeQL) via the JS taint pass. Precision rose because the scanner now skips minified/bundled files — a vuln in a generated bundle is the dependency scanner's job. Adding `--engine semgrep` lifts overall recall to [27.2%](benchmarks/results/0.1.14/summary-native-semgrep.md) (command injection to 41.7%). The false-positive counts are an upper bound by benchmark convention — every unlabeled real `exec()`/sink call counts against Scout. These numbers are published to invite fair comparison and to be improved release over release, not to impress. For how these figures sit against CodeQL, ESLint, and published research on the same corpus, see [benchmarks/COMPARISON.md](benchmarks/COMPARISON.md).

The path-traversal + SSRF (v0.1.12) and deserialization + open-redirect + weak-randomness (v0.1.13) detectors are new vulnerability *classes* (CWE-22/918/502/601/330). The injection figures above are unchanged by them (verified: identical TP/FP/FN). These classes are scored separately against 39 added CVEs. Path traversal went from a 0% baseline (v0.1.13) to **46.9% recall** (v0.1.14) after two first-principles broadenings — the request URL/path (`req.url`) joined the taint sources, and `fs.stat`/`access`/`exists` joined the file-path sinks — now ahead of even the semgrep pass on this class. SSRF, open redirect, and deserialization stay at an honest 0%: reading their CVE flows, the blocker is unrecognized sinks/sources (a `res.setHeader('Location', …)` redirect, a bare `request({uri})` client) and taint through object literals — not function boundaries — and chasing an 11-CVE tail with that breadth would risk more false positives than it's worth. See [benchmarks/COMPARISON.md](benchmarks/COMPARISON.md).

v0.1.15 adds **cross-function taint tracking for Python** (intra-file): a tainted argument to a local helper now taints that helper's parameter, so a `request.args` value flowing through a route handler into `os.system` in a service function is tracked to the sink. This is a real-world win for layered Python apps that the JS-only OpenSSF corpus can't measure — like weak randomness, it stays proven by unit tests rather than a benchmark number.

## Example Output

```
$ scout scan ./my-app

Scout v0.1.15 scanning: ./my-app

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