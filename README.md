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

One scan, three views — choose with `--format` (`-f`):

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
```

The same engine powers all three — Scout finds the problem; your own AI (which already knows your codebase) applies the fix.

## Use as a CI Gate

`scout scan` exits **1** when findings at or above `--fail-on` (default: `high`) exist, so your pipeline fails on real problems:

```bash
scout scan . --fail-on high        # default — fail on HIGH or CRITICAL findings
scout scan . --fail-on critical    # fail only on CRITICAL
scout scan . --fail-on never       # report-only mode — always exit 0
```

## What It Finds

| Scanner | Detects | Severity |
|---------|---------|----------|
| `secrets` | AWS keys, GitHub tokens, Stripe keys, DB URLs, private keys, passwords | CRITICAL |
| `injection` | SQL injection, command injection, eval(), XSS | CRITICAL |
| `headers` | Missing helmet, wildcard CORS, no CSP | HIGH |
| `deps` | Known vulnerabilities in pinned pip dependencies (via OSV.dev) | HIGH |

## Example Output

```
$ scout scan ./my-app

Scout v0.1.4 scanning: ./my-app

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

## Roadmap: AI Confirmation Pass (not yet implemented)

The CLI reserves `--model` / `--ollama-model` / `--no-ai` flags for a planned optional pass that double-checks findings with an AI provider (Anthropic, OpenAI, or local Ollama) to cut false positives further. **It is not implemented yet** — today every scan is 100% static: deterministic, offline, zero tokens. When it ships, it will remain optional and off by default; the core scan will never require an API key.

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