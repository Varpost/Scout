# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Scout, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. Email: **tejaswiraj@proton.me** (replace with your actual contact)
3. Or use GitHub's [private vulnerability reporting](https://github.com/tejaswirajgit/Scout/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgement:** Within 48 hours
- **Initial assessment:** Within 1 week
- **Fix or mitigation:** Within 2 weeks for critical issues

## Security Measures

Scout implements the following security practices:

- **No `eval()` or `exec()` on user input** — all analysis uses AST parsing and regex
- **No `shell=True`** — subprocess calls use list-form arguments only
- **No secrets in code** — API keys loaded from environment variables only
- **Path traversal prevention** — all file paths validated with `Path.resolve()` and `.is_relative_to()`
- **Dependency scanning** — automated via Dependabot and pip-audit in CI
- **Code scanning** — GitHub CodeQL runs on every push and weekly
- **Secret scanning** — GitHub secret scanning enabled on this repository

## Dependencies

Scout's core has minimal dependencies to reduce attack surface:

- `typer` — CLI framework
- `rich` — Terminal output
- `python-dotenv` — Environment variable loading
- `gitpython` — Git operations
- `jinja2` — Report templating

AI dependencies (`anthropic`, `openai`) are optional extras installed only when needed.
