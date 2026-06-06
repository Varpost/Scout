# Scout Quality Audit Roadmap

## Goal

Add an optional quality audit mode to Scout that checks maintainability, dead code, duplication, complexity, dependency risk, and common AI-generated code issues across popular languages.

This should complement `scout scan`, not replace it. `scout scan` stays focused on security findings. The new quality mode should help users answer:

- Which files look unused?
- Where is code duplicated?
- Which files are too complex?
- Which dependencies are risky?
- Which tool should be used for this project language?

## Proposed Commands

```powershell
scout quality .
scout quality . --format json
scout audit .
```

`scout quality` should run maintainability and cleanup tools.

`scout audit` should run security, secrets, dependencies, and quality checks together.

## Tool Strategy

Use the best tool for each language instead of forcing one tool to handle everything.

| Area | Tool | Language / Scope |
| --- | --- | --- |
| Dead code, duplication, health | Fallow | JavaScript, TypeScript |
| Linting and basic quality | Ruff | Python |
| Python dead code | Vulture | Python |
| Python complexity | Radon | Python |
| Python security | Bandit | Python |
| Multi-language security rules | Semgrep | Many languages |
| Secret scanning | Gitleaks | Any repository |
| Dependency vulnerabilities | pip-audit, npm audit, osv-scanner | Python, Node, many ecosystems |
| Container and IaC risk | Trivy | Docker, Terraform, dependencies |
| Advanced code scanning | CodeQL | Major languages |

## Phase 1: Project Detection

Add lightweight project detection before running external tools.

Detect:

- Python: `pyproject.toml`, `requirements.txt`, `setup.py`, `.py`
- JavaScript / TypeScript: `package.json`, `.js`, `.ts`, `.tsx`
- Docker: `Dockerfile`, `docker-compose.yml`
- Terraform: `.tf`
- Git repo: `.git`

Output a small language summary:

```text
Detected:
- Python
- JavaScript fixtures
- Git repository
```

## Phase 2: Tool Runner Abstraction

Create a common interface for external tools.

Each tool runner should define:

- Tool name
- Install check command
- Run command
- Supported languages
- Parser for output
- Severity mapping
- Whether the tool is optional or required

Example internal shape:

```python
class QualityTool:
    name: str
    supported_languages: set[str]

    def is_available(self) -> bool:
        ...

    def run(self, path: Path) -> list[Finding]:
        ...
```

## Phase 3: Python Quality Support

Start with Python because Scout is currently a Python project.

Recommended first tools:

- `ruff check .`
- `vulture scout tests`
- `radon cc scout -a`
- `bandit -r scout`

Convert output into Scout findings with consistent fields:

- Title
- Description
- File path
- Line number when available
- Severity
- Tool name
- Suggested fix

## Phase 4: JavaScript / TypeScript Quality Support

Use Fallow only when JS/TS files exist.

Run:

```powershell
npx --yes fallow
npx --yes fallow dead-code
npx --yes fallow dupes
npx --yes fallow health
```

Important behavior:

- Do not report Fallow warnings as Scout issues when the repo is primarily Python.
- Respect `.fallowrc.json` when present.
- If no `package.json` exists, explain that JS dependency accuracy may be limited.

## Phase 5: Multi-language Security Tools

Add optional integrations:

- Semgrep for broad security rules.
- Gitleaks for secrets.
- OSV Scanner for dependency vulnerabilities.
- Trivy for containers, IaC, and dependency risk.

These should be opt-in or clearly labeled because they may require installation, network access, or longer runtime.

## Phase 6: Report Format

Add a quality section to Scout reports:

```text
Quality Audit

Health:
- Maintainability: good
- Duplication: none found
- Dead code: none found

Tool Results:
- Ruff: 0 issues
- Vulture: 1 possible unused function
- Radon: average complexity A
- Fallow: no JS/TS duplicate code
```

JSON output should include raw tool metadata so users can debug false positives.

## Product Rules

- Keep Scout security findings separate from quality findings.
- Do not delete files automatically unless the user explicitly asks.
- Prefer warnings and explanations over destructive fixes.
- Make external tools optional.
- Run only tools relevant to the detected project.
- Clearly show when a tool is missing and how to install it.

## First Implementation Target

Build `scout quality .` for Python only:

1. Detect Python project.
2. Run Ruff if installed.
3. Run Vulture if installed.
4. Run Radon if installed.
5. Print a simple terminal summary.
6. Add JSON output later.

After that, add Fallow support for JS/TS projects.
