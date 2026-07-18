# Scout Security — VS Code extension

Inline security diagnostics from [Scout](https://github.com/Varpost/Scout)
(`scout-security` on PyPI): red squiggles for hardcoded secrets, SQL/NoSQL
injection, command injection, XSS, and vulnerable dependencies — on every
save. Free, local, deterministic; no account, no server, no tokens.

## Requirements

```bash
pip install scout-security
```

The extension shells out to the `scoutsec` CLI (the collision-proof name the
package installs alongside `scout`). If your install exposes a different
name or path, set `scout.executable`.

## Features

- **Scan on save** — saving a Python/JS/TS file runs Scout on just that file
  (sub-second) and shows findings inline. Toggle with `scout.scanOnSave`.
- **Scan Workspace** command — full scan of the project, findings across all
  files in the Problems panel.
- **Taint verdicts** — findings the scanner can trace to user input
  (`req.body`, `location.hash`, `request.args`, …) are marked
  `[reachable from user input]`.
- Severity mapping: CRITICAL/HIGH → Error, MEDIUM → Warning, LOW → Info.
- Your project's `[tool.scout]` configuration (excludes, scanner subset,
  custom rules) applies as usual.

## Settings

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `scout.executable` | `scoutsec` | CLI to invoke |
| `scout.scanOnSave` | `true` | scan the saved file automatically |

## Development

```bash
npm install
npm test          # compiles + unit-tests the finding→diagnostic mapper
```

Press F5 in VS Code with this folder open to launch an Extension Development
Host. Package with `npx vsce package` (needs a Marketplace publisher).
