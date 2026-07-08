---
description: Scan a path with Scout and walk through the security findings.
argument-hint: "[path]"
---

Run Scout on `$ARGUMENTS` (default: current directory). Prefer the `scan_path`
MCP tool if available; otherwise run `scout scan $ARGUMENTS --format ai-prompt`.
Summarize findings by severity, then for each finding propose and (with my
confirmation) apply the fix, and re-scan to confirm it's resolved.
