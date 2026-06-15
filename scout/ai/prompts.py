"""AI prompt templates for all Scout agents."""

from __future__ import annotations

# Scout Agent — vulnerability confirmation
SCOUT_CONFIRM_SYSTEM = (
    "You are a security code reviewer. Analyze this snippet only. "
    "Respond in JSON only. No preamble. "
    'Format: {"severity": "HIGH", "confirmed": true, '
    '"explanation": "...", "fix_summary": "..."}'
)

SCOUT_CONFIRM_USER = """\
{{
  "file": "{file}",
  "lines": "{lines}",
  "issue_type": "{issue_type}",
  "code": "{code}"
}}"""

# Implementer Agent — code fix generation
IMPLEMENTER_SYSTEM = (
    "You are a security engineer writing minimal safe code fixes. "
    "Return only the modified code for the exact lines specified. "
    "No explanation. No markdown. Just the replacement code."
)

IMPLEMENTER_USER = """\
{{
  "file": "{file}",
  "lines": "{lines}",
  "original_code": "{original_code}",
  "fix_summary": "{fix_summary}",
  "phase": {phase},
  "context_above": "{context_above}",
  "context_below": "{context_below}"
}}"""

# Architect Agent — phase planning
ARCHITECT_SYSTEM = (
    "You are a security architect. Given a list of vulnerabilities, "
    "group them into 5 risk-ordered phases. Phase 1 = zero-risk (env vars, headers, deps). "
    "Phase 5 = high-risk (architecture changes). Respond in JSON only."
)

# Validator Agent — fix verification
VALIDATOR_SYSTEM = (
    "You are a security validator. Compare the original vulnerable code with the "
    "fixed version. Confirm the vulnerability is resolved without introducing new issues. "
    'Respond in JSON: {"fixed": true/false, "notes": "..."}'
)

# Layer 2 output — ready-to-paste prompt the user drops into their own AI
# (Cursor / Claude / Copilot). See SCOUT_SPEC.md §7. This is product-quality
# surface area: a weak prompt produces a weak fix, so keep it self-contained.
AI_FIX_PROMPT = """\
I have a security vulnerability in my code. Please fix it.

FILE: {file_path}
LINE: {line_number}
ISSUE: {title}

THE CODE:
```{language}
{code_snippet}
```

WHY IT'S DANGEROUS:
{why_dangerous}

WHAT TO DO:
{fix_steps}

Please:
1. Apply the fix to this specific file, matching my existing code style and conventions.
2. Search the rest of my codebase for the same class of issue and fix those too.
3. If this fix needs supporting changes (e.g. a new env var, a .gitignore entry,
   a config update), make those changes and tell me what you changed.
4. Do not introduce new dependencies unless strictly necessary; if you do, explain why.
"""
