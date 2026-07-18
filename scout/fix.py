"""Deterministic, human-confirmed fixes for phase-1 findings (`scout fix`).

Scope is deliberately the mechanical, zero-risk class only: a hardcoded
secret in a Python file becomes an ``os.environ`` lookup (value moved to a
gitignored ``.env``), and a vulnerable ``requirements.txt`` pin is bumped to
the first fixed release OSV reported. Everything else stays advice — no AI
in the edit path, no edits without a shown diff and an explicit yes.
"""

from __future__ import annotations

import difflib
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from scout.models import Finding

# `NAME = "value"` / `NAME: str = "value"` — the assignment shapes the secret
# fix can rewrite mechanically. Group 1 indent, 2 name, 3 quote, 4 value.
_SECRET_ASSIGNMENT = re.compile(r"""^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(['"])(.+?)\3\s*$""")

# The deps scanner's own fix_summary format: "Upgrade <name> to >=<version>".
_DEP_UPGRADE = re.compile(r"^Upgrade (?P<name>\S+) to >=(?P<version>\S+)$")

_IMPORT_LINE = re.compile(r"^(?:import|from)\s+\w")


@dataclass
class FileEdit:
    """One whole-file replacement produced by a fix."""

    path: Path
    new_content: str


@dataclass
class FixProposal:
    """A confirmed-by-diff fix for a single finding.

    Attributes:
        finding: The finding being fixed.
        summary: One-line description shown above the diff.
        edits: File replacements to apply on confirm (first edit is the
            flagged file itself).
        warning: Printed after applying (e.g. rotate-the-credential).
    """

    finding: Finding
    summary: str
    edits: list[FileEdit] = field(default_factory=list)
    warning: str = ""


def _newline_of(text: str) -> str:
    """Preserve the file's dominant newline style (CRLF survives a fix)."""
    return "\r\n" if "\r\n" in text else "\n"


def _read(path: Path) -> str | None:
    try:
        # newline="" keeps \r\n intact — read_text would normalize it away
        # and every fix would silently rewrite the file's line endings.
        with path.open(encoding="utf-8", newline="") as handle:
            return handle.read()
    except OSError:
        return None


def _plan_secret_fix(finding: Finding, root: Path) -> FixProposal | None:
    """Rewrite ``NAME = "secret"`` in a .py file to an os.environ lookup.

    The secret value moves to ``<root>/.env`` (created if needed) and
    ``.env`` is ensured in ``<root>/.gitignore`` — the exact remediation the
    finding's own fix_summary prescribes.
    """
    path = Path(finding.file)
    if path.suffix.lower() != ".py":
        return None
    content = _read(path)
    if content is None:
        return None
    nl = _newline_of(content)
    lines = content.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        return None
    match = _SECRET_ASSIGNMENT.match(lines[finding.line - 1])
    if match is None:
        return None  # not a plain assignment — too risky to rewrite blind
    indent, name, _quote, value = match.groups()
    env_name = name.upper()

    lines[finding.line - 1] = f'{indent}{name} = os.environ["{env_name}"]'
    if not any(
        line == "import os" or line.startswith(("import os ", "import os.", "from os import")) for line in lines
    ):
        # ponytail: insert before the first import (or at the top) — no
        # docstring-aware placement until a real file trips this up.
        at = next((i for i, line in enumerate(lines) if _IMPORT_LINE.match(line)), 0)
        lines.insert(at, "import os")
    edits = [FileEdit(path, nl.join(lines) + (nl if content.endswith(("\n", "\r\n")) else ""))]

    env_path = root / ".env"
    env_content = _read(env_path) or ""
    env_nl = _newline_of(env_content) if env_content else nl
    if env_content and not env_content.endswith(("\n", "\r\n")):
        env_content += env_nl
    edits.append(FileEdit(env_path, f"{env_content}{env_name}={value}{env_nl}"))

    gitignore_path = root / ".gitignore"
    gitignore = _read(gitignore_path) or ""
    if ".env" not in {line.strip() for line in gitignore.splitlines()}:
        gi_nl = _newline_of(gitignore) if gitignore else nl
        if gitignore and not gitignore.endswith(("\n", "\r\n")):
            gitignore += gi_nl
        edits.append(FileEdit(gitignore_path, f"{gitignore}.env{gi_nl}"))

    return FixProposal(
        finding=finding,
        summary=f"{finding.title}: move `{name}` to the environment (.env entry `{env_name}`, gitignored)",
        edits=edits,
        warning=(
            "The credential was committed to source — moving it does not un-leak it. Rotate it with the provider."
        ),
    )


def _plan_dep_fix(finding: Finding, root: Path) -> FixProposal | None:
    """Bump a vulnerable ``requirements.txt`` exact pin to the fixed version."""
    path = Path(finding.file)
    if path.name != "requirements.txt":
        return None  # npm lockfiles are generated — `npm audit fix` owns those
    upgrade = _DEP_UPGRADE.match(finding.fix_summary)
    if upgrade is None:
        return None  # no concrete fixed version known — nothing mechanical to do
    content = _read(path)
    if content is None:
        return None
    nl = _newline_of(content)
    lines = content.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        return None
    name, version = upgrade.group("name"), upgrade.group("version")
    pin = re.compile(rf"^(\s*){re.escape(name)}(\[[^\]]*\])?\s*==\s*\S+", re.IGNORECASE)
    match = pin.match(lines[finding.line - 1])
    if match is None:
        return None  # line moved since the scan — refuse rather than guess
    lines[finding.line - 1] = f"{match.group(1)}{name}{match.group(2) or ''}=={version}"
    return FixProposal(
        finding=finding,
        summary=f"{finding.title}: pin {name}=={version} (first fixed release)",
        edits=[FileEdit(path, nl.join(lines) + (nl if content.endswith(("\n", "\r\n")) else ""))],
        warning=f"Run your test suite — {name} {version} may contain other changes.",
    )


def plan_fixes(findings: list[Finding], root: Path) -> list[FixProposal]:
    """Build proposals for every finding with a known mechanical fix.

    Args:
        findings: Findings from a scan that just ran (line numbers fresh).
        root: Project root — anchors .env and .gitignore side effects.

    Returns:
        Proposals in finding order; findings without a safe mechanical fix
        are simply absent.
    """
    proposals = []
    for finding in findings:
        if finding.fix_phase != 1 or finding.project_level:
            continue
        planner = _plan_secret_fix if finding.scanner == "secrets" else None
        planner = _plan_dep_fix if finding.scanner == "deps" else planner
        if planner is None:
            continue
        proposal = planner(finding, root)
        if proposal is not None:
            proposals.append(proposal)
    return proposals


def render_diff(proposal: FixProposal) -> str:
    """Unified diff over every file the proposal touches (new files included)."""
    chunks: list[str] = []
    for edit in proposal.edits:
        current = _read(edit.path) or ""
        rel = edit.path.name if current == "" and not edit.path.exists() else str(edit.path)
        diff = difflib.unified_diff(
            current.splitlines(),
            edit.new_content.splitlines(),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
            lineterm="",
        )
        chunks.append("\n".join(diff))
    return "\n".join(chunk for chunk in chunks if chunk)


def apply_fix(proposal: FixProposal) -> None:
    """Write every edit atomically (temp file + replace, per file)."""
    for edit in proposal.edits:
        fd, tmp_name = tempfile.mkstemp(dir=str(edit.path.parent), suffix=".scout-tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(edit.new_content)
            os.replace(tmp_name, edit.path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise


def verify_fix(proposal: FixProposal) -> bool:
    """Re-scan the fixed file: True when the original finding is gone.

    Deps findings are verified textually (the pin line changed) — re-querying
    OSV for one line is network cost with no new information.
    """
    finding = proposal.finding
    path = Path(finding.file)
    content = _read(path)
    if content is None:
        return False
    if finding.scanner == "deps":
        lines = content.splitlines()
        return finding.line <= len(lines) and lines[finding.line - 1] != finding.snippet
    from scout.scanners import get_all_scanners

    scanner_cls = next((cls for cls in get_all_scanners() if cls.name == finding.scanner), None)
    if scanner_cls is None:  # pragma: no cover — scanner registry always has it
        return False
    remaining = scanner_cls().scan_file(path, content)
    return not any(f.line == finding.line and f.title == finding.title for f in remaining)
