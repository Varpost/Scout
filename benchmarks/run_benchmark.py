"""Run Scout against the pinned OpenSSF CVE corpus and score precision/recall.

Usage (from the repo root):

    python benchmarks/run_benchmark.py                 # full corpus, native scan
    python benchmarks/run_benchmark.py --limit 10      # quick pass
    python benchmarks/run_benchmark.py --engine semgrep # extra engine-assisted run

First run downloads each pinned repository (shallow, exact commit) into
``benchmarks/corpus/`` (~1-2 GB, gitignored); re-runs reuse the download.
Results are written to ``benchmarks/results/<scout version>/``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

from scout import __version__  # noqa: E402
from scout.agents.scout_agent import run_scout  # noqa: E402
from scout.config import ScoutConfig  # noqa: E402
from scout.models import Finding  # noqa: E402

CORPUS_MANIFEST = BENCH_DIR / "corpus.json"
CORPUS_DIR = BENCH_DIR / "corpus"
RESULTS_DIR = BENCH_DIR / "results"

# A finding counts toward a category only via these title sets — scoring must
# never credit e.g. a secrets finding to an injection CVE.
CATEGORY_TITLES = {
    "sqli": {
        "SQL string concatenation",
        "SQL f-string query",
        "Raw SQL with string format",
        "SQL template literal",
        "SQL raw() with dynamic input",
        "NoSQL query with user-controlled value",
        "SQL query with user-controlled string",
    },
    "cmdi": {
        "shell=True with dynamic command",
        "shell=True with constant command",
        "os.system() call",
        "os.system() with constant command",
        "exec() with template literal",
        "exec() with string concatenation",
        "child_process exec with variable command",
        "child_process exec (member call)",
        "spawn() with shell:true",
        "exec() with user-controlled command",
    },
    "codei": {
        "eval() usage",
        "exec() usage",
        "exec() with template literal",
        "exec() with string concatenation",
        "exec() with user-controlled command",
        "Function constructor with dynamic code",
        "vm.runInContext with dynamic code",
    },
    "xss": {
        "innerHTML assignment",
        "outerHTML assignment",
        "document.write()",  # scout: ignore[injection]
        "insertAdjacentHTML with dynamic content",
        "dangerouslySetInnerHTML with dynamic content",
        "jQuery .html() with dynamic content",
        "Unescaped template output",
    },
    # Classes added post-injection (D5/E1). Single-title categories, taint-gated.
    "pathtrav": {"Path traversal"},
    "ssrf": {"Server-side request forgery (SSRF)"},
    "deserial": {"Insecure deserialization"},
    "openredir": {"Open redirect"},
}
LINE_TOLERANCE = 2


@dataclass
class Tally:
    """TP/FP/FN counts for one category."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    hits: list[str] = field(default_factory=list)
    misses: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, encoding="utf-8", errors="replace", check=False, stdin=subprocess.DEVNULL
    )


def fetch_checkout(entry: dict, dest: Path) -> bool:
    """Shallow-fetch the exact pinned commit; reuse an existing checkout."""
    marker = dest / ".scout-bench-commit"
    if marker.exists() and marker.read_text(encoding="utf-8").strip() == entry["commit"]:
        return True
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    for cmd in (
        ["git", "init", "-q"],
        ["git", "remote", "add", "origin", entry["repository"]],
        ["git", "fetch", "-q", "--depth", "1", "origin", entry["commit"]],
        ["git", "checkout", "-q", "FETCH_HEAD"],
    ):
        proc = _run(cmd, cwd=dest)
        if proc.returncode != 0:
            print(f"  ! {entry['cve']}: {' '.join(cmd[1:3])} failed: {proc.stderr.strip().splitlines()[-1:]}")
            shutil.rmtree(dest, ignore_errors=True)
            return False
    marker.write_text(entry["commit"] + "\n", encoding="utf-8")
    return True


def scan_findings(path: Path, engines: tuple[str, ...]) -> list[Finding]:
    """Run Scout's injection scanner (plus optional engines) over a checkout."""
    config = ScoutConfig(
        ai_provider="none",
        anthropic_key=None,
        openai_key=None,
        ollama_host="",
        ollama_model="",
        scanners=("injection",),  # the corpus measures injection-class CVEs only
        engines=engines,
    )
    return run_scout(path, config, quiet=True).findings


# Engine rule ids (e.g. semgrep check_id tails) mapped by keyword. A rule id
# matching no keyword belongs to no category: unrelated rules (crypto, ReDoS,
# path traversal, …) must neither score nor penalize the injection categories.
_ENGINE_KEYWORDS = {
    "sqli": ("sql",),
    "cmdi": ("command", "child-process", "child_process", "subprocess", "shell", "exec", "spawn", "os-system"),
    "codei": ("eval", "code-injection", "vm-runin", "function-constructor"),
    "xss": ("xss", "innerhtml", "inner-html", "dangerously", "document-write", "sanitiz", "html-inject"),
    "pathtrav": ("path-traversal", "pathtraversal", "directory-traversal", "path-join", "traversal"),
    "ssrf": ("ssrf", "server-side-request", "request-forgery"),
    "deserial": ("deserial", "pickle", "unsafe-yaml", "yaml-load", "unserialize", "insecure-deser"),
    "openredir": ("open-redirect", "open_redirect", "url-redirect", "unvalidated-redirect"),
}


def categories_of(finding: Finding) -> set[str]:
    """Categories a finding may satisfy (native titles or engine-rule keywords)."""
    if finding.scanner != "injection":
        rule = finding.title.lower()
        return {cat for cat, keywords in _ENGINE_KEYWORDS.items() if any(k in rule for k in keywords)}
    return {cat for cat, titles in CATEGORY_TITLES.items() if finding.title in titles}


def score_entry(entry: dict, findings: list[Finding], checkout: Path, tallies: dict[str, Tally]) -> None:
    """Score one CVE: each labeled weakness is a TP or FN; the rest are FPs."""
    cats = set(entry["categories"])
    matched_findings: set[int] = set()

    for weakness in entry["weaknesses"]:
        want = (checkout / weakness["file"]).resolve()
        hit = False
        for index, finding in enumerate(findings):
            if not (cats & categories_of(finding)):
                continue
            if Path(finding.file).resolve() == want and abs(finding.line - weakness["line"]) <= LINE_TOLERANCE:
                matched_findings.add(index)
                hit = True
        label = f"{entry['cve']} {weakness['file']}:{weakness['line']}"
        for cat in cats:
            if hit:
                tallies[cat].tp += 1
                tallies[cat].hits.append(label)
            else:
                tallies[cat].fn += 1
                tallies[cat].misses.append(label)

    for index, finding in enumerate(findings):
        if index in matched_findings:
            continue
        finding_cats = cats & categories_of(finding)
        for cat in finding_cats:
            tallies[cat].fp += 1


def render_summary(tallies: dict[str, Tally], scanned: int, failed: int, engines: tuple[str, ...]) -> str:
    def pct(value: float | None) -> str:
        return f"{value * 100:.1f}%" if value is not None else "n/a"

    mode = f"native + engines: {', '.join(engines)}" if engines else "native scanners only"
    lines = [
        f"# Scout {__version__} — OpenSSF CVE Benchmark results",
        "",
        f"- Mode: **{mode}**",
        f"- CVEs scanned: **{scanned}** (fetch failures: {failed})",
        f"- Matching: same file, line ±{LINE_TOLERANCE}, category must agree",
        "",
        "| Category | TP | FP | FN | Precision | Recall |",
        "| -------- | -- | -- | -- | --------- | ------ |",
    ]
    total = Tally()
    for cat in sorted(tallies):
        t = tallies[cat]
        total.tp += t.tp
        total.fp += t.fp
        total.fn += t.fn
        lines.append(f"| {cat} | {t.tp} | {t.fp} | {t.fn} | {pct(t.precision)} | {pct(t.recall)} |")
    lines.append(f"| **all** | {total.tp} | {total.fp} | {total.fn} | {pct(total.precision)} | {pct(total.recall)} |")
    lines += [
        "",
        "Read METHODOLOGY.md before quoting any number — especially the FP caveat",
        "(unlabeled real issues in corpus repos count as FPs by convention) and the",
        "honest-scope notes on what Scout does not attempt.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="only the first N corpus entries (quick pass)")
    parser.add_argument("--engine", action="append", default=[], help="external engine to include (e.g. semgrep)")
    parser.add_argument("--category", action="append", default=[], help="restrict to a category (cmdi/sqli/xss/codei)")
    args = parser.parse_args()
    engines = tuple(args.engine)

    entries = json.loads(CORPUS_MANIFEST.read_text(encoding="utf-8"))["entries"]
    if args.category:
        entries = [e for e in entries if set(e["categories"]) & set(args.category)]
    if args.limit:
        entries = entries[: args.limit]

    tallies = {cat: Tally() for cat in CATEGORY_TITLES}
    scanned = failed = 0
    for index, entry in enumerate(entries, start=1):
        dest = CORPUS_DIR / entry["cve"]
        print(f"[{index}/{len(entries)}] {entry['cve']} ({'+'.join(entry['categories'])})", flush=True)
        if not fetch_checkout(entry, dest):
            failed += 1
            continue
        findings = scan_findings(dest, engines)
        score_entry(entry, findings, dest, tallies)
        scanned += 1

    out_dir = RESULTS_DIR / __version__
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = "-".join(("native", *engines))
    summary = render_summary(tallies, scanned, failed, engines)
    (out_dir / f"summary-{suffix}.md").write_text(summary, encoding="utf-8")
    (out_dir / f"raw-{suffix}.json").write_text(
        json.dumps(
            {
                "scout_version": __version__,
                "mode": suffix,
                "scanned": scanned,
                "fetch_failures": failed,
                "line_tolerance": LINE_TOLERANCE,
                "categories": {
                    cat: {"tp": t.tp, "fp": t.fp, "fn": t.fn, "hits": t.hits, "misses": t.misses}
                    for cat, t in tallies.items()
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("\n" + summary)
    print(f"Written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
