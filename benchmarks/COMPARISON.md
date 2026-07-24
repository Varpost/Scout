# How Scout compares to other tools

All figures below relate to the **OpenSSF CVE Benchmark** corpus of real
JS/TS CVEs. Direct comparability varies — read the caveats. Nothing here is
cherry-picked: every number we control is reproducible from this directory,
and every external number is cited.

## Same corpus, same matcher (strictest comparison)

Both rows produced by `run_benchmark.py` on the identical 104-CVE subset with
identical matching rules (file + line ±2 + category) — the only difference is
the scan mode:

| Mode | cmdi recall | xss recall | codei recall | sqli recall | Overall recall | Overall precision |
| ---- | ----------- | ---------- | ------------ | ----------- | -------------- | ----------------- |
| Scout native v0.1.9 | 18.8% | 20.0% | 6.5% | 0.0% | 16.5% | 1.3% |
| Scout native v0.1.10 (JS taint pass) | 20.8% | 22.7% | 12.9% | 25.0% | 20.3% | 1.6% |
| Scout native v0.1.11 (member-exec + bundle skip) | **39.6%** | 21.3% | 9.7% | 25.0% | **24.7%** | **2.4%** |
| Scout `--engine semgrep` v0.1.11 | **41.7%** | 24.0% | 12.9% | 25.0% | **27.2%** | 2.6% |

The injection rows above are unchanged across v0.1.12–v0.1.13 (verified: identical
TP/FP/FN). Those releases added five **new** vulnerability classes — path
traversal (CWE-22), SSRF (CWE-918), insecure deserialization (CWE-502), open
redirect (CWE-601), weak randomness (CWE-330) — which are scored separately:

| Emerging class (v0.1.13) | Corpus CVEs | native recall | `--engine semgrep` recall |
| ------------------------ | ----------- | ------------- | ------------------------- |
| Path traversal | 28 | 0.0% | **21.9%** (7 TP) |
| Open redirect | 7 | 0.0% | 0.0% |
| SSRF | 3 | 0.0% | 0.0% |
| Insecure deserialization | 1 | 0.0% | 0.0% |

**Honest native baseline: 0%.** The textbook shapes these detectors catch
(`fs.readFile(req.query.file)`, `redirect(req.query.next)`) are unit-tested and
real, but the historical CVEs reach the sink through inputs Scout's *intra-file*
taint does not yet recognize (`req.url` on raw HTTP servers), sinks it does not
list (`fs.stat`, `Page.navigate`), or values built across a function boundary.
This is the same ceiling the injection categories hit — measured, published, and
the reason cross-function taint is the next lever.

**The `--engine semgrep` column is the orchestration payoff:** on path
traversal, native detection scores 0% but the merged semgrep pass reaches
**21.9%** — Scout hands the class it can't yet reach to an engine that can, in
one report. Weak randomness (CWE-330) has no CVE in the OpenSSF set, so it stays
unit-test-only. Blending these classes into an "overall" number would understate
the mature injection detection, so we keep them in a separate table.

Two deliberate levers moved v0.1.10 → v0.1.11, both first-principles rather
than corpus-tuned:

- **Command injection nearly doubled** (20.8% → 39.6%). Scout's `exec()`
  patterns guarded against `regexp.exec()` with a `(?<![\w.])` lookbehind,
  which also discarded the *common* forms — `cp.exec(cmd, cb)`,
  `shell.exec(...)`. Node's `child_process.exec` is async: it takes a
  callback/options **second** argument, while `regexp.exec()` takes exactly
  one. That structural signal recovers the real calls without matching regex
  tests. (Precision on cmdi drops because every real, unlabeled `exec()`
  call site counts as a false positive here — the documented FP upper bound.)
- **Overall precision rose** (1.6% → 2.4%) because the scanner now skips
  minified/bundled files (`*.min.js`, `*.bundle.js`, or any >2000-char line).
  A vulnerability in a generated bundle is the dependency scanner's job, not
  a hand-fixable XSS squiggle — standard SAST convention. This dropped ~370
  false positives for 2 true positives (both in bundles, unfixable in place),
  which is why xss/codei recall dip slightly while overall recall still rises.

Native v0.1.11 now exceeds what v0.1.10 needed the semgrep engine to reach
(24.1%) — with no external engine installed.

## Published results for other tools on this corpus (different grading)

Vándor, Mosolygó & Hegedűs, [*Comparing ML-Based Predictions and Static
Analyzer Tools for Vulnerability Detection*](https://doi.org/10.1007/978-3-031-10542-5_7)
(ICCSA 2022) ran three tools over the same OpenSSF CVE corpus and reported
per-CWE detection rates (their Table 1; line-level grading, not identical to
our matcher — treat as indicative, not directly comparable):

| Tool | CWE-78 (cmdi) | CWE-79 (xss) | CWE-89 (sqli) | CWE-94 (codei) |
| ---- | ------------- | ------------- | -------------- | --------------- |
| CodeQL (full semantic analysis) | 40% | 44% | 25% | 35% |
| ESLint (security plugins) | 55% | 40% | 0% | 78% |
| VulnJS4Line (research ML model) | 70% | 37% | 25% | 58% |
| **Scout native v0.1.11** (our matcher, see caveat) | **39.6%** | 21.3% | **25.0%** | 9.7% |

Worth stating plainly on two categories: Scout's SQL/NoSQL injection rate
now equals CodeQL's published one on this corpus (25%) and beats ESLint's
0%; and command injection (39.6%) is now essentially level with CodeQL's
published 40% — both from generic, documented detection, not corpus tuning.

The same paper's summary is the context every row above sits in: on real-world
CVEs, *"even the highest performing [tool] does not reach 50% detection
rate"* for XSS — real CVE corpora are brutally hard for every static tool,
which is exactly why they make honest benchmarks.

## Wider context from the literature

- [Lipp et al.](https://doi.org/10.1145/3533767.3534380) measured false-negative
  rates of **47–80%** for established SAST tools on real CVEs across 27 C
  projects — missing most real vulnerabilities is the industry norm, not the
  exception.
- A [study of JS static analysis tools](https://arxiv.org/abs/2301.05097) on
  957 real npm vulnerabilities: best-in-class detection was **41.5%**
  (ESLint security configs) and **31.3%** (CodeQL); a third of the
  vulnerabilities were caught by **no tool at all**.

## The honest take

- Scout native detects roughly **half of what CodeQL manages** on command
  injection and XSS on this corpus, **matches CodeQL on SQL/NoSQL
  injection**, and reaches about a third of it on code injection — for a
  zero-configuration, sub-second-per-repo, no-server scanner, against a
  full semantic-analysis engine. The remaining gap is real and published
  on purpose.
- Where the remaining gap comes from is known: both languages now have
  intra-file taint tracking (Python via AST, JS lexical), but Scout
  deliberately has no cross-file or whole-program analysis — CodeQL's
  wins are overwhelmingly flows that cross function and module boundaries.
- The `--engine semgrep` mode exists precisely so users who want
  engine-grade depth get it through the same report, while the native scan
  stays free, instant, and deterministic. `--engine codeql` (PR #79) goes
  further and orchestrates CodeQL itself — the top row of the table above,
  merged into a Scout report.
- Precision against CVE-labeled corpora is structurally low for every
  pattern tool (only the one labeled weakness per repo counts as "true") —
  see METHODOLOGY.md before comparing precision numbers anywhere.
