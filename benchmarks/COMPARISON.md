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
| Scout native v0.1.10 (JS taint pass) | 20.8% | **22.7%** | **12.9%** | **25.0%** | **20.3%** | 1.6% |
| Scout `--engine semgrep` v0.1.10 | **31.2%** | **24.0%** | 12.9% | 25.0% | **24.1%** | 1.9% |

The v0.1.9 → v0.1.10 jump is the JS taint pass (intra-file source→sink
tracking): NoSQL/ORM injection went from undetectable to 25% recall, code
injection doubled, and XSS recall rose while its false positives *fell* —
taint evidence improves recall and precision at the same time. Native
v0.1.10 now scores what v0.1.9 needed the semgrep engine to reach.

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
| **Scout native v0.1.10** (our matcher, see caveat) | **20.8%** | **22.7%** | **25.0%** | **12.9%** |

Worth stating plainly: on SQL/NoSQL injection Scout's measured rate now
equals CodeQL's published one on this corpus (25%) and beats ESLint's 0% —
one intra-file taint pass closed a category the pattern approach could not
touch at all.

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
