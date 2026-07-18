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
| Scout native (zero-dep, deterministic) | 18.8% | 20.0% | 6.5% | 0.0% | 16.5% | 1.3% |
| Scout `--engine semgrep` (p/default) | **29.2%** | 21.3% | 6.5% | 0.0% | **20.3%** | 1.6% |

Two things worth noticing in that second row: the engine's biggest lift is
command injection (+10.4 points — semgrep's `child_process` rules are strong),
and even an industrial rule engine adds only ~4 points of overall recall on
real CVEs — evidence for the paper's conclusion below, not against semgrep.

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
| **Scout native** (our matcher, see caveat) | **18.8%** | **20.0%** | **0.0%** | **6.5%** |

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

- Scout native currently detects roughly **half of what CodeQL manages** on
  command injection and XSS on this corpus — for a zero-configuration,
  sub-second-per-repo, no-server scanner, against a full semantic-analysis
  engine. The gap is real and published on purpose.
- Where the gap comes from is known and on the roadmap: intra-file taint
  tracking exists for Python (the `reachable` signal) but not yet JS, and
  Scout deliberately has no whole-program analysis.
- The `--engine semgrep` mode exists precisely so users who want
  engine-grade depth get it through the same report, while the native scan
  stays free, instant, and deterministic. `--engine codeql` (PR #79) goes
  further and orchestrates CodeQL itself — the top row of the table above,
  merged into a Scout report.
- Precision against CVE-labeled corpora is structurally low for every
  pattern tool (only the one labeled weakness per repo counts as "true") —
  see METHODOLOGY.md before comparing precision numbers anywhere.
