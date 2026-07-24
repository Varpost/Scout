# Scout benchmark methodology

## Corpus

[OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark)
(Apache-2.0): real published CVEs in real open-source JS/TS projects, each with
the vulnerable commit and the labeled file:line of the weakness.

`corpus.json` pins the subset in **Scout's claim area** — 142 CVEs whose CWEs
intersect what Scout's injection scanner actually attempts:

| Category | CWEs | CVEs |
| -------- | ---- | ---- |
| `xss` | CWE-079 | 77 |
| `cmdi` | CWE-077, CWE-078 | 48 |
| `codei` | CWE-094, CWE-095 | 31 |
| `sqli` | CWE-089 | 4 |
| `pathtrav` | CWE-022, CWE-023, CWE-036 | 28 |
| `openredir` | CWE-601 | 7 |
| `ssrf` | CWE-918 | 3 |
| `deserial` | CWE-502 | 1 |

(A CVE can carry several CWEs, so columns overlap.)

The bottom four categories were added once Scout gained detectors for them
(path traversal + SSRF in v0.1.12, deserialization + open redirect in v0.1.13).
They are **early-stage and measured honestly**: at v0.1.13 native recall on all
four is **0%** — real-world CVEs in these classes reach the sink through
sources Scout's intra-file taint does not yet recognize (`req.url`), sinks it
does not yet list (`fs.stat`, `Page.navigate`), or flows that cross a function
boundary. The textbook shapes these detectors *do* catch (`fs.readFile(req.query.f)`)
are covered by unit tests. Cross-function taint (planned) is the lever; the
baseline is committed first so the lift is auditable. No weak-randomness
(CWE-330) CVEs exist in the OpenSSF set, so that class stays unit-test-only.

## Procedure

`python benchmarks/run_benchmark.py` — for each corpus entry:

1. Shallow-fetch the **exact pre-patch commit** into `benchmarks/corpus/<CVE>/`
   (cached; gitignored; delete the folder any time to reclaim disk).
2. Run Scout's **injection scanner only**, AI off, fully deterministic.
   `--engine semgrep` produces a second, separately-reported run.
3. Score against the labeled weakness locations.

## Matching rules

- **True positive:** a finding in the same file, within **±2 lines** of the
  label, whose finding title belongs to the CVE's category (title sets are in
  `run_benchmark.py` — a secrets finding can never credit an injection CVE).
- Engine findings (e.g. semgrep rule ids) map to categories by rule-id
  keyword (`_ENGINE_KEYWORDS`); a rule matching no keyword belongs to no
  category, so unrelated engine rules neither score nor penalize.
- **False negative:** a labeled weakness with no matching finding.
- **False positive:** any claim-area finding in a scanned repo that matches no
  label.
- Precision = TP/(TP+FP), Recall = TP/(TP+FN), per category and overall.

## Caveats — read before quoting numbers

- **The FP count is an upper bound.** Corpus repos are real codebases; only
  the CVE's weakness is labeled. A true-but-unlabeled issue Scout finds counts
  as a false positive, per benchmark convention.
- **This corpus measures the injection scanner on JS/TS.** It says nothing
  about the secrets, headers, or deps scanners, nothing about Python recall
  (the corpus is JS/TS), and nothing about vulnerability classes Scout does
  not attempt (prototype pollution, path traversal, ReDoS, …).
- **Scout's XSS checks are narrow by design** (innerHTML / document.write /
  unescaped templates). Expect low recall on the `xss` category — the corpus'
  XSS CVEs span far more sink types. This is documented scope, not a surprise.
- **Minified/bundled files are skipped by the injection scanner** (`*.min.js`,
  `*.bundle.js`, or any line over 2000 chars) — generated artifacts are the
  dependency scanner's concern, not hand-fixable source. A handful of corpus
  weaknesses live only in vendored bundles and are therefore counted as
  misses; this is a deliberate precision/utility trade, not an oversight.
- **No tuning against this corpus.** Detection changes must cite a motivating
  case from elsewhere; using corpus repos to fix a miss overfits the number.
- **Corpus rot:** some pinned repositories have been deleted from GitHub
  since the OpenSSF benchmark was assembled. Failed fetches are skipped and
  counted in the summary (`fetch failures`), never silently dropped.
- Results are versioned under `results/<scout version>/` and never
  overwritten; re-run per release that touches detection.

## Reproducing

```bash
pip install -e .
python benchmarks/run_benchmark.py                  # full corpus (~1-2 GB download on first run)
python benchmarks/run_benchmark.py --limit 10       # quick pass
python benchmarks/run_benchmark.py --engine semgrep # engine-assisted run, reported separately
```

The README may cite only numbers present in a committed `results/` file.
