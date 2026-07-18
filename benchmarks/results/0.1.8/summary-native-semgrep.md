# Scout 0.1.8 — OpenSSF CVE Benchmark results

- Mode: **native + engines: semgrep**
- CVEs scanned: **104** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 14 | 40 | 34 | 25.9% | 29.2% |
| codei | 2 | 53 | 29 | 3.6% | 6.5% |
| sqli | 0 | 9 | 4 | 0.0% | 0.0% |
| xss | 16 | 1864 | 59 | 0.9% | 21.3% |
| **all** | 32 | 1966 | 126 | 1.6% | 20.3% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
