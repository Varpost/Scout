# Scout 0.1.11 — OpenSSF CVE Benchmark results

- Mode: **native + engines: semgrep**
- CVEs scanned: **104** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 20 | 127 | 28 | 13.6% | 41.7% |
| codei | 4 | 36 | 27 | 10.0% | 12.9% |
| sqli | 1 | 27 | 3 | 3.6% | 25.0% |
| xss | 18 | 1434 | 57 | 1.2% | 24.0% |
| **all** | 43 | 1624 | 115 | 2.6% | 27.2% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
