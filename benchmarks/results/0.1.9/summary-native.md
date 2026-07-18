# Scout 0.1.9 — OpenSSF CVE Benchmark results

- Mode: **native scanners only**
- CVEs scanned: **104** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 9 | 32 | 39 | 22.0% | 18.8% |
| codei | 2 | 53 | 29 | 3.6% | 6.5% |
| sqli | 0 | 9 | 4 | 0.0% | 0.0% |
| xss | 15 | 1839 | 60 | 0.8% | 20.0% |
| **all** | 26 | 1933 | 132 | 1.3% | 16.5% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
