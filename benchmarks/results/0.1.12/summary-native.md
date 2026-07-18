# Scout 0.1.12 — OpenSSF CVE Benchmark results

- Mode: **native scanners only**
- CVEs scanned: **104** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 19 | 124 | 29 | 13.3% | 39.6% |
| codei | 3 | 36 | 28 | 7.7% | 9.7% |
| sqli | 1 | 27 | 3 | 3.6% | 25.0% |
| xss | 16 | 1409 | 59 | 1.1% | 21.3% |
| **all** | 39 | 1596 | 119 | 2.4% | 24.7% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
