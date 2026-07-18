# Scout 0.1.10 — OpenSSF CVE Benchmark results

- Mode: **native scanners only**
- CVEs scanned: **104** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 10 | 33 | 38 | 23.3% | 20.8% |
| codei | 4 | 86 | 27 | 4.4% | 12.9% |
| sqli | 1 | 27 | 3 | 3.6% | 25.0% |
| xss | 17 | 1822 | 58 | 0.9% | 22.7% |
| **all** | 32 | 1968 | 126 | 1.6% | 20.3% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
