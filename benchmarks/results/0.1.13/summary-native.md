# Scout 0.1.13 — OpenSSF CVE Benchmark results

- Mode: **native scanners only**
- CVEs scanned: **140** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 19 | 124 | 29 | 13.3% | 39.6% |
| codei | 3 | 36 | 28 | 7.7% | 9.7% |
| deserial | 0 | 0 | 1 | n/a | 0.0% |
| openredir | 0 | 4 | 7 | 0.0% | 0.0% |
| pathtrav | 0 | 27 | 32 | 0.0% | 0.0% |
| sqli | 1 | 27 | 3 | 3.6% | 25.0% |
| ssrf | 0 | 0 | 3 | n/a | 0.0% |
| xss | 16 | 1409 | 59 | 1.1% | 21.3% |
| **all** | 39 | 1627 | 162 | 2.3% | 19.4% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
