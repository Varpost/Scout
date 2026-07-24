# Scout 0.1.16 — OpenSSF CVE Benchmark results

- Mode: **native scanners only**
- CVEs scanned: **140** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 20 | 121 | 28 | 14.2% | 41.7% |
| codei | 3 | 36 | 28 | 7.7% | 9.7% |
| deserial | 0 | 0 | 1 | n/a | 0.0% |
| openredir | 0 | 4 | 7 | 0.0% | 0.0% |
| pathtrav | 15 | 61 | 17 | 19.7% | 46.9% |
| sqli | 1 | 28 | 3 | 3.4% | 25.0% |
| ssrf | 0 | 0 | 3 | n/a | 0.0% |
| xss | 16 | 1409 | 59 | 1.1% | 21.3% |
| **all** | 55 | 1659 | 146 | 3.2% | 27.4% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
