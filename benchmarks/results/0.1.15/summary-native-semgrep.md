# Scout 0.1.15 — OpenSSF CVE Benchmark results

- Mode: **native + engines: semgrep**
- CVEs scanned: **140** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 20 | 127 | 28 | 13.6% | 41.7% |
| codei | 4 | 36 | 27 | 10.0% | 12.9% |
| deserial | 0 | 0 | 1 | n/a | 0.0% |
| openredir | 0 | 4 | 7 | 0.0% | 0.0% |
| pathtrav | 20 | 277 | 12 | 6.7% | 62.5% |
| sqli | 1 | 28 | 3 | 3.4% | 25.0% |
| ssrf | 0 | 0 | 3 | n/a | 0.0% |
| xss | 18 | 1434 | 57 | 1.2% | 24.0% |
| **all** | 63 | 1906 | 138 | 3.2% | 31.3% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
