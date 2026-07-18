# Scout 0.1.10 — OpenSSF CVE Benchmark results

- Mode: **native + engines: semgrep**
- CVEs scanned: **104** (fetch failures: 2)
- Matching: same file, line ±2, category must agree

| Category | TP | FP | FN | Precision | Recall |
| -------- | -- | -- | -- | --------- | ------ |
| cmdi | 15 | 41 | 33 | 26.8% | 31.2% |
| codei | 4 | 86 | 27 | 4.4% | 12.9% |
| sqli | 1 | 27 | 3 | 3.6% | 25.0% |
| xss | 18 | 1847 | 57 | 1.0% | 24.0% |
| **all** | 38 | 2001 | 120 | 1.9% | 24.1% |

Read METHODOLOGY.md before quoting any number — especially the FP caveat
(unlabeled real issues in corpus repos count as FPs by convention) and the
honest-scope notes on what Scout does not attempt.
