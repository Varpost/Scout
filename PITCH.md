# Scout
### The AI security team for the AI-coding era.

**One-line pitch:**

> Your AI writes the code. Scout makes sure it's not a disaster.

**Tagline:**

> Ship fast. Don't get breached. Free forever.

---

## The Problem

In 2026, **80%+ of code is written or co-written by AI** — Cursor, Copilot, Claude Code, v0, Bolt, Lovable. Developers ship in days what used to take months.

**The catch:** AI optimizes for *working code*, not *secure code*. It writes:

- API endpoints with no auth
- SQL queries glued together with string concatenation
- Hardcoded API keys committed to git
- Dockerfiles running as root
- Login flows missing rate limits
- Sessions that never expire

A solo dev or small team has **three bad options**:

1. **Hire a security engineer** — $150k/year. Not happening.
2. **Pay for a pentest** — $5k–$50k. Not happening either.
3. **Ship and pray** — what everyone actually does. Breach in week 2.

There is no fourth option today. **Scout is the fourth option.**

---

## The Solution

**Scout is an AI security team in your terminal.** Five specialized agents work together to find, plan, fix, and verify security issues in any codebase — without breaking production.

```bash
pip install scout
scout scan .
```

That's it. In under 60 seconds you get a security report a senior engineer would write, with a phased fix plan that never breaks your app.

---

## The Five Agents

| Agent | Role | Output |
|---|---|---|
| **Scout** | Finds every vulnerability (static + optional AI confirmation) | Raw findings |
| **Architect** | Groups fixes into 5 risk-ordered phases | Safe rollout plan |
| **Reporter** | Writes a human-tone report (not CVE jargon) | `security-report.md` |
| **Implementer** | Writes the actual code fixes — one phase at a time, only on "go" | Reviewable patches |
| **Validator** | Re-scans and runs tests after each phase | Pass/fail per phase |

**The dev stays in control.** No agent auto-applies anything. Every fix is a patch you review before it touches your code.

---

## The Safety Model — 5 Phases

Production never goes down because fixes ship in escalating risk tiers:

| Phase | What | Risk |
|---|---|---|
| **1** | Headers, env vars, dep bumps | Zero |
| **2** | Add rate limits, CORS, input limits (additive only) | Low |
| **3** | Fix auth and sessions | Medium |
| **4** | Parameterize queries, fix data layer | Medium-high |
| **5** | Architectural rewrites | High — manual review required |

One phase = one PR. Devs explicitly approve each phase with `scout fix --phase 1`.

---

## What Scout Replaces (Real Security Team Functions)

| Traditional role | Cost (USA, /yr) | Scout equivalent |
|---|---|---|
| SAST tool (Snyk Code, Checkmarx) | $5k–$50k | Built in, free |
| SCA / dependency scanning | $3k–$20k | Wraps `pip audit` + `npm audit` + OSV.dev |
| Secrets scanning (GitGuardian) | $3k+ | Built in + git history |
| IaC scanning (Snyk IaC) | $5k+ | Dockerfile + compose + Terraform |
| Security engineer | $150k | AI agents, optional BYO-key |
| Pentest (annual) | $5k–$50k | Static + AI deep review |
| Threat modeling workshop | $10k+ | Phase 2 desktop |

**Total: $180k+/year → $0.**

---

## Why It Works When Other Tools Don't

| Other tools | Scout |
|---|---|
| "Here are 247 issues, good luck" | "Here are 12 real issues, prioritized, with fix plans" |
| Compliance jargon (CWE-89, CVE-...) | "Anyone can read your user database. Here's why." |
| Requires SaaS signup + API key | Works offline, zero signup |
| Sends your code to their cloud | Static-first; AI is optional + your key |
| Finds issues but doesn't fix them | Writes the actual code fix |
| Auto-apply breaks production | Phased rollout, dev approves each step |

---

## The Tech (All Free, All Open)

- **Python 3.10+** core
- **Typer** CLI
- **AST + regex** for static analysis (instant, zero-cost)
- **Optional AI pass**: Anthropic / OpenAI (BYO key) or **Ollama** (local, free)
- **GitPython** for safe patch generation
- **OSV.dev + npm audit + pip audit** for dependency CVEs
- **Distribution:** PyPI (`pip install scout`) — free
- **Repo:** GitHub, MIT license — free forever

**The AI cost trick:** Scout never sends full files to AI. Only flagged snippets, in strict JSON, under 2k tokens per call. A full scan of a 50k-LOC app costs under $0.10 in API credits — or $0 with Ollama.

---

## Roadmap

### Phase 1 — Open Source CLI *(building now)*

Free forever. Zero signup. Works offline. Optional AI.
**Goal:** Become the default security tool for indie devs and AI-coders.

### Phase 2 — Scout Desktop *(after Phase 1 traction)*

Local desktop app (Tauri, ~10MB). **Your code never leaves your machine.**

Killer features:

- Auto-installs Ollama + model on first launch — zero AI friction
- Real-time watcher — scans on save, like a linter
- Live secret validation — "your leaked AWS key is still active right now"
- Git hook auto-setup — block secrets before they're pushed
- Scan history + trends (local SQLite) — "47 fixes this month, top risk: auth"
- AI threat model generator — replaces a $10k security architect
- Malicious dependency alerts (OSV.dev + Socket feed)
- Clickable GUI report — jump straight to vulnerable code
- Multi-project dashboard
- Auto-PR fix mode — one click per phase, still reviewable

### Phase 3 — Team / Enterprise *(only when meaningful traffic)*

GitHub Action, team dashboard, compliance mapping (SOC2, OWASP). Always optional. Phase 1 stays free forever.

---

## Who This Is For

- **Solo founders** shipping a SaaS this weekend
- **AI-first developers** using Cursor / Claude Code / Copilot / v0
- **Bootcamp grads** building portfolio apps
- **OSS maintainers** of small libraries
- **Small teams (1–10 devs)** with no security headcount
- **Hackathon builders** who don't want their MVP getting pwned in week 2

If you've ever shipped code thinking *"I hope this is secure"* — Scout is for you.

---

## The Ask (for early adopters)

1. **Install it** — `pip install scout` *(coming soon)*
2. **Run it on your project** — `scout scan .`
3. **Star the repo** — github.com/tejaswirajgit/Scout
4. **Tell one other dev** — that's how Scout grows

No signup. No tracking. No cloud. Free forever.

---

## Why Now

- **AI coding is mainstream.** Every dev is now a 10x dev — and a 10x security liability.
- **Breaches are accelerating.** Average cost of a data breach in 2026 crossed $5M.
- **Indie devs have zero options.** Existing security tools price for enterprises.
- **Local AI is finally good enough.** Ollama + Llama 3.x / Qwen / DeepSeek can do real code review on a laptop.

**Scout sits exactly where these four trends collide.**

---

> **Scout — Your security team in a CLI. Free, local, no signup.**
>
> *Built for the dev who'd rather ship than read OWASP.*

github.com/tejaswirajgit/Scout
