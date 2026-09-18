# Security Engineer Practice Kit — Take-Home Assessment Simulator

A self-paced, ~2-hour-per-variant exercise that reproduces the practical screen used
to hire security engineers: a real-feeling microservice, a scanner report you can't
take at face value, 24 hours of logs with an incident buried in noise, and detection
rules that look fine until you check them against what actually happened.

It trains the judgment the interview is really testing — **not "can you find a bug,"
but "can you rank what matters, catch the tool when it's wrong, tie a finding to its
business and regulatory consequence, and say what you'd verify before trusting it."**
Every task ships with a full answer key and a junior-vs-senior scoring rubric so you
can grade yourself honestly.

**Who it's for:** engineers preparing for security take-homes or practical
interviews; people moving from IT/dev into security who want reps on real triage,
detection, and compliance reasoning; teams who want a calibrated internal exercise.

---

## What's inside — two independent variants

Both are set at the same fictional company (**Auravia Health**, a HIPAA-covered
health-tech firm working toward HITRUST) but use different services, different bugs,
different incidents, and different traps. Do Variant 1 first; Variant 2 is harder and
deliberately punishes applying V1's answers on autopilot.

| | Variant 1 (start here) | Variant 2 (harder) |
|---|---|---|
| **Location** | this folder (root) | `variant-2/` |
| **Service** | `booking-svc` — appointment booking | `provider-svc` — provider directory & credentialing |
| **Core lesson** | an attacker who **forges** identity; the gateway's independent role knowledge exposes the lie | an attacker who is a **real, authenticated user** abusing what that identity is wrongly allowed to do — nothing forged |

Each variant contains the same four tasks: **(1)** vulnerability triage, **(2)**
detection engineering, **(3)** compliance mapping (HIPAA Security Rule + HITRUST),
**(4)** an AI-usage reflection. And the same file set:

```
INSTRUCTIONS.md            <- read first: scenario, how to run it, the box contents
ASSESSMENT.md              <- the four tasks; your worksheet
service/<svc>/             <- the codebase under review
scans/scanner-report.json  <- output of "AuraScan", the (unreliable) SAST/SCA tool
data/app.log, gateway.log  <- 24h of logs, JSON lines, with an incident inside
data/generate_logs.py      <- the log generator (don't peek until after Task 2)
siem/                      <- four deployed detection rules + a 30-day alert export
ANSWER-KEY.md              <- full solution + scoring rubric (open after you attempt)
STUDY-GUIDE.md             <- the transferable judgment patterns behind the tasks
```

**Suggested path:** Variant 1 `INSTRUCTIONS.md` → work `ASSESSMENT.md` (~2h) → grade
against `ANSWER-KEY.md` → read `STUDY-GUIDE.md` → repeat in `variant-2/`. The two
study guides stack: V2's builds on V1's eight patterns.

---

## ⚠️ Read before you rely on any of this as authoritative

This is a **training artifact**, built to be reasoned about — not a source of record.
Three things to keep straight:

1. **Everything is fictional except the CVEs.** Auravia Health, its code, its logs,
   its incidents, and its "AuraScan" tool are invented. The dependency **CVEs are
   real, public, NVD-checkable advisories** — that's what genuine SCA data looks
   like — and each variant contains a deliberate lesson about *which* CVSS number
   you're shown and whether the vulnerable code path is actually reached. The
   scanner's interpretation of those CVEs is intentionally not always right.
2. **Compliance clause numbers need verification.** The HIPAA/HITRUST citations in the
   answer keys are given to the best of general knowledge and marked `⚠[verify]` where
   a specific clause should be confirmed against the current regulatory source before
   you repeat it in a report, an interview, or a client deliverable. Regulatory text
   and control numbering change.
3. **Detection queries are pseudo-syntax, not deployable.** The rules in each `siem/`
   are written in a readable, Splunk-SPL-flavored pseudo-syntax and marked `⚠[syntax]`.
   Validate and port them to your real backend (SPL / KQL / ES|QL / Sigma + pipeline)
   before deploying — field extraction, regex dialects, CIDR matching, and null
   handling differ across platforms and *will* change whether a rule fires. Two of the
   planted gaps (a regex range, a renamed field) depend on exactly that.

**Intentional kit artifacts (not bugs to find):** the `package-lock.json` files use
placeholder `integrity` hashes (`sha512-EXAMPLEHASH…DoNotTrust…`) rather than real
ones — don't install these lockfiles expecting verifiable hashes. The services are for
review only; **do not deploy them anywhere real.**

---

*Do the code review and log analysis by reading — nothing here needs to be run. If you
want to explore, each `INSTRUCTIONS.md` has copy-paste `jq` starting points for the
logs.*
