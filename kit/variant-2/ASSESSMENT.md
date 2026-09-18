# Assessment — Variant 2 (Auravia Health · provider-svc)

Target time: **~2 hours.** Four tasks. Produce the deliverable named at the end of
each. There's no single right wording — you're scored on ranking, reasoning, and
what you choose *not* to worry about. The rubric in `ANSWER-KEY.md` shows what
separates a junior answer from a senior one on each task.

Mindset: a strong submission is decisive and short. It says what matters most and
why, names what the tools got wrong, and doesn't hedge everything into a flat list.
Treat the scanner and the rules as colleagues' work you're reviewing, not ground
truth. This variant rewards one instinct in particular: **the worst bugs here are
things that are *missing* — an authorization check that was never wired, a guard
that isn't there — and missing things are exactly what pattern-matching tools and
pattern-matching reviewers skip over.**

---

## Task 1 — Vulnerability triage (~45 min)

Review `service/provider-svc/` **and** `scans/scanner-report.json` together.

**Produce:**

1. **A ranked issue list** — every real issue you'd act on, ordered by true risk in
   this service's context (credentialing integrity, PHI documents, self-service
   registration, internet-adjacent behind a gateway). For each: a one-line "why this
   rank," the category, and the fix.
2. **A scanner-accuracy column** — for each issue, mark Right / Over-rated /
   Under-rated / Missed. Include the scanner finding(s) you're **dismissing** as
   false positives and say why. (There is at least one confident false positive, and
   it's the scanner's single highest-severity finding.)
3. **A 30-second credibility check on the scanner itself** — what can you tell about
   this tool's trustworthiness from its report metadata alone, before reading a
   single finding? (More than one tell. At least one is about a capability it
   *claims* and then contradicts.)
4. **The single most dangerous issue** and a two-sentence justification you'd say out
   loud in the risk review. It is almost certainly not the scanner's top finding.

Two nudges. First, "the codebase" includes files that aren't application logic — and
the way this service breaks trust may not be a classic injection. Second, when the
scanner flags a dependency, check *which* CVSS it's showing you and against *what
source* — then check whether the vulnerable code path is the one the app actually
calls.

---

## Task 2 — Detection engineering (~45 min)

An incident happened in the 24-hour window in `data/`. None of the four rules in
`siem/` fired on it. Both facts are true at once; explain how.

Start with a warning this variant makes explicit: **the gateway stream will not hand
you this incident.** Work out early why, because it reframes the whole task. Then
work `data/app.log` — the signal is in the application's domain events
(`provider.updated`, `provider.verify`, `availability.sync`, `document.read`), not in
a token mismatch.

**Produce:**

1. **The incident reconstructed** — a short staged timeline with specific log
   evidence (timestamps, IPs, fields) for each stage. Name which planted code
   weaknesses from Task 1 the attacker chained. State plainly why the attacker's
   requests look *identical to a legitimate user's* at the gateway.
2. **A per-rule failure analysis** — for **each** of R1–R4, the one specific reason
   it did not fire. "It's a bad rule" is not an answer; each fails for a different,
   concrete, defensible-in-isolation reason. One rule was broken by a change whose
   commit message is *itself the security bug restated as an assumption* — find it
   and read the diff. Another is silently dead for a reason that has nothing to do
   with its logic.
3. **What the 30-day alert export tells you** — `siem/alert-volume-30d.csv` shows two
   operational problems independent of this incident. Name them. One of them is a
   rule that looks *healthy* (fires steadily, everything acknowledged) and is still
   not protecting you — explain that trap.
4. **Your fix for the highest-leverage gap** — pick the one rule change that would
   have caught this incident earliest, and write the corrected logic (pseudocode is
   fine). Say what new false positives it might introduce and how you'd bound them.

> Syntax caveat: the rules are pseudo-SPL to reason about, not to deploy verbatim.
> You're judged on the logic, not the dialect.

---

## Task 3 — Compliance mapping (~20 min)

Auravia is under **HIPAA** and working toward **HITRUST**. Translate your technical
findings into the language the compliance lead and the customer's auditor use.

**Produce:**

1. **A findings-to-controls map** — take your top 5–6 issues from Tasks 1–2 (include
   at least one *detection/monitoring* gap, not only code) and map each to the HIPAA
   Security Rule safeguard it implicates. Name the safeguard; cite the clause if you
   know it, but **flag any clause number you haven't verified** rather than stating
   it as fact.
2. **The one finding with the sharpest regulatory teeth** — which issue would you
   lead the compliance conversation with, and why? Think about *what data* is exposed
   and *what obligation* that triggers. (Consider both the document exfiltration and
   a subtler angle unique to this service: what does it mean, for a HIPAA-covered
   entity, that an unauthorized party could mark clinicians "verified"?)
3. **A monitoring/review gap framed as a compliance gap** — the alert-export problems
   from Task 2 aren't just ops hygiene. Which HIPAA administrative safeguard do they
   implicate, and how would you phrase that to a non-engineer?

You're not expected to have clause numbers memorized. You *are* expected to know
which safeguard family each issue lives in and to be honest about what you'd verify.

---

## Task 4 — AI-usage reflection (~10 min)

If you used any AI assistant during this exercise (or in how you'd do this job), fill
in the template honestly. If you didn't, answer as "how I would."

**Produce (answer each):**

- **Where I used AI:** which tasks/steps, and for what specifically.
- **What I verified independently:** what the AI produced that I checked against a
  primary source or my own reasoning before trusting — and *how*. (This variant has a
  built-in example: the two dependency CVEs are shown with a vendor CVSS that differs
  from the NVD base score. Did you check?)
- **What I would not delegate to AI here, and why:** the judgment calls you'd keep
  human. (Missing-authorization bugs are a good test — would an AI code reviewer that
  scans for dangerous *calls* have caught an authorization check that simply isn't
  there?)
- **A place AI would plausibly be confidently wrong on this kit:** name one, with the
  catch.
- **Sensitive-data note:** this kit contains synthetic PHI-shaped fields
  (credentialing docs, NPI). What's your rule for putting real log data or code like
  this into a third-party AI tool in a *real* healthcare setting?

---

When you're done with all four, grade against `ANSWER-KEY.md`, then read
`STUDY-GUIDE.md` for what this variant was testing that Variant 1 wasn't.
