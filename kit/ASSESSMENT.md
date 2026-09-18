# Assessment — Variant 1 (Auravia Health · booking-svc)

Target time: **~2 hours.** Four tasks. Produce the deliverable named at the end of
each. There's no single right wording — you're being scored on ranking, reasoning,
and what you choose to *not* worry about. The rubric in `ANSWER-KEY.md` shows what
separates a junior answer from a senior one on each task.

A note on mindset: a strong submission is decisive and short. It says what matters
most and why, names what the tools got wrong, and doesn't hedge everything into a
flat list. Treat the scanner and the detection rules as colleagues' work you're
reviewing, not as ground truth.

---

## Task 1 — Vulnerability triage (~45 min)

Review `service/booking-svc/` **and** `scans/scanner-report.json` together.

The scanner found some real things, missed some real things, and mis-rated others.
Your job is to produce the triage the scanner couldn't.

**Produce:**

1. **A ranked issue list** — every real issue you'd act on, ordered by true risk
   *in this service's context* (healthcare PHI, internet-adjacent, behind a
   gateway). For each: a one-line "why this rank," the category, and the fix.
2. **A scanner-accuracy column** — for each issue, mark whether the scanner got it
   Right / Over-rated / Under-rated / Missed. Include the scanner findings you are
   **dismissing** (false positives) and say why.
3. **A 30-second credibility check on the scanner itself** — list what you can tell
   about this tool's trustworthiness from its report metadata alone, before you
   even read a finding. (There is more than one tell.)
4. **The single most dangerous issue** and a two-sentence justification you'd say
   out loud in the risk review. It is not necessarily the one the scanner ranked
   highest.

Don't forget that "the codebase" includes files that aren't application code.

---

## Task 2 — Detection engineering (~45 min)

An incident happened in the 24-hour window in `data/`. None of the four rules in
`siem/` fired on it. Both facts are true at once, and your job is to explain how.

Work `data/app.log` and `data/gateway.log` together — they share `request_id`, and
the gateway sees things (like the role it independently knows for a subject) that
the app log doesn't.

**Produce:**

1. **The incident reconstructed** — a short timeline of what happened, in stages,
   with the specific log evidence (timestamps, IPs, fields) for each stage. Name
   which planted code weaknesses from Task 1 the attacker chained.
2. **A per-rule failure analysis** — for **each** of R1–R4, the one specific reason
   it did not fire on this incident. "It's a bad rule" is not an answer; each rule
   fails for a different, concrete, defensible-in-isolation reason. At least one was
   broken by a change that looked like a reasonable fix — find it and read the diff.
3. **What the 30-day alert export tells you** — `siem/alert-volume-30d.csv` shows
   two operational problems independent of this incident. Name them and say why
   each is a real risk even on a quiet day.
4. **Your fix for the highest-leverage gap** — pick the one rule change that would
   have caught this incident earliest, and write the corrected logic (pseudocode is
   fine). Say what new false positives it might introduce and how you'd bound them.

> Remember the syntax caveat: the rules are pseudo-SPL to reason about, not to
> deploy verbatim. You're being judged on the logic, not the dialect.

---

## Task 3 — Compliance mapping (~20 min)

Auravia is under **HIPAA** and working toward **HITRUST**. Translate your technical
findings into the language the compliance lead and the customer's auditor use.

**Produce:**

1. **A findings-to-controls map** — take your top 5–6 issues from Task 1 and Task 2
   (include at least one *detection/monitoring* gap, not only code) and map each to
   the HIPAA Security Rule safeguard it implicates. Use the safeguard by name; cite
   the clause if you know it, but **flag any clause number you haven't verified**
   rather than stating it as fact.
2. **The one finding with the sharpest regulatory teeth** — which issue would you
   lead the compliance conversation with, and why (think about *what data* is
   exposed and *what obligation* that triggers)?
3. **A monitoring/review gap framed as a compliance gap** — the alert-export
   problems from Task 2 aren't just ops hygiene. Which HIPAA administrative
   safeguard do they implicate, and how would you phrase that to a non-engineer?

You are not expected to have clause numbers memorized. You *are* expected to know
which safeguard family each issue lives in and to be honest about what you'd verify.

---

## Task 4 — AI-usage reflection (~10 min)

Real assessments increasingly ask this, and real teams increasingly need it. If you
used any AI assistant during this exercise (or in how you'd do this job), fill in
the template below honestly. If you didn't, answer it as "how I would."

**Produce (template — answer each):**

- **Where I used AI:** which tasks/steps, and for what specifically.
- **What I verified independently:** what the AI produced that I checked against a
  primary source or my own reasoning before trusting — and *how* I checked it.
- **What I would not delegate to AI here, and why:** the judgment calls in this
  exercise I'd keep human, with the reason.
- **A place AI would plausibly be confidently wrong on this kit:** name one, and
  how you'd catch it. (Hint: the scanner report is itself an example of an
  automated tool being confidently wrong — what's the human check?)
- **Sensitive-data note:** this kit contains synthetic PHI-shaped fields. What's
  your rule for putting log data or code like this into a third-party AI tool in a
  *real* healthcare setting?

---

When you're done with all four, grade against `ANSWER-KEY.md`, read
`STUDY-GUIDE.md`, then run `variant-2/`.
