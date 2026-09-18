# Study Guide — Patterns to Recognize

Take-home assessments and practical interviews recycle a small number of *judgment*
patterns. The bugs change; the thing being tested doesn't. If you can name the
pattern you're looking at, you can answer faster and sound senior doing it. Each
pattern below is drawn from this kit but written to generalize.

---

## 1. CVSS is not risk. Context is risk.

A scanner hands you a 9.8 and a 6.5. The 9.8 (minimist) is a dev-only tool that
never ships; the "just a medium" is a CORS policy that leaks credentialed PHI. The
score describes the vulnerability in the abstract; **risk is the score filtered
through reachability, exposure, data sensitivity, and blast radius in *this*
system.** Seniors re-rank by context and can say why a lower number outranks a
higher one. Always ask: is the vulnerable code path actually reached? What data is
behind it? Who can get to it?

## 2. The scanner is a witness, not a judge — cross-examine it in 30 seconds.

Before reading a single finding, check whether the tool is trustworthy: do the
counts add up (this kit's report claims 12 findings and lists 10)? Is the ruleset
current (a 2017 OWASP set will miss the access-control bugs that 2021 made #1)? Does
its claimed scope match its output (claims to scan pipelines, missed the CI file)?
Do its capability claims ("deep dataflow," "reachability") survive contact with what
it missed? A report that fails these is an *input*, not a verdict. This check is
itself a scored skill.

## 3. False positives and false negatives travel together — audit both directions.

Naive triage only asks "is this finding real?" (catching false positives). Senior
triage also asks "what *isn't* here that should be?" The most dangerous item in this
kit — auth that decodes instead of verifies — produces **no finding at all**. Tools
are systematically blind to whole categories (broken access control, business
logic, auth-that-looks-like-auth). Read the code for the categories the scanner
structurally can't see, and treat a clean result in those areas as unproven, not
safe.

## 4. Authentication that runs is not authentication that works.

`jwt.decode()` vs `jwt.verify()`. A 200 response. A token with an `admin` claim.
Everything *looks* authenticated — there's a token, there's a role, the code reads
it. But nothing checks the signature, so the whole mechanism is decorative.
Access-control bugs love to hide behind machinery that *appears* to be doing the
job. Whenever you see auth, ask the blunt question: *what happens if I forge/omit/
swap this?* — and confirm the code actually rejects it, rather than reading it and
trusting it.

## 5. Attackers tune to your thresholds, and your allowlists are their doorway.

The incident paces credential stuffing to **15/5min** because the rule fires at
**20/5min**, and spoofs the batch job's **user-agent** because that UA is
allowlisted. Two lessons. First, a static threshold is a published blind spot — the
band *below* it is a safe operating zone for a patient attacker; layer volume rules
with behavioral/first-seen signals. Second, **never allowlist on a client-controlled
attribute** (user-agent, header, path) — allowlist on identities *you* issue and
verify. Every allowlist is an exception an attacker will try to occupy.

## 6. The "reasonable-looking commit" is where detections go to die.

R3 was correct, then a one-line change — adding `| where isnotnull(gw_known_role)` —
shipped as a false-positive fix (it silenced real restart/cache-warmup alert
storms), got reviewed and approved, and silently stopped catching the exact case it
existed for. The trap: `gw_known_role` is null *precisely* when a token is forged,
so the guard filters out the forgeries before the comparison ever runs. The null
wasn't the absence of signal — it *was* the signal. No rule is "broken" in a way
that looks broken; it's broken in a way that looked like an improvement. When a
detection misses, **read its change history**, and reason explicitly about the edge
cases the predicate no longer covers — especially null, empty, and "unknown" states
(and remember that in many query backends `x != y` is *not* true when one side is
null). Coverage regressions are invisible until an incident finds them.

## 7. Noise is a security control that has failed quietly.

R1 fired hundreds of times over the month and grew a backlog of unacknowledged
alerts nobody had triaged in weeks; R2 had never fired at all. Both are "working" in
the sense that they're deployed. But an alert nobody reads is not detection, and a
rule that has never fired is not proven — it may be structurally incapable of firing
(R2's regex can't match the URL-encoded payloads it's meant to catch). Worse,
**alert fatigue is the upstream cause of blind spots**: the same noise pressure that
buries a real R1 hit in an ignored queue is what motivates teams to reach for the
lazy allowlist (R4's spoofable user-agent) that lets an attacker through. And notice
the meta-tell: R3 and R4 both went silent the moment a "fix" shipped — a rule that
goes quiet right after a commit is a coverage regression until proven otherwise.
Operational health (ack rates, never-fired rules, tuning history) *is* security
posture, not ops trivia.

## 8. Vulnerabilities live outside application code — and translate into obligations.

The single highest-severity miss is a **CI workflow**, not a line of app logic; the
proof that minimist is harmless lives in the **lockfile**. Metadata, pipelines,
config, and dependencies are in scope, and often hold the worst of it because nobody
reviews them like code. And the final translation seniors make: a technical finding
becomes a **business and regulatory consequence**. ~430 PHI records read by an
unauthorized party isn't "an IDOR," it's a *breach-notification clock*. The people
deciding your assessment want to see you carry a bug all the way to "so what do we
have to do about it, and who do we have to tell?"

---

### How to use these in a live assessment

- **Open with the ranking, not the list.** State the top risk and why in two
  sentences (Patterns 1, 8).
- **Say what the tool got wrong, explicitly.** It signals you don't outsource
  judgment (Patterns 2, 3).
- **For detections, always check the diff and the volume export** (Patterns 6, 7).
- **End every finding at consequence,** not at CWE number (Pattern 8).
- **Flag what you'd verify** (clause numbers, query syntax) instead of bluffing —
  honesty reads as senior, not junior.
