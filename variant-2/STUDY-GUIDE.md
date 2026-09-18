# Study Guide — Variant 2 (what this variant tested that V1 didn't)

Variant 1's eight patterns still apply — reread them; they're the base layer. This
guide assumes them and adds the seven judgment patterns V2 is built to teach. The
one-sentence bridge from V1: **V1 was about an attacker who *lied* about who they
were; V2 is about an attacker who told the complete truth about who they were and
abused what that identity was wrongly allowed to do.** Almost everything below
follows from that shift.

If you haven't read `STUDY-GUIDE.md` in the Variant 1 kit, its patterns are:
(1) CVSS is not risk, (2) the scanner is a witness not a judge, (3) false positives
and negatives travel together, (4) auth that runs ≠ auth that works, (5) attackers
tune to thresholds and allowlists, (6) the reasonable-looking commit, (7) noise is a
failed control, (8) vulns live outside app code and become obligations. V2 leans hard
on 3, 5, 6, and 7 and adds these.

---

## 9. Authorization abuse by a legitimate principal — the identity is real, the *permission* is the bug.

The V2 attacker registered, logged in, and got a genuine `provider` session. At the
gateway, `token_role_claim == gw_known_role == "provider"` on every request — there
is no lie to catch. This breaks a whole class of detection that keys on **identity
integrity** (forged tokens, impossible travel, credential-claim mismatch — V1's whole
Task 2). None of it sees this incident, because nothing about the identity is wrong.
The signal is **behavioral**: a brand-new account escalates its own privileges,
credentials four other accounts, and then egresses to an internal IP. When you're
handed logs, ask early: *is the hard part here proving who someone is, or proving that
what they did was allowed?* If it's the second, stop looking at the auth layer and
start looking at what real accounts are permitted to do.

## 10. Mass assignment: the request body is an attack surface, not a form.

`const updated = { ...record, ...req.body }` is the whole bug. The endpoint was
"providers edit their contact details," but spreading the raw body over the record
lets the client write **every** column the subsequent `UPDATE` touches — including
`role` and `credential_status`. The dangerous line isn't a call to something scary;
it's an object spread. Whenever untrusted input is merged into a persisted object,
the writable-field set is *everything in that object* unless something narrows it.
Allowlist the fields a caller may set; never denylist, never trust the handler's name
("updateContactInfo") to describe what it can actually write.

## 11. You can't grep for a check that isn't there.

The two worst findings — missing `requireAdmin` on `/verify` (V-C1) and the
mass-assignment merge (V-C2) — are **absences**. Call-scanning tools (and reviewers
skimming for dangerous functions) are structurally blind to a guard that simply was
never wired: there's no bad line to flag. `requireAdmin` even *exists* in the codebase
— it's just not applied. The senior technique is not pattern-matching; it's
**enumeration**: list every state-changing / privileged action (verify a provider,
change a role, read a document, trigger an outbound fetch) and, for each, ask "what
enforces authorization here, and where is that line?" The ones with no answer are your
findings. Treat "the scanner found nothing in the access-control category" as
*unproven*, never as *safe* — especially under a ruleset whose #1 item is Broken
Access Control.

## 12. A detection encodes assumptions about the system; when the assumption is the bug, the rule blesses the attack.

R2 would have caught the self-escalation, except a reviewed one-line commit scoped it
to `actor_role="admin"` with the rationale *"role/credential_status can only be set
from the admin console."* That sentence is the mass-assignment vulnerability **restated
as a premise** — the exact thing the PATCH handler makes false. The rule and the bug
share one assumption, so the rule cannot see the bug. Read every rule predicate as a
*claim about how the system behaves*, then go check the code for the claim it depends
on. When a detection filters, ask "what real events does this filter throw away, and
could the attack live in them?" (This is V1's Pattern 6 with a new mechanism: V1's
guard dropped the *null* that meant "forged"; V2's guard drops the *actor role* that
means "self-service escalation.")

## 13. Your log schema is part of your detection surface — a field rename is a coverage outage.

R4 is dead, and not because its logic is wrong — its logic is fine. It matches on
`resource_path`, but a logging refactor renamed that field to `filename` and no
detection PR followed. A match over a field that no longer exists quietly evaluates to
nothing, forever. The 58 traversal reads sail past a rule written *specifically* to
catch traversal. Two takeaways: **(a)** a rule whose fire count drops to zero right
after any logging/schema change is a coverage regression until proven otherwise
(watch the export for it); **(b)** detections must be tested against the events the app
*actually emits today*, and schema changes have to fan out to the detection repo like
any other breaking change. Bonus subtlety here: even pointed at the right field, R4's
dedup keyed on `provider_id` — which the traversal leaves unchanged — so counting
distinct IDs still looks benign. Dedup on the thing that varies with the attack, not
the thing that's convenient.

## 14. SSRF's real target is the metadata service, and a URL-string allowlist is the wrong control.

The attacker's `source_url` was `http://169.254.169.254/…` — the cloud metadata
endpoint, which hands out **instance IAM credentials**. Three reasons the obvious
defenses fail: `169.254.0.0/16` is **link-local, not RFC1918**, so an "internal IP"
regex built from private ranges misses it (R3's exact gap); a **DNS name** that
resolves internally hides the destination from any check on the raw string; and a
**redirect** (see the follow-redirects CVE in this kit) can bounce an allowlisted host
to an internal one after the check passes. The control that actually works decides on
the **destination the service connected to** — egress/flow logs, a locked-down egress
proxy, IMDSv2 / metadata-blocking — not the URL the client typed. Any SSRF fix phrased
as "validate the input URL" is incomplete; ask "what happens on redirect, and what
does DNS resolve to at fetch time?"

## 15. "Green" can be worse than "red" — audit the rules that never fire *and* the ones that always look fine.

R2 showed 36 fires, 36 acknowledged, 0 open — immaculate. It was green **because** the
buggy scope filter meant it only ever saw benign admin activity; the healthy dashboard
was a direct product of the blind spot. Meanwhile R3 had never fired in its life
("assumed no SSRF") and R4 had gone silent after a refactor. Three different "looks
okay" signatures, three coverage failures. Operational metadata *is* security posture:
a never-fired high-severity rule and a always-perfectly-acknowledged high-severity rule
both deserve the same question — **"can this rule even see the thing it's for?"** A
clean queue is only good news if the rule is actually looking where the attack happens.
(V1's Pattern 7 was alert fatigue burying a real hit; V2 adds its inverse — a quiet,
tidy rule that's quiet *because* it's aimed at the wrong door.)

## 16. Sometimes the tool's number is right — distrust inferences, not arithmetic.

V1 trained you to catch inflated CVSS. V2 checks whether you overlearned it. The
scanner reports semver at **7.5** — and NVD agrees, that one's correct. It reports
follow-redirects at **7.3** — NVD says **6.1**, that one's inflated. A reflexive "the
scanner always lies, downgrade everything" gets the semver call wrong. The durable
habit isn't "distrust the number," it's **"verify the number, then separately verify
the inference built on it."** semver's CVSS is right *and* `reachable: true` is still
unproven, because the vulnerable sink (`new Range` on an untrusted range) isn't the
path the app calls (`semver.lt` on version strings). Two independent checks: is the
severity accurate, and is the vulnerable code actually reached? They have different
answers here, and a senior reports both.

---

### How to use these in a live assessment

- **Ask "identity or authorization?" first.** If real accounts are doing disallowed
  things, don't spend the hour in the auth logs (Pattern 9).
- **Enumerate privileged actions and find the missing guard** — you're hunting an
  absence, so a checklist beats a scan (Patterns 10, 11).
- **Read every rule as a claim about the system, and read its diff** (Pattern 12); and
  **read the log schema the rule depends on** (Pattern 13).
- **For SSRF, push the control to egress** and name the metadata service, link-local,
  DNS, and redirects explicitly (Pattern 14).
- **Audit the calm rules, not just the noisy ones** — never-fired and always-acked are
  both suspects (Pattern 15).
- **Verify the number *and* the inference** — don't let "scanners inflate CVSS" become
  its own bias (Pattern 16).
- **Carry every finding to consequence** — for V2 that's credentialing integrity and a
  breach-notification clock, not a CWE number (V1 Pattern 8).
- **Flag what you'd verify** (clause numbers, query syntax, CVSS provenance) instead of
  bluffing — honesty reads as senior.
