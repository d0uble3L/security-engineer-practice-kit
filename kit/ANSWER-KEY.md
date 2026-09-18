# Answer Key & Rubric — Variant 1 (Auravia Health · booking-svc)

Read this *after* attempting the assessment. It has three parts:

- **Ground truth** — every planted issue, what's real, and where the scanner lies.
- **Task-by-task model answers.**
- **Scoring rubric** — what a junior vs. a senior answer looks like on each task,
  so you can grade yourself honestly.

> **Verification flags.** HIPAA/HITRUST clause numbers below are marked
> `⚠[verify]` where you should confirm the citation against the current regulatory
> source before using it as authoritative. Detection logic is pseudo-SPL — marked
> `⚠[syntax]` — and must be validated on a real backend before deployment. The
> package CVEs are real and NVD-checkable; the scanner's interpretation of them is
> deliberately not.

---

## Part A — Ground truth (the planted issues)

### Genuinely critical (across different categories)

| # | Issue | Location | Category | Scanner verdict |
|---|-------|----------|----------|-----------------|
| C1 | **JWT signature never verified** — `jwt.decode()` used instead of `jwt.verify()`; any well-formed token is trusted, so an attacker forges an `admin` token with no secret. | `src/middleware/auth.js:17` | Broken authentication (CWE-347) | **MISSED** |
| C2 | **SQL injection** — `req.query.patientName` concatenated into `db.raw()`. | `src/routes/appointments.js:16–23` | Injection (CWE-89) | CRITICAL — **correct** (SAST-001) |
| C3 | **IDOR / BOLA on patients** — `GET /patients/:id` returns full PHI with no ownership/role check; any authenticated caller reads any patient. | `src/routes/patients.js:9` | Broken access control (CWE-639) | **MISSED** |
| C4 | **IDOR / BOLA on appointments** — `GET /appointments/:id` same problem, returns `dob`/`ssn_last4`. | `src/routes/appointments.js:33` | Broken access control (CWE-639) | **MISSED** |
| C5 | **CI secret exfiltration** — `pull_request_target` + checkout of the PR's head SHA + real secrets (incl. `JWT_SECRET`) in env → a fork PR runs attacker code with the secrets. | `.github/workflows/ci.yml` | Insecure CI/CD, supply chain (CWE-safe: "poisoned pipeline execution") | **MISSED** (despite scope claim) |

C1 + C3/C4 are the incident. C5 is the quiet catastrophe: leaking `JWT_SECRET`
would let an attacker forge tokens *even if C1 were fixed* — the two auth failures
are independent paths to the same forgery.

### Severity wrong in one direction or the other

| # | Issue | Location | Scanner said | Truth |
|---|-------|----------|--------------|-------|
| S1 | **Reflected CORS + credentials** — echoes `Origin` and sets `Allow-Credentials: true`; any site can make credentialed cross-origin calls. | `src/server.js:19–25` | MEDIUM (SAST-006) | **Under-rated → HIGH.** With credentials, this is authenticated data theft, not a headers nit. |
| S2 | **Hard-coded prod secrets** — DB password *and* JWT signing secret as literals. | `src/config.js:15, 20` | MEDIUM, and only flags **line 17** area (the password); **misses the JWT secret on line 20** | **Under-rated → HIGH.** The JWT secret in source is the more dangerous of the two and the scanner didn't even flag it. |
| S3 | **No rate limiting / lockout on `/login`.** | `src/routes/auth.js:13` | LOW (SAST-005) | **Under-rated in context → MEDIUM.** In isolation low; here it's the *entry stage* of the real incident. |
| S4 | **"Reflected XSS"** — flagged on the search response. | `src/routes/appointments.js:24` | HIGH (SAST-002) | **FALSE POSITIVE.** The handler returns `res.json(...)`; `name` flows into a *SQL string*, not HTML output. Dismiss it (the real bug on those lines is C2, not XSS). |
| S5 | **lodash CVE-2021-23337** (real). | `package.json` lodash 4.17.15 | CRITICAL, reported_cvss **9.8**, `reachable:true` | **Over-rated.** Real CVSS is **7.2**; the vulnerable `template()` sink isn't used (code only calls `_.pick`), so "reachable" is unproven. Patch anyway (trivial bump to 4.17.21) but it's not a Sev-1. |
| S6 | **axios CVE-2023-45857** (real). | `package.json` axios 1.5.0 | HIGH, reported_cvss **8.1** | **Over-rated.** Real CVSS is **6.5** (medium). Legit finding; bump to ≥1.6.0. |
| S7 | **minimist CVE-2021-44906** (real, CVSS 9.8). | `package-lock.json` (under **nodemon**, a devDependency) | CRITICAL, `reachable:true` | **Over-rated in context.** It's a **dev-only transitive** — not shipped, not reachable at runtime. The lockfile is where you prove that; the scanner's `reachable` flag is wrong. Low priority. |

### Real but low priority

| # | Issue | Location | Scanner | Truth |
|---|-------|----------|---------|-------|
| L1 | **PHI written to application logs** — `patient_name`, `dob`, `ssn_last4` logged on every appointment view. | `src/routes/appointments.js:43–49` | **MISSED** | Real, **MEDIUM** — the log index itself becomes PHI (compliance + blast-radius issue). Arguably higher than low; grade generously if ranked medium. |
| L2 | **Verbose error** — `err.stack` returned to client on `/search` failure. | `src/routes/appointments.js:27` | LOW (SAST-004) | **Correct.** Minor info leak. |
| L3 | **Missing security headers** (no `helmet`). | `src/server.js` | LOW (SAST-007) | **Correct.** Real, low. |

### Hiding in project metadata (called out because the brief demands it)
- **C5** (CI workflow) — non-application code; the highest-severity thing the
  scanner missed.
- **S7 / lockfile** — the *only* place you can correctly rule minimist down to
  "dev-only" is `package-lock.json`. Reading the lockfile beats trusting the
  scanner's reachability flag.
- Incidental: the lockfile's `integrity` hashes are placeholder `EXAMPLEHASH…`
  strings. That's a kit artifact (not a gradable finding), but a sharp reviewer who
  notices should know real lockfile integrity hashes are how you'd detect tampering
  — a good instinct, not a planted bug.

### The scanner's 30-second credibility tells (Task 1.3)
1. **`total_findings: 12` but the `findings` array has 10** — and the severity
   breakdown (3+2+2+3) also sums to **10**. The summary contradicts itself and the
   data. Instant "don't trust the counts."
2. **`ruleset: "OWASP Top 10 2017"`** — stale. 2021 moved **Broken Access Control
   to #1**; a 2017-era ruleset is exactly why it sailed past both IDORs.
3. **`scope` claims "IaC and pipeline configs"** yet the CI workflow (C5) is
   missed — the scope claim doesn't hold.
4. **`taint_analysis: true`, `deep_dataflow: true`, `reachability_analysis:
   enabled`** — yet it misses the `jwt.decode` dataflow (C1), both IDORs, and
   mis-calls minimist reachability (S7). The capability claims don't survive
   contact with the findings.

Any two of these is enough to say "this report is an input, not a verdict."

---

## Part B — Task-by-task model answers

### Task 1 — model ranking

A defensible senior ranking (yours may reorder C1–C5 with justification):

1. **C1 — JWT not verified.** Full auth bypass to `admin`. Trivially exploitable,
   and it's what actually happened. Fix: `jwt.verify(token, config.jwtSecret)` with
   algorithm pinning; reject on failure.
2. **C5 — CI secret exfiltration.** Leaks `JWT_SECRET` (and DB/reminder creds) to
   any fork PR. Independent path to token forgery + full DB creds. Fix: drop
   `pull_request_target`, or gate on label + never check out untrusted head with
   secrets in scope.
3. **C3/C4 — IDOR on patients & appointments.** Direct PHI exposure to any logged-in
   user; the exfiltration mechanism in the incident. Fix: enforce ownership/role on
   every record fetch (the caller's `sub`/`role` vs. the record's owner).
4. **C2 — SQL injection.** Real, critical, but the scanner already caught it and
   it's parameterizable immediately. Fix: parameterized query / `db.query(text,
   params)`; delete `db.raw`.
5. **S2 — hard-coded JWT secret & DB password.** Enables/compounds forgery. Rotate,
   move to a secret store, remove fallbacks.
6. **S1 — CORS + credentials.** Cross-origin credentialed theft. Allowlist origins;
   never reflect.
7. **S3 — no login rate limiting.** Entry stage; add throttle + lockout.
8. **L1 — PHI in logs.** Redact `dob`/`ssn_last4`/name from logs.
9. **S6 — axios**, **S5 — lodash**, then **S4 dismissed (false positive)** and
   **S7 minimist (dev-only, lowest)**; **L2/L3** housekeeping.

**Most dangerous single issue:** C1 (or a tie argued between C1 and C5). The
two-sentence version: *"Auth is decorative — we `decode` tokens instead of
verifying them, so anyone can mint an admin token and read every patient's PHI. It
needs a one-line fix today and it's already been used."*

### Task 2 — model answer

**Incident timeline** (attacker `185.220.101.7`, spoofing the batch job's UA
`Auravia-BatchReminder/1.2`, forged subject `user-70142`):

- **Stage A — 14:00–14:20, credential stuffing.** Paced ~15 failed logins per
  5-min block against 7 real-looking usernames. All `outcome=fail`. Chains **S3**
  (no lockout). *Under R1's 20/5m threshold by design.*
- **Stage B — 14:21–14:22, SQLi probes + forged token appears.** Two encoded SQLi
  attempts on `/appointments/search` (500s), then requests bearing an **`admin`**
  token. Gateway tell: on every `request.forward` for `token_sub=user-70142`,
  `token_role_claim="admin"` while `gw_known_role=null` — the gateway never issued
  this subject an admin session, so the claim is uncorroborated. (In the whole
  window, *every* `admin` claim carries `gw_known_role=null` and *every* one comes
  from the attacker IP; legitimate patient/staff/service traffic always has the two
  fields agreeing.) Chains **C1** (forgery) and probes **C2**.
- **Stage C — 14:23–14:40, IDOR mass enumeration.** ~430 sequential reads across
  `/patients/{id}` and `/appointments/{id}` under the forged admin token, single
  IP, ~2.3s pacing, all 200s. Chains **C3/C4**. This is the PHI exfiltration.

Kill chain: **S3 → C1 → C3/C4**, with **C5** as the alternate route to C1.

**Per-rule failure analysis:**

- **R1 (brute force):** threshold is **20 fails / 5 min per IP**; the attacker paced
  at **15 / 5 min**. Tuned under it. (Bonus: the 2024-11-30 changelog shows the
  threshold was raised 8→20 to cut scanner noise — a real, reviewed change that
  widened the blind spot.) The two loud internet bursts (~28/5m) *do* fire, which
  is why R1 looks healthy.
- **R2 (SQLi):** the rule regexes for **decoded** tokens (`UNION SELECT`,
  `' OR '1'='1`, `--`) but the payload is logged **URL-encoded** in `path`
  (`%27%20OR%20…`). No urldecode in the pipeline → zero matches. Consistent with
  "never fired" in the export.
- **R3 (privilege-claim mismatch):** **this is the reasonable-looking commit — read
  the R3 changelog diff.** The rule fires when `token_role_claim != gw_known_role`,
  which is exactly the forgery signature. The 2025-02-03 commit added
  `| where isnotnull(gw_known_role)` to stop "restart/cache-warmup" false positives
  (during warmup the session store briefly returns null and every in-flight request
  alerted). But `gw_known_role` is null **precisely when the token is forged** — the
  gateway has no session for the subject — so the guard filters out the exact rows
  that matter *before* the comparison runs. The commit message reads like sound
  noise reduction ("killed the restart-time alert storms") and was reviewed and
  approved. (Secondary subtlety worth naming: on many backends
  `token_role_claim != gw_known_role` with one null operand evaluates to null, not
  true, under three-valued logic — so even without the guard a naive `!=` can miss
  the null rows. The null isn't the absence of signal; it *is* the signal.)
- **R4 (bulk record access):** the threshold (`dc(record_id) > 100 / 10m`) would
  have caught the ~430-record walk easily. It fails on the **allowlist**: the
  2024-12-10 commit added `NOT user_agent="Auravia-BatchReminder/1.2"` to suppress
  nightly pages from the legitimate reminder batch. The attacker **sets that exact
  user-agent**, opting out of the one rule built to catch what they did. Root cause:
  the allowlist keys on a **client-controlled header** instead of the batch job's
  real identity (`user_id=svc-reminders` + `src_ip=10.0.6.12`).

**What the 30-day export shows (two independent ops problems):**
1. **R2 has never fired (0 all-time; `fires_all_time: 0`).** "No SQLi ever" was read
   as good news; it actually means the rule is structurally incapable of firing (the
   encoding gap). A high-severity rule that has *never* fired should trigger a "can
   this rule even match what we log?" review, not comfort. (R3 and R4 also went
   silent immediately after their respective commits — "went quiet right after a
   change" is itself a tell a sharp candidate names.)
2. **R1 is noisy but unreviewed — a growing unacknowledged backlog (~140 open).**
   R1 fires ~237×/30d on opportunistic internet scanners, but acknowledgment
   collapses after 2025-02-21 and the open queue climbs. A rule that fires
   constantly and is never worked is functionally *off*: a genuine brute-force lands
   in an ignored queue. Alert fatigue as a control failure. Note R1 *did* fire on
   the incident day (the two loud benign bursts), so the dashboard "looks healthy."

**Highest-leverage fix:** repair **R3** — it sits at the pivot of the kill chain and
catches the forgery the instant the token is *used* (Stage B), before any PHI is
read. Corrected logic ⚠[syntax] — remove the guard, normalize null before
comparison, and treat "privileged claim + null/absent known role" as an alert in
its own right:

```
index=auravia-gw-auth event=request.forward
| eval known = coalesce(gw_known_role, "NONE")
| where token_role_claim != known
    OR (token_role_claim IN ("admin","service") AND known="NONE")
| stats count, values(path) as paths, min(_time), max(_time) by token_sub, src_ip
| where count > 0
```

New false positives: genuine gateway restarts / cache warmups (the thing the guard
was protecting against). Bound them by (a) scoping the null-side alert to
*privileged* claims only (admin/service), where a warmup race is rarer and
higher-stakes; (b) requiring the mismatch to persist across N seconds or M requests,
so a single-request warmup blip self-clears while a 40-minute attacker does not; (c)
emitting warmup windows as a separate low-severity signal rather than dropping them
— defense in depth, not deletion. A close second is R4: re-key the allowlist off
`user_id="svc-reminders"` **and** `src_ip=10.0.6.12` (identities the client can't
set), never off the user-agent.

### Task 3 — model answer (compliance)

Findings → **HIPAA Security Rule** safeguards. Clause numbers ⚠[verify]:

- **C1, C3, C4, S1 → Access Control / Person-or-Entity Authentication.** Technical
  safeguards, ⚠[verify] *45 CFR § 164.312(a)(1)* (access control) and *§ 164.312(d)*
  (authentication). Unverified tokens + no per-record authorization = failure to
  restrict PHI access to authorized persons.
- **S2 (hard-coded JWT secret), C5 (secret leakage) → Authentication + integrity of
  access controls;** also an Administrative *risk-management* failure ⚠[verify]
  *§ 164.308(a)(1)*.
- **L1 (PHI in logs) → Audit Controls** ⚠[verify] *§ 164.312(b)* and **Minimum
  Necessary** (Privacy Rule) ⚠[verify] *§ 164.502(b)* — you've turned an audit
  mechanism into an uncontrolled PHI store.
- **S1, S6 (axios token leak) → Transmission Security** ⚠[verify] *§ 164.312(e)(1)*.
- **Detection gaps (R1–R4) + the unreviewed R1 backlog → Information System Activity
  Review**, an Administrative safeguard ⚠[verify] *§ 164.308(a)(1)(ii)(D)*: the rule
  requires *regularly reviewing* records of system activity. A ~140-alert
  unacknowledged backlog and a rule that has never fired are that safeguard failing
  in practice.

**Sharpest regulatory teeth:** the **IDOR PHI exfiltration (C3/C4 via C1)**. It's
not a hypothetical — the logs show ~430 records including `ssn_last4` and `dob`
read by an unauthorized party. That's the profile of a **reportable breach** of
unsecured PHI, which triggers HIPAA **Breach Notification** obligations ⚠[verify]
*45 CFR §§ 164.400–414* (notice to individuals, HHS, and possibly media by
thresholds). Lead the compliance conversation there, because it converts a
"vulnerability" into a "notification clock."

**Monitoring gap for a non-engineer:** *"HIPAA doesn't just require us to log
activity — it requires us to actually review it. Right now one of our alarms has
been ringing for weeks with a pile of unread alerts nobody works, and another has
never gone off once since we installed it. To an
auditor that reads as 'they have smoke detectors they don't listen to.'"* Maps to
the activity-review safeguard ⚠[verify] and to HITRUST monitoring controls
⚠[verify] (HITRUST CSF maps to HIPAA; cite the specific control only after
checking).

### Task 4 — what good looks like
There's no single answer, but a strong Task 4 (a) is specific about *where* AI was
used, (b) names a concrete independent check (e.g., "I confirmed the lodash CVSS on
the NVD rather than trusting the scanner's 9.8"), (c) draws a real line around
judgment (ranking, breach determination) and around **PHI**: synthetic here, but the
rule for real log/PHI data is *don't paste it into third-party AI without a BAA and
data controls*, and (d) can name a place AI would be confidently wrong — the
scanner report is the built-in example; the human check is reading the code and the
lockfile yourself.

---

## Part C — Scoring rubric (junior vs. senior)

Score each task 0–4. **Junior ≈ finds things. Senior ≈ ranks things, catches the
tools, and ties it to consequences.**

### Task 1 — Vulnerability triage
- **0–1:** Re-lists the scanner output; trusts its severities; misses the missed
  criticals.
- **2 (junior):** Finds most real bugs including at least one scanner miss (an
  IDOR). Ranks roughly by CVSS. May keep the XSS false positive.
- **3:** Finds C1 (jwt.decode) *and* at least one metadata finding (C5 or the
  lockfile point). Dismisses the XSS FP. Corrects at least two mis-rated
  severities with reasons.
- **4 (senior):** Context-ranks (PHI + reachability, not raw CVSS); catches C1 and
  C5 and both IDORs; corrects over- *and* under-rated findings; nails ≥2 scanner
  metadata tells including the 12-vs-10 count; picks the most-dangerous issue and
  justifies it in business terms. Rules minimist down using the lockfile.

### Task 2 — Detection engineering
- **0–1:** Can't locate the incident, or blames "bad rules" generically.
- **2 (junior):** Reconstructs the incident and finds 1–2 rule gaps (usually R1's
  threshold and R4's allowlist — the visible ones).
- **3:** All four gaps, each specific; finds the R3 commit and reads the null-vs-
  string logic; uses `request_id`/`gw_known_role` correlation across both logs.
- **4 (senior):** All of the above **plus** reads the alert export as evidence
  (never-fired R2, unreviewed R1 backlog) and reads "went silent right after a
  commit" as a tell; proposes the R3 fix at the kill-chain pivot and honestly scopes
  its new false positives instead of just widening the net.

### Task 3 — Compliance mapping
- **0–1:** "It's a HIPAA violation" with no safeguard named; or invents confident
  clause numbers.
- **2 (junior):** Maps code bugs to the right *safeguard families* (access control,
  transmission). Doesn't reach monitoring or breach.
- **3:** Includes a detection/monitoring gap as a compliance gap (activity review);
  identifies the breach-notification angle.
- **4 (senior):** Leads with breach determination and the notification clock;
  frames the monitoring gap for a non-engineer; **flags every unverified clause
  number instead of bluffing** — the honesty is itself scored.

### Task 4 — AI-usage reflection
- **0–1:** "I didn't use AI" full stop, or hand-waves.
- **2 (junior):** Names where AI helped and that they "checked it."
- **3:** Gives a concrete verification method tied to a primary source; draws a
  real do-not-delegate line.
- **4 (senior):** All that, plus a specific "AI would be confidently wrong here"
  example with the catch, and a clear PHI/BAA data-handling rule for the real-world
  version of this work.

**Senior bar overall:** decisive ranking over completeness, tools treated as
fallible inputs, technical findings translated into consequences (breach clock,
notification, customer trust), and intellectual honesty about what needs
verification.
