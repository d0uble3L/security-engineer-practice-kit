# Security Engineer Practice Kit — Take-Home Assessment Simulator

**Variant 2 (harder) · "Auravia Health" provider-svc**

This is the second run. If you did Variant 1, the shape is familiar — a real-feeling
service, a scanner report you can't trust, logs with an incident buried in noise,
and detection rules that look fine until you check them — but the bugs, the
incident, and the traps are different, and the pieces cut deeper. Variant 1's
strongest lessons don't transfer as answers; a couple of them are set up here
precisely so that applying them naively leads you wrong.

Everything here is fictional. Auravia Health, its code, its logs, and its incident
are invented for practice. The CVEs in the dependency data are real, public
advisories; everything else is made up.

---

## The scenario

**Auravia Health** runs a cloud-hosted platform for a network of outpatient
clinics. You've already reviewed `booking-svc` (Variant 1). Now you've been handed a
second, more sensitive service: **`provider-svc`**, the **provider directory,
credentialing, and availability** service. It's the system of record for *which
clinicians are allowed to see patients* — it stores provider identities, NPI and
license data, credentialing documents (license PDFs, DEA certs), and the
"verified / pending" status that governs whether a provider can be scheduled.

Two things make it higher-stakes than booking-svc:

1. **It has a self-service registration path** — providers can sign themselves up
   (pending credentialing) before any human reviews them.
2. **Credentialing is a trust decision.** A bug that lets the wrong person mark a
   provider "verified," or read another provider's credentialing file, isn't just a
   data-exposure issue — it's a patient-safety and licensing-integrity issue.

Same regulatory backdrop: Auravia operates under **HIPAA** and its largest hospital
customer contractually requires progress toward **HITRUST**.

You've been handed the service, its latest scanner output, 24 hours of logs from the
day of an incident, and the detection rules that were supposed to catch things. The
security lead wants your read before the risk review.

---

## What's in the box

```
INSTRUCTIONS.md              <- you are here
ASSESSMENT.md                <- the four tasks; your worksheet
service/provider-svc/        <- the codebase under review (the whole service repo, dotfiles included)
scans/scanner-report.json    <- output of "AuraScan", the SAST/SCA tool
data/app.log                 <- provider-svc application + access logs (24h, JSON lines)
data/gateway.log             <- auth-gateway audit logs (24h, JSON lines)
data/generate_logs.py        <- the generator (don't peek until you've done Task 2)
siem/                        <- the four deployed detection rules + a 30-day alert export
ANSWER-KEY.md                <- full solution + scoring rubric (don't open until you're done)
STUDY-GUIDE.md               <- what's new in V2, layered on the V1 patterns
```

---

## How to run it

1. **Time-box it.** Target ~2 hours for the four tasks. Going over is fine for
   learning; note where the time went.
2. **Work in `ASSESSMENT.md`.** There's no autograder; the value is the reasoning,
   which the answer key holds a mirror to.
3. **Treat the tools as unreliable narrators.** The scanner and the rules were
   written by a plausible, busy team. Some of what they say is right, some is wrong,
   and the wrong parts are wrong for reasons you can articulate.
4. **Carry the V1 lessons in, but don't autopilot.** In V1 the gateway's independent
   role knowledge exposed a forged token. Ask early whether that same move works
   here. (It doesn't — and understanding *why* is half of Task 2.)
5. **Don't open `ANSWER-KEY.md` early.** Grade after.

### Poking at the code (optional)

You do **not** need to run anything — it's a code-review and log-analysis exercise.
If you want to explore:

```bash
cd service/provider-svc
npm install          # dev only; do not deploy this service anywhere real
```

The logs are JSON lines. Useful starting points:

```bash
# every distinct event type in the app log
jq -r '.event' data/app.log | sort | uniq -c

# who changed role or credential_status, and were they an admin?
jq -c 'select(.event=="provider.updated")
       | select(.fields_changed | index("role") or index("credential_status"))
       | {ts,actor,actor_role,provider_id,fields_changed}' data/app.log

# every availability sync target host
jq -r 'select(.event=="availability.sync") | .source_url' data/app.log | sort -u

# document reads whose filename looks like traversal
jq -c 'select(.event=="document.read") | select(.filename|test("\\.\\.|%2e|%2f"))
       | {ts,actor,provider_id,filename}' data/app.log | head
```

---

## ⚠️ Before you rely on any of this as authoritative

This is a **training artifact**. Two classes of content must be verified before you
repeat them anywhere real (a report, an interview answer, a client deliverable):

- **Compliance clause numbers.** The HIPAA and HITRUST citations in the answer key
  are given to the best of general knowledge and labeled where they need checking.
  Regulatory text and control numbering change; confirm any specific citation
  against the current source before presenting it as fact.
- **Detection query syntax.** The rules in `siem/` are written in a readable,
  SPL-flavored pseudo-syntax to be reasoned about, not pasted into a live SIEM.
  Validate and port them to your actual backend before deploying — and note that
  two of this variant's gaps (a regex range in R3, a renamed field in R4) are
  exactly the kind of thing that behaves differently across backends.

The dependency CVEs are real and NVD-checkable — including a deliberate lesson about
*which* CVSS number you're being shown. The scanner's interpretation of them is not
always right. That's the point.
