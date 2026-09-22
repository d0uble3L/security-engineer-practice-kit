# Security Engineer Practice Kit — Take-Home Assessment Simulator

**Variant 1 · "Auravia Health" booking-svc**

This kit reproduces the kind of practical exercise used to screen security
engineers: a real-feeling service, a scanner report you can't take at face value,
log data with a real incident buried in noise, and detection rules that look fine
until you check them against what actually happened. You work the same judgment a
take-home or a practical interview is really testing — not "can you find a bug"
but "can you rank what matters, catch the tool when it's wrong, and say why."

Everything here is fictional. Auravia Health, its code, its logs, and its incident
are invented for practice. The CVEs referenced in the dependency data are real,
public advisories (that's what normal SCA data looks like); everything else is
made up.

---

## The scenario

**Auravia Health** runs a cloud-hosted patient-scheduling platform for a network
of outpatient clinics. It's a ~40-person company: a handful of product engineers,
a two-person security function, and a compliance lead who reports to the COO.
Because it stores and processes patient health information (PHI), it operates under
**HIPAA**, and its largest hospital customer contractually requires it to be
working toward **HITRUST** certification.

You've been handed one service — **`booking-svc`**, the appointment booking and
lookup microservice — plus its latest scanner output, 24 hours of logs from the
night of an incident, and the detection rules that were supposed to catch things.
The security lead wants your read before their Monday risk review.

---

## What's in the box

```
INSTRUCTIONS.md         <- you are here
ASSESSMENT.md           <- the four tasks; this is your worksheet
service/booking-svc/    <- the codebase under review (the whole service repo, dotfiles included)
scans/scanner-report.json   <- output of "AuraScan", the SAST/SCA tool
data/app.log            <- booking-svc application + access logs (24h, JSON lines)
data/gateway.log        <- auth-gateway audit logs (24h, JSON lines)
data/generate_logs.py   <- the generator (don't peek until you've done Task 2)
siem/                   <- the four deployed detection rules + a 30-day alert export
ANSWER-KEY.md           <- full solution + scoring rubric (don't open until you're done)
STUDY-GUIDE.md          <- 8 recurring judgment patterns these assessments test
variant-2/              <- a second, harder run with a different service and bugs
```

---

## How to run it

1. **Time-box it.** Target ~2 hours for the four tasks, the way a real take-home
   is scoped. Going over is fine for learning; just note where the time went.
2. **Work in `ASSESSMENT.md`.** Each task tells you what to produce. Write your
   answers in your own file or inline — there's no autograder; the value is in the
   reasoning, which the answer key then holds up a mirror to.
3. **Treat the tools as unreliable narrators.** The scanner and the detection
   rules were written by a plausible, busy team. Some of what they say is right,
   some is wrong, and the wrong parts are wrong for reasons you can articulate.
4. **Don't open `ANSWER-KEY.md` early.** The whole skill is arriving at the
   ranking yourself. Grade after.
5. **Then do Variant 2** for a second rep on different bugs.

### Poking at the code (optional)

You do **not** need to run anything to complete the assessment — it's a
code-review and log-analysis exercise. If you want to explore:

```bash
cd service/booking-svc
npm install          # dev only; do not deploy this service anywhere real
```

The logs are JSON lines. Useful starting points:

```bash
# every distinct event type in the app log
jq -r '.event' data/app.log | sort | uniq -c

# gateway view of one request id
jq -c 'select(.request_id=="req-000001")' data/gateway.log

# traffic from a single source ip
jq -c 'select(.src_ip=="185.220.101.7")' data/app.log | head
```

---

## ⚠️ Before you rely on any of this as authoritative

This is a **training artifact**, and two classes of content in it must be verified
before you repeat them anywhere real (a report, an interview answer you're staking
a claim on, a client deliverable):

- **Compliance clause numbers.** The HIPAA and HITRUST citations in the answer key
  are given to the best of general knowledge and are labeled where they need
  checking. Regulatory text and control numbering change; confirm any specific
  citation against the current source before presenting it as fact.
- **Detection query syntax.** The rules in `siem/` are written in a readable,
  SPL-flavored pseudo-syntax to be reasoned about, not pasted into a live SIEM.
  Validate and port them to your actual backend before deploying.

The dependency CVEs are real and can be checked against the NVD. The scanner's
*interpretation* of them is deliberately not always right — that's the point.
