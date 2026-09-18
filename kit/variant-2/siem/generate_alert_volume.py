#!/usr/bin/env python3
"""
Generates a 30-day alert-volume export for the four provider-svc detection rules,
covering the window that ENDS on the incident day (2025-06-17).

Two artifacts:
  - alert-volume-30d.csv     : per-day, per-rule alert counts + triage state
  - alert-volume-summary.json: per-rule rollup an analyst would see on a dashboard

Operational symptoms deliberately encoded (the Task-2 "why didn't the SOC notice?"
tells, consistent with the rule files and the logs):

  R1  noisy but UNREVIEWED. Fires on opportunistic self-signup scraper bursts.
      The triage queue stopped being worked weeks ago -> large open,
      unacknowledged backlog. A real precision registration (5 accounts, one IP)
      is both under threshold AND, even if it fired, would land in an ignored
      queue. R1 DID fire on the incident day (the 04:00 scraper burst of 35
      signups from 192.0.2.77), so the dashboard "looks healthy."

  R2  fires at a low, steady rate and is fully acknowledged -> looks like a
      healthy rule. But every fire is a legitimate med-staff (admin) console
      role/credential change; the rule was scoped to `actor_role=admin`, so the
      provider self-escalation in the incident is invisible to it. "Green and
      acknowledged" is not "covering the threat."

  R3  zero fires in the window. No legitimate sync ever targets an internal
      literal IP, and the attacker's link-local metadata target (169.254.169.254)
      is outside the rule's RFC1918/loopback regex. A high-severity rule that
      never fires deserves a "can this even match what we care about?" review.

  R4  zero fires. DEAD since the 2025-04-09 logging refactor renamed
      `resource_path` -> `filename`; the rule still matches on `resource_path`,
      which no longer exists on the events. The entire 30-day window is
      post-refactor, so R4 is silent straight through the document-exfil incident.
"""

import csv
import json
import random
from datetime import date, timedelta

SEED = 4242
random.seed(SEED)

START = date(2025, 5, 19)
DAYS = 30                        # 2025-05-19 .. 2025-06-17 inclusive
INCIDENT_DAY = date(2025, 6, 17)
R4_REFACTOR_DAY = date(2025, 4, 9)   # before the window -> R4 silent all window

rows = []
r1_open_backlog = 0

for i in range(DAYS):
    d = START + timedelta(days=i)
    weekday = d.weekday()
    is_weekend = weekday >= 5

    # ---- R1: noisy self-signup scraper alerts ---------------------------
    base = random.randint(2, 5)
    if not is_weekend:
        base += random.randint(0, 3)
    # a couple of loud scraper days
    if d in (date(2025, 5, 27), date(2025, 6, 9)):
        base += random.randint(7, 11)
    # incident day: the 04:00 scraper burst (35 signups) trips R1
    if d == INCIDENT_DAY:
        base += 3
    r1_fires = base

    # Triage effectively stopped on 2025-06-02. Before, ~most acknowledged.
    if d <= date(2025, 6, 2):
        r1_ack = int(round(r1_fires * random.uniform(0.7, 0.95)))
    else:
        r1_ack = int(round(r1_fires * random.uniform(0.0, 0.12)))
    r1_ack = min(r1_ack, r1_fires)
    r1_open_backlog += (r1_fires - r1_ack)

    # ---- R2: low steady legit admin credential/role changes -------------
    # med-staff console verifies/updates; higher on weekdays, ~all acknowledged.
    r2_fires = 0 if is_weekend and random.random() < 0.6 else random.randint(0, 3)
    r2_ack = r2_fires  # expected, worked same day

    # ---- R3 / R4: silent for the reasons above --------------------------
    r3_fires = 0
    r4_fires = 0

    rows.append({
        "date": d.isoformat(),
        "R1_fires": r1_fires,
        "R1_acknowledged": r1_ack,
        "R1_open_cumulative": r1_open_backlog,
        "R2_fires": r2_fires,
        "R2_acknowledged": r2_ack,
        "R3_fires": r3_fires,
        "R4_fires": r4_fires,
    })

# ---- write daily CSV -----------------------------------------------------
csv_path = "alert-volume-30d.csv"
with open(csv_path, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)

# ---- rollup summary ------------------------------------------------------
r1_total = sum(r["R1_fires"] for r in rows)
r1_ack_total = sum(r["R1_acknowledged"] for r in rows)
r1_open_total = r1_total - r1_ack_total
r2_total = sum(r["R2_fires"] for r in rows)
r2_ack_total = sum(r["R2_acknowledged"] for r in rows)

summary = {
    "export_generated": "2025-06-18T06:00:00Z",
    "window": {"start": START.isoformat(),
               "end": (START + timedelta(days=DAYS - 1)).isoformat(),
               "days": DAYS},
    "note": "Illustrative fiction for the practice kit. Counts are generated, "
            "not measured. Use to reason about operational blind spots, not as "
            "real telemetry.",
    "rules": [
        {
            "id": "R1-registration-abuse",
            "severity": "medium",
            "fires_30d": r1_total,
            "acknowledged_30d": r1_ack_total,
            "open_unacknowledged": r1_open_total,
            "last_fired": INCIDENT_DAY.isoformat(),
            "last_queue_triaged": "2025-06-02",
            "last_rule_review": "2025-01-20",
            "analyst_note": "high-volume, ~all opportunistic signup scrapers; "
                            "queue not worked since Jun 2."
        },
        {
            "id": "R2-privilege-self-change",
            "severity": "high",
            "fires_30d": r2_total,
            "acknowledged_30d": r2_ack_total,
            "open_unacknowledged": r2_total - r2_ack_total,
            "last_fired": "2025-06-16",
            "last_rule_review": "2025-03-11",
            "analyst_note": "fires low and steady, all legit med-staff admin "
                            "changes, fully acknowledged. Looks healthy."
        },
        {
            "id": "R3-ssrf-internal-egress",
            "severity": "high",
            "fires_30d": 0,
            "acknowledged_30d": 0,
            "open_unacknowledged": 0,
            "last_fired": None,
            "fires_all_time": 0,
            "last_rule_review": "2025-02-18",
            "analyst_note": "has never fired since creation; assumed 'no SSRF.'"
        },
        {
            "id": "R4-document-exfil",
            "severity": "high",
            "fires_30d": 0,
            "acknowledged_30d": 0,
            "open_unacknowledged": 0,
            "last_fired": "2025-04-08",
            "last_rule_review": "2025-04-09",
            "analyst_note": "silent since the 2025-04-09 logging refactor "
                            "(resource_path -> filename); no fires in window."
        }
    ]
}

with open("alert-volume-summary.json", "w") as f:
    json.dump(summary, f, indent=2)

print(f"wrote {csv_path} ({len(rows)} days)")
print(f"R1 30d fires={r1_total} ack={r1_ack_total} open_backlog={r1_open_total}")
print(f"R2 30d fires={r2_total} ack={r2_ack_total}")
print("R3/R4 30d fires = 0 / 0")
