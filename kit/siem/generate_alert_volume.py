#!/usr/bin/env python3
"""
Generates a 30-day alert-volume export for the four booking-svc detection rules,
covering the window that ENDS on the incident day (2025-03-11).

Two artifacts:
  - alert-volume-30d.csv     : per-day, per-rule alert counts + triage state
  - alert-volume-summary.json: per-rule rollup an analyst would see on a dashboard

Operational symptoms deliberately encoded (these are the Task-2 "why didn't the
SOC notice?" tells, and they are consistent with the rule files and the logs):

  R1  noisy but UNREVIEWED. Fires many times/day on opportunistic internet
      scanners. The triage queue stopped being worked weeks ago -> large open,
      unacknowledged backlog. Real signal buried here would never be looked at.
      NOTE: R1 *did* fire on the incident day (the two loud benign brute bursts
      at 03:00 and 21:00), so the dashboard "looks healthy" for R1.

  R2  has NEVER fired. Zero alerts across the whole window (and, per its own
      metadata, zero since it was created). Read by the team as "no SQLi
      attempts," never investigated as "maybe the rule can't match what we log."

  R3  zero fires since the 2025-02-03 "isnotnull(gw_known_role)" guard landed.
      Window is entirely post-guard, so it sits silent through the forged-token
      incident.

  R4  zero fires since the 2024-12-10 user-agent allowlist landed. The only
      heavy reader is the (allowlisted) reminder batch; the spoofed-UA attacker
      is suppressed the same way.
"""

import csv
import json
import random
from datetime import date, timedelta

SEED = 1337
random.seed(SEED)

START = date(2025, 2, 10)
DAYS = 30                       # 2025-02-10 .. 2025-03-11 inclusive
INCIDENT_DAY = date(2025, 3, 11)

rows = []
r1_open_backlog = 0             # accumulates: alerts raised but never triaged

for i in range(DAYS):
    d = START + timedelta(days=i)
    weekday = d.weekday()       # 0=Mon .. 6=Sun
    is_weekend = weekday >= 5

    # ---- R1: noisy internet-scanner brute-force alerts -------------------
    base = random.randint(3, 7)
    if not is_weekend:
        base += random.randint(0, 4)
    # a couple of loud scanning days
    if d in (date(2025, 2, 18), date(2025, 3, 4)):
        base += random.randint(8, 12)
    # incident day: the two benign brute bursts (03:00, 21:00) both trip R1
    if d == INCIDENT_DAY:
        base += 2
    r1_fires = base

    # Triage effectively stopped on 2025-02-21. Before that, ~most acknowledged.
    # After, almost nothing gets acknowledged -> backlog grows.
    if d <= date(2025, 2, 21):
        r1_ack = int(round(r1_fires * random.uniform(0.7, 0.95)))
    else:
        r1_ack = int(round(r1_fires * random.uniform(0.0, 0.1)))
    r1_ack = min(r1_ack, r1_fires)
    r1_open_backlog += (r1_fires - r1_ack)

    # ---- R2 / R3 / R4: silent for the reasons above ----------------------
    r2_fires = 0
    r3_fires = 0
    r4_fires = 0

    rows.append({
        "date": d.isoformat(),
        "R1_fires": r1_fires,
        "R1_acknowledged": r1_ack,
        "R1_open_cumulative": r1_open_backlog,
        "R2_fires": r2_fires,
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

summary = {
    "export_generated": "2025-03-12T06:00:00Z",
    "window": {"start": START.isoformat(),
               "end": (START + timedelta(days=DAYS - 1)).isoformat(),
               "days": DAYS},
    "note": "Illustrative fiction for the practice kit. Counts are generated, "
            "not measured. Use to reason about operational blind spots, not as "
            "real telemetry.",
    "rules": [
        {
            "id": "R1-login-bruteforce",
            "severity": "medium",
            "fires_30d": r1_total,
            "acknowledged_30d": r1_ack_total,
            "open_unacknowledged": r1_open_total,
            "last_fired": INCIDENT_DAY.isoformat(),
            "last_queue_triaged": "2025-02-21",
            "last_rule_review": "2024-11-30",
            "analyst_note": "high-volume, ~all opportunistic scanners; queue not "
                            "worked since Feb 21."
        },
        {
            "id": "R2-sqli-search",
            "severity": "high",
            "fires_30d": 0,
            "acknowledged_30d": 0,
            "open_unacknowledged": 0,
            "last_fired": None,
            "fires_all_time": 0,
            "last_rule_review": "2024-09-02",
            "analyst_note": "has never fired since creation; assumed 'no SQLi.'"
        },
        {
            "id": "R3-privilege-claim-mismatch",
            "severity": "high",
            "fires_30d": 0,
            "acknowledged_30d": 0,
            "open_unacknowledged": 0,
            "last_fired": "2025-01-28",
            "last_rule_review": "2025-02-03",
            "analyst_note": "silent since the 2025-02-03 change; no fires in window."
        },
        {
            "id": "R4-sensitive-record-enumeration",
            "severity": "high",
            "fires_30d": 0,
            "acknowledged_30d": 0,
            "open_unacknowledged": 0,
            "last_fired": "2024-12-09",
            "last_rule_review": "2024-12-10",
            "analyst_note": "silent since the 2024-12-10 allowlist; no fires in window."
        }
    ]
}

with open("alert-volume-summary.json", "w") as f:
    json.dump(summary, f, indent=2)

print(f"wrote {csv_path} ({len(rows)} days)")
print(f"R1 30d fires={r1_total} ack={r1_ack_total} open_backlog={r1_open_total}")
print("R2/R3/R4 30d fires = 0 / 0 / 0")
