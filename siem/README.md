# Auravia Health — Detection Content (booking-svc)

This directory is a snapshot of the detection-as-code repo the (fictional) Auravia
Health detection team has deployed against `booking-svc` telemetry. It contains
four production rules and a 30-day alert-volume export.

Your job in Task 2 is **not** to admire these rules — it's to figure out why the
incident in `data/` walked straight past all four of them, and what minimal,
defensible change fixes each gap without drowning the SOC in false positives.

---

## Log sources these rules run against

| Index              | Source file        | What it holds                                  |
|--------------------|--------------------|------------------------------------------------|
| `booking-svc-app`  | `data/app.log`     | Application HTTP access + record-view events   |
| `auravia-gw-auth`  | `data/gateway.log` | Auth-gateway login outcomes + forwarded-request audit |

### `booking-svc-app` fields (JSON lines)
`ts, level, event, method, path, status, latency_ms, src_ip, user_id,
user_role, request_id, user_agent, bytes` — plus `record_id` on
`event in ("appointment.view","patient.view")`.

### `auravia-gw-auth` fields (JSON lines)
- `event="auth.login"`: `ts, src_ip, username, outcome, reason, user_agent`
- `event="request.forward"`: `ts, request_id, src_ip, path, method, token_sub,
  token_role_claim, gw_known_role, status`

`token_role_claim` is the role asserted **inside the JWT**. `gw_known_role` is the
role the gateway independently knows for that subject from its own session store
(`null` when the gateway never issued/loaded a session for that subject). A gap
between the two is the whole ballgame — see R3.

---

## ⚠️ Verification flag (read before selling or deploying)

The `query:` block in each rule is written in a **Splunk-SPL-flavored
pseudo-syntax** chosen because these logs land in named indexes. It is meant to be
*read and reasoned about*, not copy-pasted into a live SIEM. **Before using any of
these queries as authoritative, port and validate them against your actual backend**
(Splunk SPL, Sentinel KQL, Elastic ES|QL, Panther Python, Sigma + a pipeline, etc.).
Field extraction, `stats`/`bin` semantics, timerange handling, and null comparison
behavior differ across backends and *will* change whether a rule fires. Where a
gap in these rules depends on null-vs-string comparison (R3) or URL-decoding
(R2), that behavior is backend-specific and must be confirmed on the real
platform.

Rule IDs, thresholds, and the changelog entries are illustrative fiction.
