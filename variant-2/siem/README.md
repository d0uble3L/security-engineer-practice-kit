# Auravia Health — Detection Content (provider-svc)

This directory is a snapshot of the detection-as-code repo the (fictional) Auravia
Health detection team has deployed against `provider-svc` telemetry. It contains
four production rules and a 30-day alert-volume export.

Your job in Task 2 is **not** to admire these rules — it's to figure out why the
incident in `data/` walked straight past all four of them, and what minimal,
defensible change fixes each gap without drowning the SOC in false positives.

A warning that matters more here than in Variant 1: **the gateway stream does not
save you this time.** In V1 the attacker forged a token, so the gateway's
independent role knowledge (`gw_known_role`) disagreed with the token's claim. Here
the attacker is a *legitimately authenticated provider* — they registered, they
logged in, the gateway issued them a real `provider` session. On every forwarded
request `token_role_claim == gw_known_role == "provider"`. The identity is real; the
**authorization** is what's broken. A detection strategy built around token integrity
is structurally blind to this incident. The signal lives in the *application* events.

---

## Log sources these rules run against

| Index              | Source file        | What it holds                                   |
|--------------------|--------------------|-------------------------------------------------|
| `provider-svc-app` | `data/app.log`     | Application HTTP access + domain events          |
| `auravia-gw-auth`  | `data/gateway.log` | Auth-gateway login outcomes + forwarded-request audit |

### `provider-svc-app` fields (JSON lines)
Base on every line:
`ts, level, event, method, path, status, latency_ms, src_ip, user_id, user_role,
request_id, user_agent, bytes`.

Domain events carry extra fields:
- `event="provider.view"`: `record_id`
- `event="provider.updated"`: `actor, actor_role, provider_id, fields_changed` (a list)
- `event="provider.verify"`: `actor, actor_role, provider_id`
- `event="availability.sync"`: `actor, actor_role, provider_id, source_url, fetch_status, slot_count`
- `event="document.read"`: `actor, actor_role, provider_id, filename, bytes`
- `event="auth.register"`: `username, provider_id`

> Note the field name on document events is **`filename`**. It used to be
> `resource_path`; a logging refactor renamed it. Keep that in mind when you read R4.

### `auravia-gw-auth` fields (JSON lines)
- `event="auth.login"`: `ts, src_ip, username, outcome, reason, user_agent`
- `event="request.forward"`: `ts, request_id, src_ip, path, method, token_sub,
  token_role_claim, gw_known_role, status`

`token_role_claim` is the role asserted inside the JWT; `gw_known_role` is the role
the gateway independently knows for that subject. In this incident they **agree** on
every request — that is the point (see the warning above), not a data error.

---

## ⚠️ Verification flag (read before selling or deploying)

The `query:` block in each rule is written in a **Splunk-SPL-flavored pseudo-syntax**
chosen because these logs land in named indexes. It is meant to be *read and reasoned
about*, not copy-pasted into a live SIEM. **Before using any of these queries as
authoritative, port and validate them against your actual backend** (Splunk SPL,
Sentinel KQL, Elastic ES|QL, Panther, Sigma + a pipeline, etc.). Field extraction,
`mvfind`/`match` semantics, regex dialects, IP/CIDR matching, and null handling differ
across backends and *will* change whether a rule fires. Where a gap depends on regex
coverage (R3) or on a field name that a refactor changed (R4), that behavior is
backend- and pipeline-specific and must be confirmed on the real platform.

Rule IDs, thresholds, and the changelog entries are illustrative fiction.
