#!/usr/bin/env python3
"""
Auravia Health provider-svc — synthetic log generator (Variant 2).

Produces two correlated JSON-lines streams over one 24h window:
  - app.log      : provider-svc application/access events   (SIEM index: provider-svc-app)
  - gateway.log  : auth gateway audit events                (SIEM index: auravia-gw-auth)

Everything is invented. Deterministic: fixed seed => identical output.
Re-run with:  python3 generate_logs.py

The incident here is deliberately different from Variant 1. In V1 the attacker
forged a token (an *identity* failure the gateway could see as a role mismatch).
Here the attacker is a LEGITIMATELY authenticated provider who self-registers and
then abuses broken *authorization*: mass-assignment to self-escalate, missing
function-level authz to verify accounts, SSRF to cloud metadata, and path
traversal to read other providers' documents. Because the identity is genuine,
`token_role_claim` and `gw_known_role` AGREE the whole time — the V1 detection
pivot is blind to this.
"""
import json, random, ipaddress
from datetime import datetime, timedelta, timezone

SEED = 4242
random.seed(SEED)

DAY = datetime(2025, 6, 17, 0, 0, 0, tzinfo=timezone.utc)
def ts(dt): return dt.isoformat().replace("+00:00", "Z")

app_events = []
gw_events = []
_rid = [0]
def rid():
    _rid[0] += 1
    return f"req-{_rid[0]:06d}"

# --- population ------------------------------------------------------------
ADMIN_STAFF = [f"user-{n:04d}" for n in range(2001, 2006)]   # med-staff office (can verify)
PROVIDERS   = [f"user-{n:05d}" for n in range(60000, 60400)] # clinicians
PROVIDER_IDS = list(range(4000, 4400))
PORTAL_UA = "Mozilla/5.0 (Auravia-Portal/3.1)"
PROV_UA   = "Mozilla/5.0 (Auravia-Provider/2.2)"
CLINIC_IPS = ["10.20.4."+str(n) for n in range(10, 40)]
PROV_IPS   = ["198.51.100."+str(n) for n in range(2, 250)]
DOC_ARCHIVER = "svc-doc-archiver"
ARCHIVER_UA  = "Auravia-DocArchiver/1.0"
MON_UA = "kube-probe/1.27"
PARTNER_FEEDS = [
    "https://cal.partnerhealth.example/feeds/slots.json",
    "https://sched.westside-radiology.example/api/availability",
    "https://api.telehealthpartners.example/v2/openings",
]

def pick(pool): return random.choice(pool)

def add_app(dt, method, path, status, src_ip, user_id, role, ua,
            latency=None, bytes_=None, extra=None):
    e = {
        "ts": ts(dt),
        "level": "info" if status < 400 else ("warn" if status < 500 else "error"),
        "event": "http.access", "method": method, "path": path, "status": status,
        "latency_ms": latency if latency is not None else random.randint(6, 90),
        "src_ip": src_ip, "user_id": user_id, "user_role": role,
        "request_id": (extra or {}).get("request_id", rid()),
        "user_agent": ua, "bytes": bytes_ if bytes_ is not None else random.randint(180, 1400),
    }
    if extra:
        for k, v in extra.items():
            if k != "request_id":
                e[k] = v
    app_events.append(e)
    return e["request_id"]

def add_gw(dt, event, **kw):
    e = {"ts": ts(dt), "event": event}
    e.update(kw)
    gw_events.append(e)

def login_and_forward(dt, user_id, username, role, src_ip, ua, method, path,
                      status=200, latency=None, bytes_=None, extra=None):
    """Legit flow: gateway issued this session, so gw_known_role is set and matches."""
    r = rid()
    add_gw(dt, "request.forward", request_id=r, src_ip=src_ip, path=path, method=method,
           token_sub=user_id, token_role_claim=role, gw_known_role=role, status=status)
    ex = {"request_id": r}
    if extra:
        ex.update(extra)
    add_app(dt, method, path, status, src_ip, user_id, role, ua, latency, bytes_, ex)
    return r

# --- 1) health checks + monitoring (all day, every 30s) --------------------
t = DAY
while t < DAY + timedelta(days=1):
    add_app(t, "GET", "/health", 200, "10.0.0.5", None, None, MON_UA,
            latency=random.randint(1, 4), bytes_=48)
    t += timedelta(seconds=30)

# --- 2) benign business traffic (diurnal, 07:00-19:00 heavier) -------------
def hourly_weight(h):
    if 7 <= h < 19: return random.randint(26, 60)
    if 19 <= h < 22 or 5 <= h < 7: return random.randint(6, 14)
    return random.randint(1, 4)

for h in range(24):
    n = hourly_weight(h)
    for _ in range(n):
        dt = DAY + timedelta(hours=h, seconds=random.randint(0, 3599))
        roll = random.random()
        if roll < 0.40:
            # a provider or staff member views a provider profile
            uid = pick(PROVIDERS)
            pid = pick(PROVIDER_IDS)
            login_and_forward(dt, uid, uid, "provider", pick(PROV_IPS), PROV_UA, "GET",
                              f"/api/v2/providers/{pid}", 200,
                              extra={"event": "provider.view", "record_id": pid})
        elif roll < 0.62:
            # front-desk / med-staff directory search
            uid = pick(ADMIN_STAFF)
            nm = random.choice(["okafor","reyes","donnelly","klein","abara","walsh","novak"])
            login_and_forward(dt, uid, uid, "admin", pick(CLINIC_IPS), PORTAL_UA, "GET",
                              f"/api/v2/providers?search={nm}", 200,
                              bytes_=random.randint(700, 3800))
        elif roll < 0.78:
            # a provider edits ONLY their own contact details (benign self-edit)
            uid = pick(PROVIDERS)
            pid = pick(PROVIDER_IDS)
            fld = random.choice([["email"], ["phone"], ["email", "phone"], ["specialty"]])
            login_and_forward(dt, uid, uid, "provider", pick(PROV_IPS), PROV_UA, "PATCH",
                              f"/api/v2/providers/{pid}", 200,
                              extra={"event": "provider.updated", "actor": uid,
                                     "actor_role": "provider", "provider_id": pid,
                                     "fields_changed": fld})
        elif roll < 0.88:
            # med-staff verifies a pending provider (legit credentialing)
            uid = pick(ADMIN_STAFF)
            pid = pick(PROVIDER_IDS)
            login_and_forward(dt, uid, uid, "admin", pick(CLINIC_IPS), PORTAL_UA, "POST",
                              f"/api/v2/providers/{pid}/verify", 200,
                              extra={"event": "provider.verify", "actor": uid,
                                     "actor_role": "admin", "provider_id": pid})
        elif roll < 0.96:
            # a provider reads one of their OWN credentialing documents
            uid = pick(PROVIDERS)
            pid = pick(PROVIDER_IDS)
            fn = random.choice(["license.pdf", "dea-cert.pdf", "board-cert.pdf", "cv.pdf"])
            login_and_forward(dt, uid, uid, "provider", pick(PROV_IPS), PROV_UA, "GET",
                              f"/api/v2/providers/{pid}/documents/{fn}", 200,
                              bytes_=random.randint(20000, 240000),
                              extra={"event": "document.read", "actor": uid,
                                     "actor_role": "provider", "provider_id": pid,
                                     "filename": fn})
        else:
            # a provider syncs availability from a legit EXTERNAL partner feed
            uid = pick(PROVIDERS)
            pid = pick(PROVIDER_IDS)
            feed = pick(PARTNER_FEEDS)
            login_and_forward(dt, uid, uid, "provider", pick(PROV_IPS), PROV_UA, "POST",
                              f"/api/v2/providers/{pid}/availability/sync", 200,
                              extra={"event": "availability.sync", "actor": uid,
                                     "actor_role": "provider", "provider_id": pid,
                                     "source_url": feed, "fetch_status": 200,
                                     "slot_count": random.randint(4, 40)})

# --- 3) benign nightly document-archiver job (01:30-01:55) LOOKALIKE -------
# A service account bulk-reads documents to archive them. Properly issued
# 'service' session, off-hours, paced, from a fixed internal IP. This is the
# traffic an exporter allowlist would be built around.
bt = DAY + timedelta(hours=1, minutes=30)
for i in range(120):
    pid = 4000 + i
    fn = random.choice(["license.pdf", "dea-cert.pdf", "board-cert.pdf"])
    login_and_forward(bt, DOC_ARCHIVER, DOC_ARCHIVER, "service", "10.0.6.20", ARCHIVER_UA, "GET",
                      f"/api/v2/providers/{pid}/documents/{fn}", 200,
                      bytes_=random.randint(20000, 200000),
                      extra={"event": "document.read", "actor": DOC_ARCHIVER,
                             "actor_role": "service", "provider_id": pid, "filename": fn})
    bt += timedelta(seconds=random.randint(4, 8))

# --- 4) benign light registration trickle (new providers onboarding) -------
for _ in range(9):
    dt = DAY + timedelta(hours=random.randint(8, 18), seconds=random.randint(0, 3599))
    uname = random.choice(["dr.", "np.", "pa."]) + random.choice(
        ["hchen", "rsingh", "kobrien", "lmensah", "tfarah", "bvoss"]) + str(random.randint(1, 99))
    pid = random.randint(4400, 4460)
    add_app(dt, "POST", "/api/v2/auth/register", 201, pick(PROV_IPS), None, "anon",
            PROV_UA, latency=random.randint(20, 60), bytes_=64,
            extra={"event": "auth.register", "username": uname, "provider_id": pid})

# --- 5) benign bulk-signup spam burst that DOES trip R1 (so R1 looks alive)-
# A marketing/scraper bot mass-hits the open registration endpoint at 04:00.
spam_ip = "192.0.2.77"
sb = DAY + timedelta(hours=4)
for i in range(35):
    dt = sb + timedelta(seconds=random.randint(0, 1800))
    add_app(dt, "POST", "/api/v2/auth/register", random.choice([201, 400, 400]),
            spam_ip, None, "anon", "python-requests/2.31",
            latency=random.randint(5, 20), bytes_=48,
            extra={"event": "auth.register", "username": f"promo{i}@spam.example",
                   "provider_id": (4600 + i)})

# --- 6) internet background noise: 404 path scanning -----------------------
for _ in range(200):
    dt = DAY + timedelta(seconds=random.randint(0, 86399))
    ip = str(ipaddress.IPv4Address(random.randint(0x2f000000, 0xdf000000)))
    p = random.choice(["/.env", "/wp-login.php", "/admin", "/api/v1/providers",
                       "/actuator/health", "/.git/config", "/api/v2/../../etc/passwd"])
    add_app(dt, "GET", p, 404, ip, None, None, "curl/7.88.1",
            latency=random.randint(1, 8), bytes_=0)

# ===========================================================================
#  THE INCIDENT  (2025-06-17 ~10:05-10:41 UTC)
#  Chains: self-service registration -> mass-assignment self-escalation
#  (role + credential_status) -> missing function-level authz (verify) ->
#  SSRF to cloud metadata -> path-traversal document exfiltration.
#  The attacker is a REAL authenticated provider the whole time:
#  token_role_claim == gw_known_role == "provider" on every forwarded request.
# ===========================================================================
ATTACK_IP  = "45.148.10.7"
ATTACK_UA  = "Mozilla/5.0 (Auravia-Provider/2.2)"   # ordinary provider UA — no spoof needed
ATTACKER   = "user-63314"
PRIMARY_PID = 4407
SLEEPER_PIDS = [4408, 4409, 4410, 4411]             # extra accounts registered for verify-abuse

# Stage A (10:05-10:06): self-register primary + a few sleeper accounts.
reg = DAY + timedelta(hours=10, minutes=5)
add_app(reg, "POST", "/api/v2/auth/register", 201, ATTACK_IP, None, "anon", ATTACK_UA,
        latency=random.randint(20, 50), bytes_=64,
        extra={"event": "auth.register", "username": "dr.avery.locke", "provider_id": PRIMARY_PID})
for i, spid in enumerate(SLEEPER_PIDS):
    dt = reg + timedelta(seconds=20 + i * 12)
    add_app(dt, "POST", "/api/v2/auth/register", 201, ATTACK_IP, None, "anon", ATTACK_UA,
            latency=random.randint(20, 50), bytes_=64,
            extra={"event": "auth.register", "username": f"locke.alt{i+1}", "provider_id": spid})

# Stage B (10:07): login -> genuine provider session. gw_known_role == provider.
lg = DAY + timedelta(hours=10, minutes=7)
add_gw(lg, "auth.login", src_ip=ATTACK_IP, username="dr.avery.locke",
       outcome="success", user_agent=ATTACK_UA)
login_and_forward(lg + timedelta(seconds=2), ATTACKER, "dr.avery.locke", "provider",
                  ATTACK_IP, ATTACK_UA, "GET", f"/api/v2/providers/{PRIMARY_PID}", 200,
                  extra={"event": "provider.view", "record_id": PRIMARY_PID})

# Stage C (10:09): MASS-ASSIGNMENT self-escalation. PATCH own record, but the
# submitted body includes role + credential_status, which the handler blindly
# merges. Signal: actor == provider_id (self-edit) AND fields_changed carries
# the privileged fields. Identity is legit, so gw_known_role == provider.
esc = DAY + timedelta(hours=10, minutes=9)
login_and_forward(esc, ATTACKER, "dr.avery.locke", "provider", ATTACK_IP, ATTACK_UA,
                  "PATCH", f"/api/v2/providers/{PRIMARY_PID}", 200,
                  extra={"event": "provider.updated", "actor": ATTACKER,
                         "actor_role": "provider", "provider_id": PRIMARY_PID,
                         "fields_changed": ["full_name", "specialty", "email", "phone",
                                            "role", "credential_status"]})

# Stage D (10:11-10:16): BFLA — the /verify endpoint has no admin guard, so the
# provider verifies their own sleeper accounts (and themselves). Signal:
# provider.verify where actor_role != admin.
vt = DAY + timedelta(hours=10, minutes=11)
for spid in [PRIMARY_PID] + SLEEPER_PIDS:
    login_and_forward(vt, ATTACKER, "dr.avery.locke", "provider", ATTACK_IP, ATTACK_UA,
                      "POST", f"/api/v2/providers/{spid}/verify", 200,
                      extra={"event": "provider.verify", "actor": ATTACKER,
                             "actor_role": "provider", "provider_id": spid})
    vt += timedelta(seconds=random.randint(40, 80))

# Stage E (10:20-10:22): SSRF. The availability-sync fetch takes a user-supplied
# source_url with no allowlist, pointed at cloud metadata (link-local
# 169.254.169.254). Signal: availability.sync with an internal/link-local
# source_url. The 502 path also leaks the upstream body back to the caller.
ssrf = DAY + timedelta(hours=10, minutes=20)
ssrf_targets = [
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", 200, 0),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/provider-svc-role", 200, 0),
    ("http://169.254.169.254/latest/api/token", 502, 0),
    ("http://169.254.169.254/latest/meta-data/hostname", 200, 0),
]
for url, st, slots in ssrf_targets:
    login_and_forward(ssrf, ATTACKER, "dr.avery.locke", "provider", ATTACK_IP, ATTACK_UA,
                      "POST", f"/api/v2/providers/{PRIMARY_PID}/availability/sync", st,
                      extra={"event": "availability.sync", "actor": ATTACKER,
                             "actor_role": "provider", "provider_id": PRIMARY_PID,
                             "source_url": url, "fetch_status": (200 if st == 200 else 0),
                             "slot_count": slots})
    ssrf += timedelta(seconds=random.randint(20, 45))

# Stage F (10:24-10:41): PATH TRAVERSAL document exfiltration. filename escapes
# the per-provider directory to read OTHER providers' credentialing PDFs.
# Signal: document.read with traversal tokens in `filename`, one actor pulling
# many providers' documents. provider_id stays 4407 while the traversal target
# walks other ids. (Note: the events emit `filename`, not `resource_path`.)
ex = DAY + timedelta(hours=10, minutes=24)
targets = list(range(4000, 4400, 7))
for i, tgt in enumerate(targets):
    doc = random.choice(["license.pdf", "dea-cert.pdf", "board-cert.pdf"])
    fn = f"..%2f..%2f{tgt}%2f{doc}"
    login_and_forward(ex, ATTACKER, "dr.avery.locke", "provider", ATTACK_IP, ATTACK_UA,
                      "GET", f"/api/v2/providers/{PRIMARY_PID}/documents/{fn}", 200,
                      bytes_=random.randint(30000, 260000),
                      extra={"event": "document.read", "actor": ATTACKER,
                             "actor_role": "provider", "provider_id": PRIMARY_PID,
                             "filename": fn})
    ex += timedelta(seconds=random.uniform(13.0, 17.0))

# --- write out (sorted by ts) ----------------------------------------------
app_events.sort(key=lambda e: e["ts"])
gw_events.sort(key=lambda e: e["ts"])
with open("app.log", "w") as f:
    for e in app_events: f.write(json.dumps(e) + "\n")
with open("gateway.log", "w") as f:
    for e in gw_events: f.write(json.dumps(e) + "\n")

print(f"app.log     : {len(app_events)} lines")
print(f"gateway.log : {len(gw_events)} lines")
