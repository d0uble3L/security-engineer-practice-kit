#!/usr/bin/env python3
"""
Auravia Health booking-svc — synthetic log generator (Variant 1).

Produces two correlated JSON-lines streams over one 24h window:
  - app.log      : booking-svc application/access events   (SIEM index: booking-svc-app)
  - gateway.log  : auth gateway audit events               (SIEM index: auravia-gw-auth)

Everything is invented. Deterministic: fixed seed => identical output.
Re-run with:  python3 generate_logs.py
"""
import json, random, ipaddress
from datetime import datetime, timedelta, timezone

SEED = 1337
random.seed(SEED)

DAY = datetime(2025, 3, 11, 0, 0, 0, tzinfo=timezone.utc)
def ts(dt): return dt.isoformat().replace("+00:00", "Z")

app_events = []
gw_events = []
_rid = [0]
def rid():
    _rid[0] += 1
    return f"req-{_rid[0]:06d}"

# --- population ------------------------------------------------------------
STAFF = [f"user-{n:04d}" for n in range(1001, 1026)]        # front desk / nurses
STAFF_UA = "Mozilla/5.0 (Auravia-Portal/3.1)"
PATIENT_IDS = list(range(50000, 50600))
CLINIC_IPS = ["10.20.4."+str(n) for n in range(10, 40)]     # office NAT ranges
SERVICE_ACCT = "svc-reminders"
BATCH_UA = "Auravia-BatchReminder/1.2"
MON_UA = "kube-probe/1.27"

def pick_ip(pool): return random.choice(pool)

def add_app(dt, method, path, status, src_ip, user_id, role, ua, latency=None, bytes_=None, extra=None):
    e = {
        "ts": ts(dt), "level": "info" if status < 400 else ("warn" if status < 500 else "error"),
        "event": "http.access", "method": method, "path": path, "status": status,
        "latency_ms": latency if latency is not None else random.randint(6, 90),
        "src_ip": src_ip, "user_id": user_id, "user_role": role,
        "request_id": (extra or {}).get("request_id", rid()),
        "user_agent": ua, "bytes": bytes_ if bytes_ is not None else random.randint(180, 1400),
    }
    if extra:
        for k, v in extra.items():
            if k != "request_id": e[k] = v
    app_events.append(e)
    return e["request_id"]

def add_gw(dt, event, **kw):
    e = {"ts": ts(dt), "event": event}
    e.update(kw)
    gw_events.append(e)

def login_and_forward(dt, user_id, username, role, src_ip, ua, method, path, status=200,
                      latency=None, bytes_=None, extra=None):
    """Legit flow: gateway issued this session, so gw_known_role is set and matches."""
    r = rid()
    add_gw(dt, "request.forward", request_id=r, src_ip=src_ip, path=path, method=method,
           token_sub=user_id, token_role_claim=role, gw_known_role=role, status=status)
    ex = {"request_id": r}
    if extra: ex.update(extra)
    add_app(dt, method, path, status, src_ip, user_id, role, ua, latency, bytes_, ex)

# --- 1) health checks + monitoring (all day, every 30s) --------------------
t = DAY
while t < DAY + timedelta(days=1):
    add_app(t, "GET", "/health", 200, "10.0.0.5", None, None, MON_UA, latency=random.randint(1, 4), bytes_=48)
    t += timedelta(seconds=30)

# --- 2) benign patient/staff traffic (diurnal, 07:00-19:00 heavier) --------
def hourly_weight(h):
    if 7 <= h < 19: return random.randint(30, 70)
    if 19 <= h < 22 or 5 <= h < 7: return random.randint(6, 16)
    return random.randint(1, 5)

for h in range(24):
    n = hourly_weight(h)
    for _ in range(n):
        dt = DAY + timedelta(hours=h, seconds=random.randint(0, 3599))
        roll = random.random()
        if roll < 0.45:
            # a patient views/books their own appointment (self-scoped id)
            uid = f"user-{random.randint(70000,70999)}"
            pid = random.choice(PATIENT_IDS)
            login_and_forward(dt, uid, uid, "patient", "198.51.100."+str(random.randint(2,254)),
                              "Mozilla/5.0 (iPhone; Auravia-App/2.0)", "GET",
                              f"/api/v2/patients/{pid}/appointments", 200)
        elif roll < 0.75:
            # front-desk staff searches / views
            uid = random.choice(STAFF)
            nm = random.choice(["smith","garcia","nguyen","patel","brown","kim","lopez"])
            login_and_forward(dt, uid, uid, "staff", pick_ip(CLINIC_IPS), STAFF_UA, "GET",
                              f"/api/v2/appointments/search?patientName={nm}", 200,
                              bytes_=random.randint(900, 4200))
        elif roll < 0.9:
            uid = random.choice(STAFF)
            aid = random.randint(900000, 900800)
            login_and_forward(dt, uid, uid, "staff", pick_ip(CLINIC_IPS), STAFF_UA, "GET",
                              f"/api/v2/appointments/{aid}", 200,
                              extra={"event": "appointment.view", "record_id": aid})
        else:
            uid = f"user-{random.randint(70000,70999)}"
            login_and_forward(dt, uid, uid, "patient", "198.51.100."+str(random.randint(2,254)),
                              "Mozilla/5.0 (iPhone; Auravia-App/2.0)", "POST",
                              "/api/v2/appointments", 201)

# --- 3) nightly batch reminder job (02:00-02:28) BENIGN LOOKALIKE ----------
# Service account enumerates upcoming appointments to send reminders. It has a
# properly issued 'service' session, runs off-hours, is paced, and uses the
# internal batch user-agent. This is the traffic R4's allowlist was built for.
bt = DAY + timedelta(hours=2)
for i in range(300):
    aid = 950000 + i
    login_and_forward(bt, SERVICE_ACCT, SERVICE_ACCT, "service", "10.0.6.12", BATCH_UA, "GET",
                      f"/api/v2/appointments/{aid}", 200,
                      extra={"event": "appointment.view", "record_id": aid})
    bt += timedelta(seconds=random.randint(3, 6))

# --- 4) internet background noise: scanners + small brute forces -----------
# Random 404 path scanning all day.
for _ in range(220):
    dt = DAY + timedelta(seconds=random.randint(0, 86399))
    ip = str(ipaddress.IPv4Address(random.randint(0x2f000000, 0xdf000000)))
    p = random.choice(["/.env", "/wp-login.php", "/admin", "/api/v1/users", "/actuator/health",
                       "/.git/config", "/api/v2/../../etc/passwd"])
    add_app(dt, "GET", p, 404, ip, None, None, "curl/7.88.1", latency=random.randint(1,8), bytes_=0)

# A couple of noisy but real internet brute forces that DO trip R1 (so R1 looks healthy).
for burst_ip, hour in [("203.0.113.44", 3), ("203.0.113.90", 21)]:
    for k in range(28):
        dt = DAY + timedelta(hours=hour, minutes=random.randint(0,4), seconds=random.randint(0,59))
        u = random.choice(["admin","root","test","info"])
        add_gw(dt, "auth.login", src_ip=burst_ip, username=u, outcome="fail",
               reason="no_user", user_agent="python-requests/2.31")
        add_app(dt, "POST", "/api/v2/auth/login", 401, burst_ip, None, "anon",
                "python-requests/2.31", latency=random.randint(5,20), bytes_=33)

# ===========================================================================
#  THE INCIDENT  (2025-03-11 ~14:00-14:42 UTC)
#  Chains: missing login rate-limit -> JWT signature not verified (forged
#  admin token) -> IDOR/BOLA mass enumeration of PHI. Attacker spoofs the
#  batch job's user-agent.
# ===========================================================================
ATTACK_IP = "185.220.101.7"
ATTACK_UA = "Auravia-BatchReminder/1.2"        # spoofs the internal batch UA
FORGED_SUB = "user-70142"                       # a real-looking but unknown-to-gw subject

# Stage A (14:00-14:20): paced credential stuffing, ~15 attempts / 5 min,
# UNDER R1's 20/5min threshold. All fail (attacker has no valid creds).
targets = ["j.okafor","m.reyes","s.donnelly","a.klein","front.desk","c.abara","t.walsh"]
a = DAY + timedelta(hours=14)
for block in range(4):                          # 4 five-minute blocks
    base = a + timedelta(minutes=5*block)
    for k in range(15):                         # 15 per 5-min block
        dt = base + timedelta(seconds=random.randint(0, 299))
        u = random.choice(targets)
        add_gw(dt, "auth.login", src_ip=ATTACK_IP, username=u, outcome="fail",
               reason="bad_password", user_agent=ATTACK_UA)
        add_app(dt, "POST", "/api/v2/auth/login", 401, ATTACK_IP, None, "anon",
                ATTACK_UA, latency=random.randint(8,25), bytes_=33)

# Stage B (14:21-14:22): a few SQLi probes against /search, then a forged
# admin token appears. NOTE on the gateway: NO token.issued(role=admin) exists
# for FORGED_SUB, and request.forward shows gw_known_role=null while the token
# claims admin -> the correlation tell R3 should catch.
sq = DAY + timedelta(hours=14, minutes=21)
for payload, st in [("smith%27%20OR%20%271%27%3D%271", 500),
                    ("%27%20UNION%20SELECT%20ssn_last4%2Cdob%20FROM%20patients--", 500),
                    ("smith%27--", 200)]:
    r = rid()
    add_gw(sq, "request.forward", request_id=r, src_ip=ATTACK_IP,
           path="/api/v2/appointments/search", method="GET",
           token_sub=FORGED_SUB, token_role_claim="admin", gw_known_role=None, status=st)
    add_app(sq, "GET", f"/api/v2/appointments/search?patientName={payload}", st, ATTACK_IP,
            FORGED_SUB, "admin", ATTACK_UA, latency=random.randint(15,60),
            bytes_=(0 if st==500 else random.randint(400,3000)),
            extra={"request_id": r})
    sq += timedelta(seconds=random.randint(20, 60))

# Stage C (14:23-14:40): IDOR/BOLA mass enumeration under the forged admin
# token. Sequential record ids across /api/v2/patients/{id} and
# /api/v2/appointments/{id}. ~430 records, single IP, spoofed batch UA.
ex = DAY + timedelta(hours=14, minutes=23)
for i in range(430):
    if i % 2 == 0:
        pid = 50000 + i
        path = f"/api/v2/patients/{pid}"
        r = rid()
        add_gw(ex, "request.forward", request_id=r, src_ip=ATTACK_IP, path=path, method="GET",
               token_sub=FORGED_SUB, token_role_claim="admin", gw_known_role=None, status=200)
        add_app(ex, "GET", path, 200, ATTACK_IP, FORGED_SUB, "admin", ATTACK_UA,
                latency=random.randint(10,40), bytes_=random.randint(600,900),
                extra={"request_id": r, "event": "patient.view", "record_id": pid})
    else:
        aid = 50000 + i
        path = f"/api/v2/appointments/{aid}"
        r = rid()
        add_gw(ex, "request.forward", request_id=r, src_ip=ATTACK_IP, path=path, method="GET",
               token_sub=FORGED_SUB, token_role_claim="admin", gw_known_role=None, status=200)
        add_app(ex, "GET", path, 200, ATTACK_IP, FORGED_SUB, "admin", ATTACK_UA,
                latency=random.randint(10,40), bytes_=random.randint(600,900),
                extra={"request_id": r, "event": "appointment.view", "record_id": aid})
    ex += timedelta(seconds=random.uniform(2.0, 2.6))

# --- write out (sorted by ts) ----------------------------------------------
app_events.sort(key=lambda e: e["ts"])
gw_events.sort(key=lambda e: e["ts"])
with open("app.log", "w") as f:
    for e in app_events: f.write(json.dumps(e) + "\n")
with open("gateway.log", "w") as f:
    for e in gw_events: f.write(json.dumps(e) + "\n")

print(f"app.log     : {len(app_events)} lines")
print(f"gateway.log : {len(gw_events)} lines")
