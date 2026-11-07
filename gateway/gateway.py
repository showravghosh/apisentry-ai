import os
import re
import json
import time
import csv
import base64
import asyncio
from collections import deque, OrderedDict
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import numpy as np
import joblib
import httpx
from fastapi import FastAPI, Request, Response
from catboost import CatBoostClassifier

ART = os.getenv("APISENTRY_ART", os.path.join(os.path.dirname(__file__), "artifacts"))
BACKEND = os.getenv("APISENTRY_BACKEND", "http://localhost:8000")
WINDOW_SEC = 10.0
WINDOW_LONG = 60.0
DECISION_LOG = os.getenv("APISENTRY_DECISION_LOG", os.path.join(os.path.dirname(__file__), "gateway_decisions.csv"))
POLICY = os.getenv("APISENTRY_POLICY", "v9")
POOLED = os.getenv("APISENTRY_POOLED", "1") == "1"
ASYNC_LOG = os.getenv("APISENTRY_ASYNC_LOG", "1") == "1"
MAX_KEYS = int(os.getenv("APISENTRY_MAX_KEYS", "100000"))
TRUST_XFF = os.getenv("APISENTRY_TRUST_XFF", "1") == "1"

BLOCK_THRESHOLD = 0.85
RATELIMIT_THRESHOLD = 0.55

SQL_KEYWORDS = ["select", "union", "drop", "or ", "and ", "--", "#", "=", ";",
                "sleep", "like", "||", "'"]
SPECIAL = ["'", '"', ";", "-", "=", "#", "(", ")", "|"]

model = CatBoostClassifier()
model.load_model(os.path.join(ART, "model.cbm"))
scaler = joblib.load(os.path.join(ART, "scaler.pkl"))
with open(os.path.join(ART, "encoders.json")) as f:
    encoders = json.load(f)
with open(os.path.join(ART, "feature_columns.json")) as f:
    cfg = json.load(f)

NUM_COLS = cfg["num_cols"]
CAT_COLS = cfg["cat_cols"]
LABELS = cfg["labels"]
NORMAL_IDX = LABELS.index("normal")
V3_PATH = os.path.join(ART, "policy_%s.json" % POLICY)
V3 = json.load(open(V3_PATH)) if os.path.exists(V3_PATH) else None
SOURCE_KEY = cfg.get("source_key", "ip")
PROFILE_PATH = os.getenv("APISENTRY_PROFILE", "")
PROFILE = json.load(open(PROFILE_PATH)) if PROFILE_PATH else {}
LOGIN_PATHS = set(PROFILE.get("login_paths", ["/login"]))
LOGIN_FAIL_MARKER = PROFILE.get("login_fail_marker", "").encode()
OBJECT_PATTERNS = [re.compile(x) for x in PROFILE.get("object_patterns", [r"^/users/(\d+)"])]


class BoundedState(OrderedDict):
    def get_deque(self, key):
        if key in self:
            self.move_to_end(key)
            return self[key]
        dq = deque()
        self[key] = dq
        while len(self) > MAX_KEYS:
            self.popitem(last=False)
        return dq


state = BoundedState()
state_long = BoundedState()
token_state = BoundedState()
token_state_long = BoundedState()
login_global = deque()
account_state = BoundedState()
object_state = BoundedState()
buckets = BoundedState()
src_long = BoundedState()
object_long = BoundedState()
fail_long = BoundedState()
id_state = BoundedState()

app = FastAPI(title="APISentry Gateway")
client = None
log_queue = deque()

DEC_FIELDS = ["timestamp", "ip", "method", "endpoint", "predicted", "risk", "decision"]
if not os.path.exists(DECISION_LOG):
    with open(DECISION_LOG, "w", newline="") as f:
        csv.DictWriter(f, fieldnames=DEC_FIELDS).writeheader()


def flush_log():
    if not log_queue:
        return
    rows = []
    while log_queue:
        rows.append(log_queue.popleft())
    with open(DECISION_LOG, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=DEC_FIELDS).writerows(rows)


async def log_writer():
    while True:
        await asyncio.sleep(0.5)
        flush_log()


async def state_sweeper():
    while True:
        await asyncio.sleep(5.0)
        now = time.time()
        for st, w in ((state, WINDOW_SEC), (token_state, WINDOW_SEC)):
            for k in [k for k, dq in st.items() if not dq or now - dq[-1][0] > w]:
                st.pop(k, None)
        for k in [k for k, dq in object_state.items() if not dq or now - dq[-1][0] > WINDOW_SEC]:
            object_state.pop(k, None)
        for k in [k for k, dq in account_state.items() if not dq or now - dq[-1][0] > WINDOW_LONG]:
            account_state.pop(k, None)
        for st in (state_long, token_state_long, src_long, object_long, fail_long, id_state):
            for k in [k for k, dq in st.items() if not dq or now - (dq[-1] if not isinstance(dq[-1], tuple) else dq[-1][0]) > WINDOW_LONG]:
                st.pop(k, None)


@app.on_event("startup")
async def startup():
    global client
    if POOLED:
        client = httpx.AsyncClient(timeout=30.0, limits=httpx.Limits(max_connections=200, max_keepalive_connections=100))
    if ASYNC_LOG:
        asyncio.create_task(log_writer())
    asyncio.create_task(state_sweeper())


@app.on_event("shutdown")
async def shutdown():
    flush_log()
    if client is not None:
        await client.aclose()


@app.post("/__apisentry/reset")
def reset_state():
    if os.getenv("APISENTRY_TEST_HOOKS", "0") != "1":
        return Response(status_code=404)
    for st in (state, state_long, token_state, token_state_long, account_state, object_state, buckets, src_long, object_long, fail_long, id_state):
        st.clear()
    login_global.clear()
    return {"reset": True}


@app.get("/__apisentry/state")
def state_size():
    return {"ip_keys": len(state), "ip_keys_long": len(state_long), "token_keys": len(token_state),
            "token_keys_long": len(token_state_long), "policy": POLICY, "profile": PROFILE.get("name", "default"), "pooled": POOLED, "async_log": ASYNC_LOG}


def normalize_endpoint(path):
    return re.sub(r"/\d+", "/{id}", str(path))


def target_user(path):
    for rx in OBJECT_PATTERNS:
        m = rx.match(str(path))
        if m:
            return m.group(1)
    return None


def normalize_payload(text):
    t = str(text)
    for _ in range(3):
        d = unquote_plus(t)
        if d == t:
            break
        t = d
    t = t.lower()
    t = re.sub(r"/\*.*?\*/", " ", t)
    t = re.sub(r"\s+", " ", t)
    return t


def body_features(text):
    b = normalize_payload(text)
    return len(b), sum(b.count(c) for c in SPECIAL), sum(1 for k in SQL_KEYWORDS if k in b)


def numeric_features(text):
    t = unquote_plus(str(text))
    vals = []
    for x in re.findall(r"-?\d+\.?\d*", t):
        try:
            vals.append(float(x))
        except ValueError:
            pass
    mx = max(vals) if vals else 0.0
    mn = min(vals) if vals else 0.0
    has_neg = 1 if any(v < 0 for v in vals) else 0
    return mx, mn, has_neg, t.count(":")


def enc(col, val):
    classes = encoders[col]
    return classes.index(val) if val in classes else len(classes)


def token_subject(auth_header):
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part)).get("sub")
    except Exception:
        return None


def login_username(body_bytes):
    try:
        v = json.loads(body_bytes.decode("utf-8", "ignore") or "{}").get("username")
        return str(v) if v is not None else None
    except Exception:
        m = re.search(r'"username"\s*:\s*"([^"]*)"', body_bytes.decode("utf-8", "ignore"))
        return m.group(1) if m else None


PRICE_FIELDS = ("unit_price", "price", "discount", "total")


NUMSTR = re.compile(r"^\s*-\s*\d+(\.\d+)?\s*$")


def tamper_walk(o):
    if isinstance(o, dict):
        return any(k in PRICE_FIELDS or tamper_walk(v) for k, v in o.items())
    if isinstance(o, list):
        return any(tamper_walk(v) for v in o)
    if isinstance(o, bool):
        return False
    if isinstance(o, (int, float)):
        return o < 0
    if isinstance(o, str):
        return bool(NUMSTR.match(o))
    return False


def body_tampering(body_bytes):
    try:
        o = json.loads(body_bytes.decode("utf-8", "ignore") or "null")
    except Exception:
        return 0
    if not isinstance(o, (dict, list)):
        return 0
    return int(tamper_walk(o))


def client_ip(request):
    if TRUST_XFF and request.headers.get("x-forwarded-for"):
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def extract(request, body_bytes):
    now = time.time()
    path = request.url.path
    query = request.url.query
    ip = client_ip(request)
    ep_norm = normalize_endpoint(path)
    is_login = 1 if path in LOGIN_PATHS else 0
    tuser = target_user(path)

    body_text = body_bytes.decode("utf-8", "ignore") + " " + query
    path_norm = normalize_payload(path)
    path_sql = sum(1 for k in SQL_KEYWORDS if k in path_norm)
    body_len, body_special, body_sql = body_features(body_text)
    body_mx, body_mn, body_neg, body_fc = numeric_features(body_text)
    hour = datetime.now(timezone.utc).hour

    subject = token_subject(request.headers.get("authorization", ""))
    skey = ip + "|" + subject if (SOURCE_KEY == "ip_identity" and subject) else ip
    dq = state.get_deque(skey)
    while dq and now - dq[0][0] > WINDOW_SEC:
        dq.popleft()
    ip_req = len(dq) + 1
    ip_fail = sum(x[1] for x in dq)
    ip_login = sum(x[2] for x in dq) + is_login
    eps = set(x[3] for x in dq)
    eps.add(ep_norm)
    users = set(x[4] for x in dq if x[4] is not None)
    if tuser:
        users.add(tuser)

    okey = ip + "|" + subject if subject else ip
    oq = object_state.get_deque(okey)
    while oq and now - oq[0][0] > WINDOW_SEC:
        oq.popleft()
    if tuser:
        oq.append((now, tuser))
    id_objects = len(set(x[1] for x in oq))

    sq = src_long.get_deque(okey)
    while sq and now - sq[0] > WINDOW_LONG:
        sq.popleft()
    sq.append(now)
    src_req_60s = len(sq)
    iq = id_state.get_deque(okey)
    while iq and now - iq[0] > WINDOW_SEC:
        iq.popleft()
    iq.append(now)
    id_req_10s = len(iq)
    oql = object_long.get_deque(okey)
    while oql and now - oql[0][0] > WINDOW_LONG:
        oql.popleft()
    if tuser:
        oql.append((now, tuser))
    id_objects_60s = len(set(x[1] for x in oql))
    fq = fail_long.get_deque(ip)
    while fq and now - fq[0] > WINDOW_LONG:
        fq.popleft()
    login_fail_60s = len(fq)

    dq_long = state_long.get_deque(skey)
    while dq_long and now - dq_long[0] > WINDOW_LONG:
        dq_long.popleft()
    ip_req_60s = len(dq_long) + 1

    if subject:
        tq = token_state.get_deque(subject)
        while tq and now - tq[0][0] > WINDOW_SEC:
            tq.popleft()
        tq.append((now, ip))
        token_ips = len(set(x[1] for x in tq))
        tql = token_state_long.get_deque(subject)
        while tql and now - tql[0][0] > WINDOW_LONG:
            tql.popleft()
        tql.append((now, ip))
        token_ips_60s = len(set(x[1] for x in tql))
    else:
        token_ips = 0
        token_ips_60s = 0

    uname = login_username(body_bytes) if is_login else None
    g_fail = 0
    g_users = 0
    a_fail = 0
    if is_login:
        while login_global and now - login_global[0][0] > WINDOW_SEC:
            login_global.popleft()
        g_fail = sum(x[1] for x in login_global)
        g_users = len(set(x[2] for x in login_global if x[2]) | ({uname} if uname else set()))
        aq = account_state.get_deque(uname)
        while aq and now - aq[0][0] > WINDOW_LONG:
            aq.popleft()
        a_fail = sum(x[1] for x in aq)

    feats = {
        "id_distinct_objects_10s": id_objects, "id_distinct_objects_60s": id_objects_60s, "src_req_60s": src_req_60s, "id_req_10s": id_req_10s, "path_sql_hits": path_sql, "ip_login_fail_60s": login_fail_60s, "glob_login_fail_10s": g_fail, "glob_login_users_10s": g_users, "acct_fail_60s": a_fail,
        "request_size": len(body_bytes), "hour": hour, "body_len": body_len,
        "body_special": body_special, "body_sql_hits": body_sql,
        "body_max_num": body_mx, "body_min_num": body_mn,
        "body_has_neg": body_neg, "body_field_count": body_fc, "is_login": is_login,
        "ip_req_10s": ip_req, "ip_fail_10s": ip_fail, "ip_fail_ratio_10s": ip_fail / max(ip_req, 1),
        "ip_login_10s": ip_login, "ip_uniq_ep_10s": len(eps),
        "ip_distinct_users_10s": len(users), "token_ips_10s": token_ips,
        "ip_req_60s": ip_req_60s, "token_ips_60s": token_ips_60s,
        "method": request.method, "endpoint_norm": ep_norm,
    }
    meta = {"ip": ip, "ep_norm": ep_norm, "is_login": is_login, "tuser": tuser,
            "dq": dq, "dq_long": dq_long, "now": now, "uname": uname, "tamper": body_tampering(body_bytes), "fq": fq, "subject": subject, "okey": okey}
    return feats, meta


def score(feats):
    num_vec = np.array([[feats[c] for c in NUM_COLS]], dtype=float)
    num_scaled = scaler.transform(num_vec)[0]
    cat_vec = [enc(c, feats[c]) for c in CAT_COLS]
    x = np.concatenate([num_scaled, cat_vec]).reshape(1, -1)
    proba = model.predict_proba(x)[0]
    pred_idx = int(np.argmax(proba))
    return LABELS[pred_idx], float(1.0 - proba[NORMAL_IDX])


def decide(pred, risk):
    if pred != "normal" and risk >= BLOCK_THRESHOLD:
        return "BLOCK"
    if pred != "normal" and risk >= RATELIMIT_THRESHOLD:
        return "RATE_LIMIT"
    return "ALLOW"


def policy_v1(feats, pred, risk):
    guards = {
        "api_flooding": feats["ip_req_10s"] >= 8,
        "bola": feats["ip_distinct_users_10s"] >= 3,
        "brute_force": feats["ip_fail_10s"] >= 3,
        "token_replay": feats["token_ips_10s"] >= 4,
        "credential_stuffing": feats["ip_login_10s"] >= 3,
    }
    if pred in guards and not guards[pred]:
        pred = "normal"
        risk = min(risk, 0.3)
    decision = decide(pred, risk)
    if feats["body_sql_hits"] >= 3:
        pred, risk, decision = "sql_injection", max(risk, 0.95), "BLOCK"
    if feats["ip_req_10s"] >= 8 or feats["ip_req_60s"] >= 30:
        pred, risk, decision = "api_flooding", max(risk, 0.95), "BLOCK"
    if feats["token_ips_10s"] >= 5 or feats["token_ips_60s"] >= 3:
        pred, risk, decision = "token_replay", max(risk, 0.95), "BLOCK"
    if feats["ip_distinct_users_10s"] >= 5:
        pred, risk, decision = "bola", max(risk, 0.95), "BLOCK"
    return pred, risk, decision


def policy_v2(feats, pred, risk):
    decision = decide(pred, risk)
    if feats["body_sql_hits"] >= 3:
        return "sql_injection", max(risk, 0.95), "BLOCK"
    if feats["id_distinct_objects_10s"] >= 5:
        return "bola", max(risk, 0.95), "BLOCK"
    corroborated = (feats["ip_req_10s"] >= 8 or feats["ip_req_60s"] >= 30
                    or feats["token_ips_10s"] >= 5)
    if decision == "RATE_LIMIT" and corroborated and pred != "api_flooding":
        decision = "BLOCK"
    if pred == "api_flooding" and decision == "BLOCK":
        decision = "RATE_LIMIT"
    return pred, risk, decision


def record_login(meta, is_err):
    if not meta["is_login"]:
        return
    login_global.append((meta["now"], is_err, meta["uname"]))
    account_state.get_deque(meta["uname"]).append((meta["now"], is_err))


def rate_exceeded(ip, now):
    rl = (V3 or {}).get("rate_limit", {"rate_per_sec": 10, "burst": 20})
    if ip in buckets:
        tokens, last = buckets[ip]
        buckets.move_to_end(ip)
    else:
        tokens, last = rl["burst"], now
    tokens = min(rl["burst"], tokens + (now - last) * rl["rate_per_sec"])
    if tokens < 1:
        buckets[ip] = (tokens, now)
        return True
    buckets[ip] = (tokens - 1, now)
    while len(buckets) > MAX_KEYS:
        buckets.popitem(last=False)
    return False


def policy_v3(feats, pred, risk, meta):
    if feats["body_sql_hits"] >= V3["sql_hard"]:
        return "sql_injection", max(risk, 0.95), "BLOCK"
    if "path_sql_hard" in V3 and feats["path_sql_hits"] >= V3["path_sql_hard"]:
        return "sql_injection", max(risk, 0.95), "BLOCK"
    if "bola_hard" in V3 and feats["id_distinct_objects_10s"] >= V3["bola_hard"]:
        return "bola", max(risk, 0.95), "BLOCK"
    if V3.get("tamper_hard") and meta["tamper"]:
        return "parameter_tampering", max(risk, 0.95), "BLOCK"
    if "objects_60s" in V3 and feats["id_distinct_objects_60s"] >= V3["objects_60s"]:
        return "bola", max(risk, 0.95), "BLOCK"
    decision = "ALLOW"
    fcount = feats["id_req_10s"] if (V3.get("flood_identity_auth") and meta["subject"]) else feats["ip_req_10s"]
    if pred == "api_flooding" and fcount < V3.get("flood_min_req_10s", 0):
        pred = "normal"
    if pred == "bola" and feats["id_distinct_objects_10s"] < V3.get("bola_min_objects", 0):
        pred = "normal"
    if pred != "normal" and risk >= V3["tau_r"]:
        decision = "RATE_LIMIT"
        if risk >= V3["tau_b"]:
            for col, thr in V3["sig"].get(pred, []):
                if feats[col] >= thr:
                    decision = "BLOCK"
                    break
        if decision == "BLOCK" and pred == "api_flooding" and V3.get("flood_throttle_only"):
            decision = "RATE_LIMIT"
    if decision == "ALLOW" and "login_fail_60s" in V3 and meta["is_login"] and feats["ip_login_fail_60s"] >= V3["login_fail_60s"]:
        return "brute_force", risk, "RATE_LIMIT"
    if decision == "ALLOW" and "src_req_60s" in V3 and feats["src_req_60s"] >= V3["src_req_60s"]:
        return "api_flooding", risk, "RATE_LIMIT"
    bkey = meta["okey"] if (V3.get("bucket_identity_auth") and meta["subject"]) else meta["ip"]
    if decision == "ALLOW" and rate_exceeded(bkey, meta["now"]):
        return "api_flooding", risk, "RATE_LIMIT"
    return pred, risk, decision


def log_decision(meta, method, pred, risk, decision):
    row = {"timestamp": datetime.now(timezone.utc).isoformat(), "ip": meta["ip"], "method": method,
           "endpoint": meta["ep_norm"], "predicted": pred, "risk": round(risk, 3), "decision": decision}
    if ASYNC_LOG:
        log_queue.append(row)
    else:
        with open(DECISION_LOG, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=DEC_FIELDS).writerow(row)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(path: str, request: Request):
    body_bytes = await request.body()
    feats, meta = extract(request, body_bytes)
    pred, risk = score(feats)
    if POLICY in ("v3", "v4", "v5", "v6", "v7", "v8", "v9"):
        pred, risk, decision = policy_v3(feats, pred, risk, meta)
    else:
        pred, risk, decision = (policy_v2 if POLICY == "v2" else policy_v1)(feats, pred, risk)
    log_decision(meta, request.method, pred, risk, decision)

    if decision in ("BLOCK", "RATE_LIMIT"):
        meta["dq"].append((meta["now"], 1, meta["is_login"], meta["ep_norm"], meta["tuser"]))
        meta["dq_long"].append(meta["now"])
        record_login(meta, 1)
        if meta["is_login"]:
            meta["fq"].append(meta["now"])
        status = 403 if decision == "BLOCK" else 429
        msg = "Request blocked by APISentry" if decision == "BLOCK" else "Rate limited by APISentry"
        return Response(
            content=json.dumps({"error": msg, "attack_type": pred, "risk_score": round(risk, 3)}),
            status_code=status, media_type="application/json",
            headers={"X-APISentry-Decision": decision, "X-APISentry-Risk": str(round(risk, 3))})

    url = BACKEND + request.url.path
    if request.url.query:
        url += "?" + request.url.query
    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("host", "content-length")
                   and not (k.lower() == "authorization" and v.strip().lower() in ("", "bearer"))}
    if client is not None:
        r = await client.request(request.method, url, content=body_bytes, headers=fwd_headers)
    else:
        async with httpx.AsyncClient() as c:
            r = await c.request(request.method, url, content=body_bytes, headers=fwd_headers, timeout=30.0)

    is_err = 1 if (r.status_code >= 400 or (meta["is_login"] and LOGIN_FAIL_MARKER and LOGIN_FAIL_MARKER in r.content)) else 0
    meta["dq"].append((meta["now"], is_err, meta["is_login"], meta["ep_norm"], meta["tuser"]))
    meta["dq_long"].append(meta["now"])
    record_login(meta, is_err)
    if meta["is_login"] and is_err:
        meta["fq"].append(meta["now"])

    return Response(content=r.content, status_code=r.status_code,
                    media_type=r.headers.get("content-type"),
                    headers={"X-APISentry-Decision": decision,
                             "X-APISentry-Risk": str(round(risk, 3)),
                             "X-APISentry-Predicted": pred})
