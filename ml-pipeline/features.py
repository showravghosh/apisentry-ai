import os
import re
from collections import deque
from urllib.parse import unquote_plus
import numpy as np
import pandas as pd

DATA = os.getenv("APISENTRY_DATA", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "apishield_dataset_v1.csv"))
W_SHORT = 10.0
W_LONG = 60.0
SQL_LEGACY = ["select", "union", "drop", "or ", "'", "--", "#", "=", ";", "sleep"]
SQL_GATEWAY = ["select", "union", "drop", "or ", "and ", "--", "#", "=", ";", "sleep", "like", "||", "'"]
SPECIAL = ["'", '"', ";", "-", "=", "#", "(", ")", "|"]
ANON = ("anon", "invalid_token", "none", "nan")
KEY = os.getenv("APISENTRY_KEY", "ip")
NUM_BASE = ["request_size", "hour", "body_len", "body_special", "body_sql_hits", "body_max_num", "body_min_num",
       "body_has_neg", "body_field_count", "is_login", "ip_req_10s", "ip_fail_10s", "ip_fail_ratio_10s",
       "ip_login_10s", "ip_uniq_ep_10s", "ip_distinct_users_10s", "token_ips_10s"]
CAT = ["method_enc", "endpoint_norm_enc"]
ACCT = ["glob_login_fail_10s", "glob_login_users_10s", "acct_fail_60s"]
SHORTCUT = ["hour", "body_len", "request_size"]
NUM = [c for c in NUM_BASE if c not in SHORTCUT] + ACCT
GW = NUM + CAT
GW_SUBMITTED = NUM_BASE + CAT
ALLNUM = list(dict.fromkeys(NUM_BASE + NUM))
BEH = [c for c in GW if c.startswith(("ip_", "token_", "glob_", "acct_"))]
PAY = [c for c in GW if c not in BEH]
LABELS = ["api_flooding", "bola", "brute_force", "credential_stuffing", "normal",
          "parameter_tampering", "sql_injection", "token_replay"]


def load_raw(path=DATA):
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    df["ts"] = (df["timestamp"] - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds().to_numpy()
    df["user_id"] = df["user_id"].astype(str)
    return df


def norm_ep(p):
    return re.sub(r"/\d+", "/{id}", str(p))


def target_user(p):
    m = re.match(r"/users/(\d+)", str(p))
    return m.group(1) if m else None


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


def payload_features(text, mode="legacy"):
    if mode == "legacy":
        b = unquote_plus(str(text)).lower()
        kw = SQL_LEGACY
    else:
        b = normalize_payload(text)
        kw = SQL_GATEWAY
    return len(b), sum(b.count(c) for c in SPECIAL), sum(1 for k in kw if k in b)


def numeric_features(text):
    t = unquote_plus(str(text))
    vals = []
    for x in re.findall(r"-?\d+\.?\d*", t):
        try:
            vals.append(float(x))
        except ValueError:
            pass
    return (max(vals) if vals else 0.0), (min(vals) if vals else 0.0), (1 if any(v < 0 for v in vals) else 0), t.count(":")


def static_features(df, mode="legacy"):
    out = df.copy()
    out["endpoint_norm"] = out["endpoint"].apply(norm_ep)
    out["hour"] = out["timestamp"].dt.hour
    out["is_error"] = (out["status_code"] >= 400).astype(int)
    out["is_login"] = (out["endpoint"] == "/login").astype(int)
    out["target_user"] = out["endpoint"].apply(target_user)
    p = np.array([payload_features(b, mode) for b in out["request_body"]], dtype=float)
    out["body_len"], out["body_special"], out["body_sql_hits"] = p[:, 0], p[:, 1], p[:, 2]
    q = np.array([numeric_features(b) for b in out["request_body"]], dtype=float)
    out["body_max_num"], out["body_min_num"], out["body_has_neg"], out["body_field_count"] = q[:, 0], q[:, 1], q[:, 2], q[:, 3]
    return out


def source_key(df, key="ip"):
    if key == "ip":
        return df["ip_address"].astype(str).to_numpy()
    if key == "identity":
        u = df["user_id"].to_numpy()
        ip = df["ip_address"].astype(str).to_numpy()
        return np.where(np.isin(u, ANON), "ip:" + ip, "id:" + u)
    if key == "ip_identity":
        u = df["user_id"].to_numpy()
        ip = df["ip_address"].astype(str).to_numpy()
        return np.where(np.isin(u, ANON), ip, np.char.add(np.char.add(ip.astype(str), "|"), u.astype(str)))
    if key == "ip_ua":
        return (df["ip_address"].astype(str) + "|" + df["user_agent"].astype(str)).to_numpy()
    raise ValueError(key)


def window_features(df, key="ip", stream=None, strict=False):
    n = len(df)
    ts = df["ts"].to_numpy()
    src = source_key(df, key)
    ips = df["ip_address"].astype(str).to_numpy()
    err = df["is_error"].to_numpy()
    lo = df["is_login"].to_numpy()
    ep = df["endpoint_norm"].to_numpy()
    tu = df["target_user"].to_numpy()
    uid = df["user_id"].to_numpy()
    grp = np.zeros(n, dtype=int) if stream is None else np.asarray(stream)
    r10 = np.zeros(n); f10 = np.zeros(n); l10 = np.zeros(n); e10 = np.zeros(n); u10 = np.zeros(n)
    r60 = np.zeros(n); t10 = np.zeros(n); t60 = np.zeros(n); o10 = np.zeros(n)
    st, stl, tk, tkl, ob = {}, {}, {}, {}, {}
    okey = np.where(np.isin(uid, ANON), ips, np.char.add(np.char.add(ips.astype(str), "|"), uid.astype(str)))
    for i in range(n):
        k = (grp[i], src[i])
        dq = st.setdefault(k, deque())
        dq.append((ts[i], err[i], lo[i], ep[i], tu[i]))
        while dq and ts[i] - dq[0][0] > W_SHORT:
            dq.popleft()
        r10[i] = len(dq)
        f10[i] = sum(x[1] for x in dq) - (err[i] if strict else 0)
        l10[i] = sum(x[2] for x in dq)
        e10[i] = len(set(x[3] for x in dq))
        u10[i] = len(set(x[4] for x in dq if x[4] is not None))
        dl = stl.setdefault(k, deque())
        dl.append(ts[i])
        while dl and ts[i] - dl[0] > W_LONG:
            dl.popleft()
        r60[i] = len(dl)
        oq = ob.setdefault((grp[i], okey[i]), deque())
        if tu[i] is not None:
            oq.append((ts[i], tu[i]))
        while oq and ts[i] - oq[0][0] > W_SHORT:
            oq.popleft()
        o10[i] = len(set(x[1] for x in oq))
        if uid[i] in ANON:
            continue
        kt = (grp[i], uid[i])
        tq = tk.setdefault(kt, deque())
        tq.append((ts[i], ips[i]))
        while tq and ts[i] - tq[0][0] > W_SHORT:
            tq.popleft()
        t10[i] = len(set(x[1] for x in tq))
        tl = tkl.setdefault(kt, deque())
        tl.append((ts[i], ips[i]))
        while tl and ts[i] - tl[0][0] > W_LONG:
            tl.popleft()
        t60[i] = len(set(x[1] for x in tl))
    out = df.copy()
    out["ip_req_10s"] = r10
    out["ip_fail_10s"] = f10
    out["ip_fail_ratio_10s"] = f10 / np.maximum(r10, 1)
    out["ip_login_10s"] = l10
    out["ip_uniq_ep_10s"] = e10
    out["ip_distinct_users_10s"] = u10
    out["token_ips_10s"] = t10
    out["ip_req_60s"] = r60
    out["token_ips_60s"] = t60
    out["id_distinct_objects_10s"] = o10
    return out


def login_user(b):
    m = re.search(r'"username"\s*:\s*"([^"]*)"', str(b))
    return m.group(1) if m else None


def account_features(df, stream=None):
    n = len(df)
    ts = df["ts"].to_numpy()
    lo = df["is_login"].to_numpy()
    err = df["is_error"].to_numpy()
    un = df["request_body"].apply(login_user).to_numpy()
    grp = np.zeros(n, dtype=int) if stream is None else np.asarray(stream)
    gfail = np.zeros(n); gusers = np.zeros(n); afail = np.zeros(n); gep = np.zeros(n)
    gq, aq, eq = {}, {}, {}
    ep = df["endpoint_norm"].to_numpy()
    for i in range(n):
        ke = (grp[i], ep[i])
        e = eq.setdefault(ke, deque())
        e.append(ts[i])
        while e and ts[i] - e[0] > W_SHORT:
            e.popleft()
        gep[i] = len(e)
        if not lo[i]:
            continue
        q = gq.setdefault(grp[i], deque())
        while q and ts[i] - q[0][0] > W_SHORT:
            q.popleft()
        gfail[i] = sum(x[1] for x in q)
        gusers[i] = len(set(x[2] for x in q if x[2]) | ({un[i]} if un[i] else set()))
        k = (grp[i], un[i])
        a = aq.setdefault(k, deque())
        while a and ts[i] - a[0][0] > W_LONG:
            a.popleft()
        afail[i] = sum(x[1] for x in a)
        q.append((ts[i], err[i], un[i]))
        a.append((ts[i], err[i]))
    out = df.copy()
    out["glob_login_fail_10s"] = gfail
    out["glob_login_users_10s"] = gusers
    out["acct_fail_60s"] = afail
    out["glob_ep_req_10s"] = gep
    return out


METHODS = ["DELETE", "GET", "PATCH", "POST", "PUT"]


def encode(df, ep_classes=None):
    out = df.copy()
    if ep_classes is None:
        ep_classes = sorted(out["endpoint_norm"].astype(str).unique())
    m = {v: i for i, v in enumerate(ep_classes)}
    out["endpoint_norm_enc"] = out["endpoint_norm"].astype(str).map(lambda v: m.get(v, len(ep_classes)))
    mm = {v: i for i, v in enumerate(sorted(df["method"].astype(str).unique()))}
    out["method_enc"] = out["method"].astype(str).map(mm)
    return out, ep_classes


def build(df=None, mode="legacy", key="ip", stream=None, strict=False):
    key = KEY if key == "default" else key
    if df is None:
        df = load_raw()
    s = static_features(df, mode)
    w = window_features(s, key=key, stream=stream, strict=strict)
    w = account_features(w, stream=stream)
    e, _ = encode(w)
    e[ALLNUM] = e[ALLNUM].fillna(0)
    return e


GUARD = {"api_flooding": ("ip_req_10s", 8), "bola": ("ip_distinct_users_10s", 3), "brute_force": ("ip_fail_10s", 3),
         "token_replay": ("token_ips_10s", 4), "credential_stuffing": ("ip_login_10s", 3)}
TAU_R = 0.55
TAU_B = 0.85


def frozen_policy(pred, risk, f):
    pred = np.asarray(pred, dtype=object).copy()
    risk = np.asarray(risk, dtype=float).copy()
    act = np.where((pred != "normal") & (risk >= TAU_B), "BLOCK", np.where((pred != "normal") & (risk >= TAU_R), "RATE_LIMIT", "ALLOW")).astype(object)
    sq = f["body_sql_hits"].to_numpy() >= 3
    bo = (f["id_distinct_objects_10s"].to_numpy() >= 5) & ~sq
    corr = (f["ip_req_10s"].to_numpy() >= 8) | (f["ip_req_60s"].to_numpy() >= 30) | (f["token_ips_10s"].to_numpy() >= 5)
    esc = (act == "RATE_LIMIT") & corr & (pred != "api_flooding")
    act[esc] = "BLOCK"
    fl = (pred == "api_flooding") & (act == "BLOCK")
    act[fl] = "RATE_LIMIT"
    pred[bo] = "bola"; risk[bo] = np.maximum(risk[bo], 0.95); act[bo] = "BLOCK"
    pred[sq] = "sql_injection"; risk[sq] = np.maximum(risk[sq], 0.95); act[sq] = "BLOCK"
    return pred, risk, act


def gateway_policy(pred, risk, f, use_guard=True, use_sig=True, use_long=True):
    pred = np.asarray(pred, dtype=object).copy()
    risk = np.asarray(risk, dtype=float).copy()
    n = len(pred)
    if use_guard:
        for c, (col, t) in GUARD.items():
            m = (pred == c) & (f[col].to_numpy() < t)
            pred[m] = "normal"
            risk[m] = np.minimum(risk[m], 0.3)
    act = np.where((pred != "normal") & (risk >= TAU_B), "BLOCK",
                   np.where((pred != "normal") & (risk >= TAU_R), "RATE_LIMIT", "ALLOW")).astype(object)
    if use_sig:
        sq = f["body_sql_hits"].to_numpy() >= 3
        fl = f["ip_req_10s"].to_numpy() >= 8
        tr = f["token_ips_10s"].to_numpy() >= 5
        if use_long:
            fl = fl | (f["ip_req_60s"].to_numpy() >= 30)
            tr = tr | (f["token_ips_60s"].to_numpy() >= 3)
        bo = f["ip_distinct_users_10s"].to_numpy() >= 5
        for m, c in [(sq, "sql_injection"), (fl, "api_flooding"), (tr, "token_replay"), (bo, "bola")]:
            pred[m] = c
            risk[m] = np.maximum(risk[m], 0.95)
            act[m] = "BLOCK"
    return pred, risk, act
