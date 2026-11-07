import sys, json, re, time
sys.path.insert(0, ".")
import numpy as np
from collections import deque
from sklearn.model_selection import StratifiedGroupKFold
import features as F
import common as C
import stats as S

raw = F.load_raw()
static = F.static_features(raw, "gateway")
y = raw["label"].to_numpy(dtype=object)
n = len(raw)
sess = raw["session_id"].astype(str).to_numpy()
ts_all = raw["ts"].to_numpy(dtype=float)
ip_all = raw["ip_address"].astype(str).to_numpy()
uid_all = raw["user_id"].astype(str).to_numpy()
LAB = sorted(set(y)); ATK = [c for c in LAB if c != "normal"]
V6 = json.load(open(sys.argv[1]))
PRICE_FIELDS = ("unit_price", "price", "discount", "total")
NUMSTR = re.compile(r"^\s*-\s*\d+(\.\d+)?\s*$")


def tamper_v6(b):
    try:
        o = json.loads(b or "null")
    except Exception:
        return 0
    if not isinstance(o, dict):
        return 0
    neg = any(isinstance(v, (int, float)) and not isinstance(v, bool) and v < 0 for v in o.values())
    return int(neg or any(k in o for k in PRICE_FIELDS))


def walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in PRICE_FIELDS:
                return True
            if walk(v):
                return True
        return False
    if isinstance(o, list):
        return any(walk(v) for v in o)
    if isinstance(o, bool):
        return False
    if isinstance(o, (int, float)):
        return o < 0
    if isinstance(o, str):
        return bool(NUMSTR.match(o))
    return False


def tamper_v7(b):
    try:
        o = json.loads(b or "null")
    except Exception:
        return 0
    if not isinstance(o, (dict, list)):
        return 0
    return int(walk(o))


body = raw["request_body"].fillna("").astype(str)
T6 = body.map(tamper_v6).to_numpy().astype(bool)
T7 = body.map(tamper_v7).to_numpy().astype(bool)
ANON = set(F.ANON)
okey = np.array([ip_all[i] if uid_all[i] in ANON else ip_all[i] + "|" + uid_all[i] for i in range(n)])
ep = raw["endpoint"].astype(str).to_numpy()
login = ep == "/login"
lfail = login & (raw["status_code"].to_numpy() >= 400)
tu = raw["endpoint"].astype(str).str.extract(r"^/users/(\d+)")[0].fillna("").to_numpy()


def long_feats(stream):
    f60 = np.zeros(n); o60 = np.zeros(n); r60 = np.zeros(n)
    qf, qo, qr = {}, {}, {}
    for i in np.argsort(ts_all, kind="stable"):
        t = ts_all[i]; g = stream[i]
        d = qf.setdefault((g, ip_all[i]), deque())
        while d and t - d[0] > 60:
            d.popleft()
        f60[i] = len(d)
        if lfail[i]:
            d.append(t)
        d2 = qo.setdefault((g, okey[i]), deque())
        if tu[i]:
            d2.append((t, tu[i]))
        while d2 and t - d2[0][0] > 60:
            d2.popleft()
        o60[i] = len(set(x[1] for x in d2))
        d3 = qr.setdefault((g, okey[i]), deque())
        d3.append(t)
        while d3 and t - d3[0] > 60:
            d3.popleft()
        r60[i] = len(d3)
    return f60, o60, r60


def feats(stream):
    w = F.window_features(static, key="ip", stream=stream, strict=True)
    w = F.account_features(w, stream=stream)
    e, _ = F.encode(w)
    e[F.ALLNUM] = e[F.ALLNUM].fillna(0)
    return e


def graded(pred, risk, f, cfg, floor=0, thr_only=False):
    p = np.asarray(pred, dtype=object).copy()
    if floor:
        p[(p == "api_flooding") & (f["ip_req_10s"].to_numpy() < floor)] = "normal"
    act = np.where((p != "normal") & (risk >= cfg["tau_r"]), "RATE_LIMIT", "ALLOW").astype(object)
    for c, rules in cfg["sig"].items():
        ev = np.zeros(len(p), bool)
        for col, thr in rules:
            ev |= f[col].to_numpy() >= thr
        act[(p == c) & (risk >= cfg["tau_b"]) & ev] = "BLOCK"
    if thr_only:
        act[(p == "api_flooding") & (act == "BLOCK")] = "RATE_LIMIT"
    return p, act


def bucket(act, ts, keys, rate=10.0, burst=20.0):
    act = act.copy(); st = {}
    for i in np.argsort(ts, kind="stable"):
        if act[i] != "ALLOW":
            continue
        k = keys[i]
        tok, last = st.get(k, (burst, ts[i]))
        tok = min(burst, tok + (ts[i] - last) * rate)
        if tok < 1:
            st[k] = (tok, ts[i]); act[i] = "RATE_LIMIT"
        else:
            st[k] = (tok - 1, ts[i])
    return act


def policy(pred, risk, f, idx, tam, lg=None):
    _, a = graded(pred, risk, f, V6, floor=V6["flood_min_req_10s"], thr_only=True)
    if lg is not None:
        f60, o60, r60 = lg
        a[(login[idx]) & (f60[idx] >= lg_cfg["login_fail_60s"]) & (a == "ALLOW")] = "RATE_LIMIT"
        a[(r60[idx] >= lg_cfg["src_req_60s"]) & (a == "ALLOW")] = "RATE_LIMIT"
        a[o60[idx] >= lg_cfg["objects_60s"]] = "BLOCK"
    a[(f["body_sql_hits"].to_numpy() >= V6["sql_hard"]) | (f["id_distinct_objects_10s"].to_numpy() >= V6["bola_hard"]) | tam[idx]] = "BLOCK"
    return bucket(a, ts_all[idx], ip_all[idx], V6["rate_limit"]["rate_per_sec"], V6["rate_limit"]["burst"])


GF = [2, 3, 4, 5, 6, 8]; GO = [8, 9, 10, 12, 15]; GR = [20, 25, 30, 35, 40, 50]


def select(idx, yv, lg):
    f60, o60, r60 = lg
    ben = yv == "normal"
    return {"login_fail_60s": next((g for g in GF if ((login[idx]) & (f60[idx] >= g) & ben).sum() == 0), 99),
            "objects_60s": next((g for g in GO if ((o60[idx] >= g) & ben).sum() == 0), 99),
            "src_req_60s": next((g for g in GR if ((r60[idx] >= g) & ben).sum() == 0), 99)}


def summ(yt, act, g):
    ben = yt == "normal"
    o = {"benign_blocked_n": int((act[ben] == "BLOCK").sum()), "benign_throttled_n": int((act[ben] == "RATE_LIMIT").sum()), "n_benign": int(ben.sum()),
         "attack_enforced": round(float((act[~ben] != "ALLOW").mean()), 4), "attack_blocked": round(float((act[~ben] == "BLOCK").mean()), 4),
         "per_attack_enforced": {c: round(float((act[yt == c] != "ALLOW").mean()), 3) for c in ATK}}
    o["ci_hard_block"] = S.boot_binary(~ben, act == "BLOCK", g)
    o["ci_any_enforcement"] = S.boot_binary(~ben, act != "ALLOW", g)
    return o


R = {"tamper_rule_on_full_corpus": {"v6": {c: int(T6[y == c].sum()) for c in LAB}, "v7": {c: int(T7[y == c].sum()) for c in LAB}}}
outer = list(StratifiedGroupKFold(5, shuffle=True, random_state=42).split(np.zeros(n), y, sess))
acc = {k: {"y": [], "a": [], "g": []} for k in ["v6", "v7"]}
vy, vidx = [], []
folds = []
for k, (tr, te) in enumerate(outer):
    tri = np.array(tr); te = np.array(te)
    itr, iva = next(StratifiedGroupKFold(4, shuffle=True, random_state=200 + k).split(tri, y[tri], sess[tri]))
    a, b = tri[itr], tri[iva]
    stream = np.full(n, 0); stream[b] = 1; stream[te] = 2
    d = feats(stream)
    lg = long_feats(stream)
    m = C.cb().fit(d.iloc[a][F.GW], y[a])
    pt, rt = C.predict(m, d.iloc[te][F.GW])
    ft = d.iloc[te].reset_index(drop=True)
    lg_cfg = select(b, y[b], lg)
    folds.append(lg_cfg)
    vy.append(y[b]); vidx.append((b, lg))
    a6 = policy(pt, rt, ft, te, T6)
    a7 = policy(pt, rt, ft, te, T7, lg)
    for nm, aa in (("v6", a6), ("v7", a7)):
        acc[nm]["y"].append(y[te]); acc[nm]["a"].append(aa); acc[nm]["g"].append(sess[te])
    print("fold", k, lg_cfg, flush=True)
R["fold_long_rule_values"] = folds
for nm, v in acc.items():
    R[nm] = summ(np.concatenate(v["y"]), np.concatenate(v["a"]), np.concatenate(v["g"]))
    print(nm, R[nm]["benign_blocked_n"], R[nm]["benign_throttled_n"], R[nm]["attack_enforced"], json.dumps(R[nm]["per_attack_enforced"]), flush=True)
dep = {}
for key, grid in (("login_fail_60s", GF), ("objects_60s", GO), ("src_req_60s", GR)):
    ok = []
    for g in grid:
        bad = 0
        for (bi, lg), yv in zip(vidx, vy):
            f60, o60, r60 = lg
            ben = yv == "normal"
            v = {"login_fail_60s": login[bi] & (f60[bi] >= g), "objects_60s": o60[bi] >= g, "src_req_60s": r60[bi] >= g}[key]
            bad += int((v & ben).sum())
        if bad == 0:
            dep[key] = g
            break
R["deploy_long_rule_values"] = dep
print("deploy", dep)
json.dump(R, open("out/e12_v7.json", "w"), indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))
print("done")
