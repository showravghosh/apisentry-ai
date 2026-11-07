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


AUTH = np.array([u not in set(F.ANON) for u in uid_all])


def long_feats(stream):
    f60 = np.zeros(n); o60 = np.zeros(n); r60 = np.zeros(n); i10 = np.zeros(n)
    qf, qo, qr, qi = {}, {}, {}, {}
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
        d4 = qi.setdefault((g, okey[i]), deque())
        d4.append(t)
        while d4 and t - d4[0] > 10:
            d4.popleft()
        i10[i] = len(d4)
    return f60, o60, r60, i10


def feats(stream):
    w = F.window_features(static, key="ip", stream=stream, strict=True)
    w = F.account_features(w, stream=stream)
    e, _ = F.encode(w)
    e[F.ALLNUM] = e[F.ALLNUM].fillna(0)
    return e


def graded(pred, risk, f, cfg, floor=0, thr_only=False, fcount=None):
    p = np.asarray(pred, dtype=object).copy()
    if floor:
        fc = f["ip_req_10s"].to_numpy() if fcount is None else fcount
        p[(p == "api_flooding") & (fc < floor)] = "normal"
    if cfg.get("bola_min_objects"):
        p[(p == "bola") & (f["id_distinct_objects_10s"].to_numpy() < cfg["bola_min_objects"])] = "normal"
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
    f60, o60, r60, i10 = lg
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


V7 = json.load(open(sys.argv[2]))
import pandas as pd


def stages(pred, risk, f, idx, lg, V7):
    f60, o60, r60, i10 = lg
    fcount = np.where(AUTH[idx], i10[idx], f["ip_req_10s"].to_numpy()) if V7.get("flood_identity_auth") else None
    bkeys = okey[idx] if V7.get("bucket_identity_auth") else ip_all[idx]
    out = {}
    _, a0 = graded(pred, risk, f, V7)
    out["classifier_stage"] = a0.copy()
    sq = f["body_sql_hits"].to_numpy() >= V7["sql_hard"]
    bo = f["id_distinct_objects_10s"].to_numpy() >= V7["bola_hard"]
    tm = T7[idx]
    a = a0.copy(); a[sq] = "BLOCK"; out["+sql_rule"] = a.copy()
    a[bo] = "BLOCK"; out["+bola_10s_rule"] = a.copy()
    a[tm] = "BLOCK"; out["+tamper_rule"] = a.copy()
    _, a1 = graded(pred, risk, f, V7, floor=V7["flood_min_req_10s"], thr_only=True, fcount=fcount)
    a1[sq | bo | tm] = "BLOCK"; out["+flood_floor_throttle"] = a1.copy()
    lf = login[idx] & (f60[idx] >= V7["login_fail_60s"]) & (a1 == "ALLOW")
    sr = (r60[idx] >= V7["src_req_60s"]) & (a1 == "ALLOW")
    ob = o60[idx] >= V7["objects_60s"]
    a2 = a1.copy(); a2[ob] = "BLOCK"; out["+objects_60s_rule"] = a2.copy()
    a2[lf & (a2 == "ALLOW")] = "RATE_LIMIT"; out["+login_fail_60s_rule"] = a2.copy()
    a2[sr & (a2 == "ALLOW")] = "RATE_LIMIT"; out["+src_req_60s_rule"] = a2.copy()
    a3 = bucket(a2, ts_all[idx], bkeys, V7["rate_limit"]["rate_per_sec"], V7["rate_limit"]["burst"])
    out["+rate_limiter_v7"] = a3
    fires = {"sql_rule": sq, "bola_10s_rule": bo, "tamper_rule": tm, "objects_60s_rule": ob, "login_fail_60s_rule": lf, "src_req_60s_rule": sr}
    return out, fires


def long_sweeps(idx, yv, lg):
    f60, o60, r60, i10 = lg
    ben = yv == "normal"
    o = {}
    for key, grid, mask, cls in (("login_fail_60s", GF, lambda g: login[idx] & (f60[idx] >= g), "brute_force"), ("objects_60s", GO, lambda g: o60[idx] >= g, "bola"), ("src_req_60s", GR, lambda g: r60[idx] >= g, "api_flooding")):
        o[key] = [{"h": g, "fires": int(mask(g).sum()), "fires_ben": int((mask(g) & ben).sum()), "hit_cls": int((mask(g) & (yv == cls)).sum()), "n_cls": int((yv == cls).sum()), "n_ben": int(ben.sum())} for g in grid]
    tm = T7[idx]
    o["tamper_v7"] = {"fires": int(tm.sum()), "fires_ben": int((tm & ben).sum()), "hit_cls": int((tm & (yv == "parameter_tampering")).sum()), "n_cls": int((yv == "parameter_tampering").sum())}
    return o


outer = list(StratifiedGroupKFold(5, shuffle=True, random_state=42).split(np.zeros(n), y, sess))
NSEL = []; ACT = {}; FIRE = {}; YY = []; GG = []; IX = []; SV = []; STT = []
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
    st, fi = stages(pt, rt, ft, te, lg, V7)
    for s_, v in st.items():
        ACT.setdefault(s_, []).append(v)
    sel = select(b, y[b], lg)
    VN = dict(V7); VN.update(sel)
    stn, _ = stages(pt, rt, ft, te, lg, VN)
    ACT.setdefault("nested_full", []).append(stn["+rate_limiter_v7"])
    NSEL.append(sel)
    for s_, v in fi.items():
        FIRE.setdefault(s_, []).append(v)
    YY.append(y[te]); GG.append(sess[te]); IX.append(te)
    SV.append(long_sweeps(b, y[b], lg)); STT.append(long_sweeps(te, y[te], lg))
    print("fold", k, flush=True)
Y = np.concatenate(YY); G = np.concatenate(GG); IDX = np.concatenate(IX)
A = {k: np.concatenate(v) for k, v in ACT.items()}
R = {"policy": V7, "nested_selected": NSEL, "note": "deployed values applied to every outer test fold; nested_full uses fold-selected long-window values", "stages": {k: summ(Y, v, G) for k, v in A.items()}}
ben = Y == "normal"; base = A["classifier_stage"]
R["rules"] = {}
for r_, fl in FIRE.items():
    fl = np.concatenate(fl)
    R["rules"][r_] = {"fires": int(fl.sum()), "fires_on_benign": int((fl & ben).sum()), "new_benign_flags": int((fl & ben & (base == "ALLOW")).sum()),
                      "attacks_recovered": int((fl & ~ben & (base == "ALLOW")).sum()), "precision": round(float((fl & ~ben).sum() / max(fl.sum(), 1)), 4)}
fl_drop = (base != "ALLOW") & (A["+flood_floor_throttle"] == "ALLOW")
R["rules"]["flood_floor_effect"] = {"benign_released": int((fl_drop & ben).sum()), "attacks_released": int((fl_drop & ~ben).sum())}


def merge(lst):
    o = {}
    for key in ["login_fail_60s", "objects_60s", "src_req_60s"]:
        rows = []
        for i in range(len(lst[0][key])):
            r = dict(lst[0][key][i])
            for kk in r:
                if kk != "h":
                    r[kk] = sum(x[key][i][kk] for x in lst)
            rows.append(r)
        o[key] = rows
    o["tamper_v7"] = {kk: sum(x["tamper_v7"][kk] for x in lst) for kk in lst[0]["tamper_v7"]}
    return o


R["long_rule_sweeps"] = {"validation": merge(SV), "test": merge(STT)}
A7 = A["+rate_limiter_v7"]
order = np.lexsort((ts_all[IDX], G))
df = pd.DataFrame({"g": G[order], "y": Y[order], "a": A7[order], "t": ts_all[IDX][order]})
df = df[df.y != "normal"]
ep = []
for (g, c), grp in df.groupby(["g", "y"], sort=False):
    e = (grp.a != "ALLOW").to_numpy()
    first = int(np.argmax(e)) if e.any() else None
    ep.append({"attack": c, "n": len(grp), "detected": bool(e.any()), "first_blocked": bool(e[0]), "passed_before_first": first,
               "time_to_first": float(grp.t.to_numpy()[first] - grp.t.to_numpy()[0]) if first is not None else None, "enf_rate": float(e.mean())})
E = pd.DataFrame(ep)
R["event_level_offline_v7"] = {c: {"episodes": int(len(x)), "episode_detection": round(float(x.detected.mean()), 3), "request_enforcement": round(float(x.enf_rate.mean()), 3),
                                   "first_request_enforced": round(float(x.first_blocked.mean()), 3),
                                   "median_requests_before_first": float(x.passed_before_first.dropna().median()) if x.detected.any() else None,
                                   "median_seconds_to_first": round(float(x.time_to_first.dropna().median()), 3) if x.detected.any() else None} for c, x in E.groupby("attack")}
np.savez_compressed("out/e15_%s_acts.npz" % sys.argv[3], y=Y, g=G, idx=IDX, **{"act_" + k.replace("+", "plus_"): v for k, v in A.items()})
json.dump(R, open("out/e15_%s_stages.json" % sys.argv[3], "w"), indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))
for k, v in R["stages"].items():
    print(k, v["benign_blocked_n"], v["benign_throttled_n"], v["attack_enforced"], v["attack_blocked"])
print(json.dumps(R["rules"]))
print(json.dumps(R["event_level_offline_v7"]))
print("done")
