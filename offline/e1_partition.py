import sys, json, time
sys.path.insert(0, ".")
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.metrics import f1_score, precision_recall_fscore_support
import features as F
import common as C

raw = F.load_raw()
static = F.static_features(raw, "gateway")
y = raw["label"].to_numpy(dtype=object)
n = len(raw)
sess = raw["session_id"].astype(str).to_numpy()
ip = raw["ip_address"].astype(str).to_numpy()
ident = F.source_key(raw, "identity")
FEATS = {"robust": F.GW, "submitted_set": F.GW_SUBMITTED}


def feats(stream=None):
    w = F.window_features(static, key="ip", stream=stream, strict=True)
    w = F.account_features(w, stream=stream)
    e, _ = F.encode(w)
    e[F.ALLNUM] = e[F.ALLNUM].fillna(0)
    return e


def per_class(yt, yp):
    p, r, f, s = precision_recall_fscore_support(yt, yp, labels=F.LABELS, zero_division=0)
    return {c: {"prec": round(float(p[i]), 3), "rec": round(float(r[i]), 3), "f1": round(float(f[i]), 3), "n": int(s[i])} for i, c in enumerate(F.LABELS)}


def fold_assign(groups, k=5, seed=42):
    if groups is None:
        it = StratifiedKFold(k, shuffle=True, random_state=seed).split(np.zeros(n), y)
    else:
        it = StratifiedGroupKFold(k, shuffle=True, random_state=seed).split(np.zeros(n), y, groups)
    fold = np.zeros(n, dtype=int)
    for f, (_, te) in enumerate(it):
        fold[te] = f
    return fold


def run_protocol(name, fold, rebuild, fs="robust"):
    oof = np.empty(n, dtype=object)
    oof_risk = np.zeros(n)
    fm = []
    base = None if rebuild else feats(None)
    for f in range(fold.max() + 1):
        te = fold == f
        tr = ~te
        if rebuild:
            d = feats(np.where(te, 1, 0))
        else:
            d = base
        m = C.cb().fit(d.loc[tr, FEATS[fs]], y[tr])
        p, r = C.predict(m, d.loc[te, FEATS[fs]])
        oof[te] = p
        oof_risk[te] = r
        fm.append(C.metrics(y[te], p))
    agg = C.metrics(y, oof)
    out = {"protocol": name, "features": fs, "rebuild_within_partition": rebuild,
           "pooled": {k: round(v, 4) for k, v in agg.items()},
           "fold_macroF1_mean": round(float(np.mean([x["macroF1"] for x in fm])), 4),
           "fold_macroF1_std": round(float(np.std([x["macroF1"] for x in fm])), 4),
           "fold_fpr_mean": round(float(np.mean([x["fpr"] for x in fm])), 4),
           "per_class": per_class(y, oof)}
    print(name, fs, "rebuild" if rebuild else "global", out["pooled"], "folds", out["fold_macroF1_mean"], "+/-", out["fold_macroF1_std"], flush=True)
    return out, oof, oof_risk


def chrono_fold():
    lab = pd.Series(y).groupby(sess).agg(lambda s: next((v for v in s if v != "normal"), "normal"))
    start = pd.Series(raw["ts"].to_numpy()).groupby(sess).min()
    fold = {}
    for c in lab.unique():
        ss = start[lab[lab == c].index].sort_values().index.tolist()
        k = len(ss)
        for j, s in enumerate(ss):
            fold[s] = 0 if j < int(0.6 * k) else (1 if j < int(0.8 * k) else 2)
    return np.array([fold[s] for s in sess])


def dependence():
    fold = fold_assign(None)
    te = fold == 0
    ts = raw["ts"].to_numpy()
    st = {}
    cross = np.zeros(n)
    tot = np.zeros(n)
    from collections import deque
    for i in range(n):
        dq = st.setdefault(ip[i], deque())
        dq.append((ts[i], te[i]))
        while dq and ts[i] - dq[0][0] > F.W_SHORT:
            dq.popleft()
        tot[i] = len(dq) - 1
        cross[i] = sum(1 for x in dq if not x[1]) if te[i] else 0
    m = te
    share = np.where(tot[m] > 0, cross[m] / np.maximum(tot[m], 1), 0)
    return {"test_requests": int(m.sum()),
            "test_with_any_train_history": round(float((cross[m] > 0).mean()), 4),
            "mean_share_of_window_from_train": round(float(share[tot[m] > 0].mean()), 4),
            "by_class_any_train_history": {c: round(float((cross[m & (y == c)] > 0).mean()), 3) for c in F.LABELS}}


R = {"dependence_original_protocol": dependence()}
print("dependence", R["dependence_original_protocol"], flush=True)
oofs = {}
rows = []
for name, groups in [("stratified_rows", None), ("session_grouped", sess), ("source_grouped", ip), ("identity_grouped", ident)]:
    fold = fold_assign(groups)
    for rebuild in ([False, True] if name != "identity_grouped" else [True]):
        o, p, r = run_protocol(name, fold, rebuild)
        rows.append(o)
        oofs[(name, rebuild)] = (p, r)
o, _, _ = run_protocol("stratified_rows", fold_assign(None), False, "submitted_set"); rows.append(o)
o, _, _ = run_protocol("session_grouped", fold_assign(sess), True, "submitted_set"); rows.append(o)

cf = chrono_fold()
d = feats(np.where(cf == 2, 1, np.where(cf == 1, 2, 0)))
trm, tem = cf == 0, cf == 2
for fs in ["robust", "submitted_set"]:
    m = C.cb().fit(d.loc[trm, FEATS[fs]], y[trm])
    p, r = C.predict(m, d.loc[tem, FEATS[fs]])
    t0 = raw["ts"].to_numpy()[tem]
    warm = t0 - t0.min() >= F.W_LONG
    o = {"protocol": "chronological_per_class_sessions", "features": fs, "rebuild_within_partition": True,
         "pooled": {k: round(v, 4) for k, v in C.metrics(y[tem], p).items()},
         "after_warmup_60s": {k: round(v, 4) for k, v in C.metrics(y[tem][warm], p[warm]).items()},
         "n_train": int(trm.sum()), "n_test": int(tem.sum()), "per_class": per_class(y[tem], p)}
    print(o["protocol"], fs, o["pooled"], "warm", o["after_warmup_60s"], flush=True)
    rows.append(o)

ia = np.isin(raw["user_id"].to_numpy(), ["alice"])
ib = np.isin(raw["user_id"].to_numpy(), ["bob"])
anon_fold = fold_assign(np.where(np.isin(raw["user_id"].to_numpy(), F.ANON), ip, "x"), k=2)
lopo = []
for test_user, train_user in [("alice", "bob"), ("bob", "alice")]:
    anon = np.isin(raw["user_id"].to_numpy(), F.ANON)
    tem = (raw["user_id"].to_numpy() == test_user) | (anon & (anon_fold == (0 if test_user == "alice" else 1)))
    d = feats(np.where(tem, 1, 0))
    m = C.cb().fit(d.loc[~tem, F.GW], y[~tem])
    p, r = C.predict(m, d.loc[tem, F.GW])
    o = {"protocol": "leave_one_principal_out", "test_principal": test_user, "rebuild_within_partition": True,
         "pooled": {k: round(v, 4) for k, v in C.metrics(y[tem], p).items()}, "per_class": per_class(y[tem], p)}
    print(o["protocol"], test_user, o["pooled"], "token_replay", o["per_class"]["token_replay"], flush=True)
    rows.append(o)
R["protocols"] = rows
json.dump(R, open("out/e1_partition.json", "w"), indent=2)
np.save("out/oof_session_rebuild.npy", np.array([oofs[("session_grouped", True)][0], oofs[("session_grouped", True)][1]], dtype=object), allow_pickle=True)
np.save("out/oof_stratified_global.npy", np.array([oofs[("stratified_rows", False)][0], oofs[("stratified_rows", False)][1]], dtype=object), allow_pickle=True)
print("saved")
