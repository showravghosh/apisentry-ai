import sys, json, time, pickle, os, tempfile
sys.path.insert(0, ".")
import numpy as np
import pandas as pd
from scipy.stats import wilcoxon, chi2
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score, precision_recall_fscore_support, confusion_matrix, accuracy_score, precision_score, recall_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import LinearSVC
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
LAB = sorted(set(y))
ATK = [c for c in LAB if c != "normal"]
V6 = json.load(open(sys.argv[1]))
PRICE_FIELDS = ("unit_price", "price", "discount", "total")


def body_tampering(b):
    try:
        o = json.loads(b or "null")
    except Exception:
        return 0
    if not isinstance(o, dict):
        return 0
    neg = any(isinstance(v, (int, float)) and not isinstance(v, bool) and v < 0 for v in o.values())
    return int(neg or any(k in o for k in PRICE_FIELDS))


tam_all = raw["request_body"].fillna("").astype(str).map(body_tampering).to_numpy().astype(bool)


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
    act = act.copy()
    st = {}
    hit = np.zeros(len(act), bool)
    for i in np.argsort(ts, kind="stable"):
        if act[i] != "ALLOW":
            continue
        k = keys[i]
        tok, last = st.get(k, (burst, ts[i]))
        tok = min(burst, tok + (ts[i] - last) * rate)
        if tok < 1:
            st[k] = (tok, ts[i]); act[i] = "RATE_LIMIT"; hit[i] = True
        else:
            st[k] = (tok - 1, ts[i])
    return act, hit


def v6_stages(pred, risk, f, idx):
    cfg = V6
    out = {}
    _, a0 = graded(pred, risk, f, cfg)
    out["classifier_stage"] = a0.copy()
    sq = f["body_sql_hits"].to_numpy() >= cfg["sql_hard"]
    bo = f["id_distinct_objects_10s"].to_numpy() >= cfg["bola_hard"]
    tm = tam_all[idx]
    a = a0.copy(); a[sq] = "BLOCK"; out["+sql_rule"] = a.copy()
    a[bo] = "BLOCK"; out["+bola_rule"] = a.copy()
    a[tm] = "BLOCK"; out["+tamper_rule"] = a.copy()
    _, a1 = graded(pred, risk, f, cfg, floor=cfg["flood_min_req_10s"], thr_only=True)
    a1[sq | bo | tm] = "BLOCK"; out["+flood_floor_throttle"] = a1.copy()
    a2, hit = bucket(a1, ts_all[idx], ip_all[idx], cfg["rate_limit"]["rate_per_sec"], cfg["rate_limit"]["burst"])
    out["+rate_limiter_v6"] = a2
    fires = {"sql_rule": sq, "bola_rule": bo, "tamper_rule": tm, "rate_limiter": hit}
    return out, fires


def enf_summary(yt, act, g):
    ben = yt == "normal"
    o = {"benign_blocked_n": int((act[ben] == "BLOCK").sum()), "benign_throttled_n": int((act[ben] == "RATE_LIMIT").sum()), "n_benign": int(ben.sum()),
         "benign_blocked": round(float((act[ben] == "BLOCK").mean()), 4), "benign_throttled": round(float((act[ben] == "RATE_LIMIT").mean()), 4),
         "attack_blocked": round(float((act[~ben] == "BLOCK").mean()), 4), "attack_enforced": round(float((act[~ben] != "ALLOW").mean()), 4),
         "per_attack_enforced": {c: round(float((act[yt == c] != "ALLOW").mean()), 3) for c in ATK},
         "per_attack_blocked": {c: round(float((act[yt == c] == "BLOCK").mean()), 3) for c in ATK}}
    o["ci_hard_block"] = S.boot_binary(~ben, act == "BLOCK", g)
    o["ci_any_enforcement"] = S.boot_binary(~ben, act != "ALLOW", g)
    return o


def clf_summary(yt, yp, g):
    p, r, f1, sup = precision_recall_fscore_support(yt, yp, labels=LAB, zero_division=0)
    return {"acc": round(float(accuracy_score(yt, yp)), 4), "macro_prec": round(float(precision_score(yt, yp, average="macro", zero_division=0)), 4),
            "macro_rec": round(float(recall_score(yt, yp, average="macro", zero_division=0)), 4), "macroF1": round(float(f1_score(yt, yp, average="macro")), 4),
            "fpr": round(float((yp[yt == "normal"] != "normal").mean()), 4), "attack_recall": round(float((yp[yt != "normal"] != "normal").mean()), 4),
            "per_class": {c: {"prec": round(float(p[i]), 3), "rec": round(float(r[i]), 3), "f1": round(float(f1[i]), 3), "n": int(sup[i])} for i, c in enumerate(LAB)}}


def rule_baseline(f):
    p = np.full(len(f), "normal", dtype=object)
    bo = f["ip_distinct_users_10s"].to_numpy() >= 5
    tr = (f["token_ips_10s"].to_numpy() >= 5) | (f["token_ips_60s"].to_numpy() >= 3)
    fl = (f["ip_req_10s"].to_numpy() >= 8) | (f["ip_req_60s"].to_numpy() >= 30)
    sq = f["body_sql_hits"].to_numpy() >= 3
    for m, c in [(bo, "bola"), (tr, "token_replay"), (fl, "api_flooding"), (sq, "sql_injection")]:
        p[m] = c
    return p


TGRID = [0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95, 0.97, 0.99]
SQLG = [1, 2, 3, 4, 5, 6]
BOLAG = [3, 4, 5, 6, 7, 8, 10]
FLOODG = [6, 8, 10, 12, 15, 20]


def sweeps(pred, risk, f, yv, idx):
    ben = yv == "normal"
    att = ~ben
    o = {"thresh": [], "sql": [], "bola": [], "flood_floor": [], "tamper": {}}
    for t in TGRID:
        fl = (pred != "normal") & (risk >= t)
        o["thresh"].append({"t": t, "flag_att": int((fl & att).sum()), "flag_ben": int((fl & ben).sum()), "n_att": int(att.sum()), "n_ben": int(ben.sum())})
    v = f["body_sql_hits"].to_numpy()
    for h in SQLG:
        fl = v >= h
        o["sql"].append({"h": h, "fires": int(fl.sum()), "fires_ben": int((fl & ben).sum()), "hit_cls": int((fl & (yv == "sql_injection")).sum()), "n_cls": int((yv == "sql_injection").sum()), "n_ben": int(ben.sum())})
    v = f["id_distinct_objects_10s"].to_numpy()
    for h in BOLAG:
        fl = v >= h
        o["bola"].append({"h": h, "fires": int(fl.sum()), "fires_ben": int((fl & ben).sum()), "hit_cls": int((fl & (yv == "bola")).sum()), "n_cls": int((yv == "bola").sum()), "n_ben": int(ben.sum())})
    r10 = f["ip_req_10s"].to_numpy()
    for h in FLOODG:
        fl = (pred == "api_flooding") & (risk >= V6["tau_r"]) & (r10 >= h)
        o["flood_floor"].append({"h": h, "fires": int(fl.sum()), "fires_ben": int((fl & ben).sum()), "hit_cls": int((fl & (yv == "api_flooding")).sum()), "n_cls": int((yv == "api_flooding").sum()), "n_ben": int(ben.sum())})
    tm = tam_all[idx]
    o["tamper"] = {"fires": int(tm.sum()), "fires_ben": int((tm & ben).sum()), "hit_cls": int((tm & (yv == "parameter_tampering")).sum()), "n_cls": int((yv == "parameter_tampering").sum())}
    return o


def merge_sweeps(lst):
    o = {}
    for key in ["thresh", "sql", "bola", "flood_floor"]:
        rows = []
        for i in range(len(lst[0][key])):
            r = dict(lst[0][key][i])
            for k in r:
                if k not in ("t", "h"):
                    r[k] = sum(x[key][i][k] for x in lst)
            rows.append(r)
        o[key] = rows
    o["tamper"] = {k: sum(x["tamper"][k] for x in lst) for k in lst[0]["tamper"]}
    return o


MODELS = {"CatBoost": C.cb, "Random Forest": lambda: RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1),
          "KNN (k=7)": lambda: KNeighborsClassifier(n_neighbors=7), "Linear SVM": lambda: LinearSVC(class_weight="balanced", max_iter=4000),
          "Logistic Regression": lambda: LogisticRegression(max_iter=2000, class_weight="balanced")}
outer = list(StratifiedGroupKFold(5, shuffle=True, random_state=42).split(np.zeros(n), y, sess))
OOF = {"y": [], "g": [], "idx": []}
VAL = {"y": [], "g": []}
mp = {k: [] for k in MODELS}; mpv = {k: [] for k in MODELS}
views = {"payload_only": F.PAY, "behavioural_only": F.BEH, "both": F.GW}
vp = {k: [] for k in views}
risk_oof = []
acts = {}; rules_fire = {}; actv1 = []; rbase = []
swv = []; swt = []
cost = {}
for k, (tr, te) in enumerate(outer):
    t0 = time.time()
    tri = np.array(tr)
    itr, iva = next(StratifiedGroupKFold(4, shuffle=True, random_state=200 + k).split(tri, y[tri], sess[tri]))
    a, b = tri[itr], tri[iva]
    te = np.array(te)
    stream = np.full(n, 0); stream[b] = 1; stream[te] = 2
    d = feats(stream)
    fv = d.iloc[b].reset_index(drop=True); ft = d.iloc[te].reset_index(drop=True)
    OOF["y"].append(y[te]); OOF["g"].append(sess[te]); OOF["idx"].append(te)
    VAL["y"].append(y[b]); VAL["g"].append(sess[b])
    for name, mk in MODELS.items():
        m = mk(); m.fit(d.iloc[a][F.GW], y[a])
        mpv[name].append(np.asarray(m.predict(d.iloc[b][F.GW])).ravel().astype(object))
        mp[name].append(np.asarray(m.predict(d.iloc[te][F.GW])).ravel().astype(object))
        if k == 0 and name in ("CatBoost", "Random Forest", "KNN (k=7)"):
            x1 = d.iloc[te][F.GW].iloc[[0]]
            for _ in range(20):
                m.predict(x1)
            tt = []
            for i in range(300):
                xi = d.iloc[te][F.GW].iloc[[i]]
                s0 = time.perf_counter(); m.predict(xi); tt.append((time.perf_counter() - s0) * 1000)
            fd, pth = tempfile.mkstemp(); os.close(fd)
            if name == "CatBoost":
                m.save_model(pth)
            else:
                pickle.dump(m, open(pth, "wb"))
            cost[name] = {"single_request_ms_median": round(float(np.median(tt)), 3), "single_request_ms_p95": round(float(np.percentile(tt, 95)), 3), "model_size_MB": round(os.path.getsize(pth) / 1e6, 2)}
            os.remove(pth)
        if name == "CatBoost":
            pv, rv = C.predict(m, d.iloc[b][F.GW])
            pt, rt = C.predict(m, d.iloc[te][F.GW])
    for vn, cols in views.items():
        if vn == "both":
            vp[vn].append(mp["CatBoost"][-1])
            continue
        m = C.cb().fit(d.iloc[a][cols], y[a])
        vp[vn].append(np.asarray(m.predict(d.iloc[te][cols])).ravel().astype(object))
    risk_oof.append(rt)
    st, fires = v6_stages(pt, rt, ft, te)
    for s_, aa in st.items():
        acts.setdefault(s_, []).append(aa)
    for r_, fl in fires.items():
        rules_fire.setdefault(r_, []).append(fl)
    _, _, a1 = F.gateway_policy(pt, rt, ft, use_guard=True, use_sig=True, use_long=True)
    actv1.append(a1)
    rbase.append(rule_baseline(ft))
    swv.append(sweeps(pv, rv, fv, y[b], b)); swt.append(sweeps(pt, rt, ft, y[te], te))
    print("fold", k, "done %.0fs" % (time.time() - t0), flush=True)

Y = np.concatenate(OOF["y"]); G = np.concatenate(OOF["g"]); IDX = np.concatenate(OOF["idx"])
YV = np.concatenate(VAL["y"])
R = {"n_requests": int(n), "n_sessions": int(len(set(sess))), "protocol": "5-fold StratifiedGroupKFold by session (random_state 42); inner 4-fold split for validation (random_state 200+k); windows rebuilt within train/validation/test streams", "policy_v6": V6}
P = {k: np.concatenate(v) for k, v in mp.items()}
PV = {k: np.concatenate(v) for k, v in mpv.items()}
R["model_comparison"] = {k: {"val_macroF1": round(float(f1_score(YV, PV[k], average="macro")), 4), **clf_summary(Y, P[k], G)} for k in MODELS}
tabs = {k: S.session_tables(Y, P[k], G, LAB) for k in MODELS}
bo, dr = S.boot(tabs)
R["model_ci"] = bo
R["catboost_vs_rf"] = {m: S.paired_diff(dr, "CatBoost", "Random Forest", m) for m in ["macroF1", "fpr", "attack_recall"]}
c1 = (P["CatBoost"] == Y); c2 = (P["Random Forest"] == Y)
b01 = int((c1 & ~c2).sum()); b10 = int((~c1 & c2).sum())
R["mcnemar_catboost_rf"] = {"only_catboost_correct": b01, "only_rf_correct": b10, "chi2": round((abs(b01 - b10) - 1) ** 2 / max(b01 + b10, 1), 3), "p": float(chi2.sf((abs(b01 - b10) - 1) ** 2 / max(b01 + b10, 1), 1))}
R["confusion_catboost"] = {"labels": LAB, "matrix": confusion_matrix(Y, P["CatBoost"], labels=LAB).tolist()}
R["cost"] = cost
VP = {k: np.concatenate(v) for k, v in vp.items()}
R["feature_view_ablation"] = {k: clf_summary(Y, VP[k], G) for k in views}
vt = {k: S.session_tables(Y, VP[k], G, LAB) for k in views}
vb, vd = S.boot(vt)
R["feature_view_ci"] = vb
R["view_diff_both_minus_behavioural"] = {m: S.paired_diff(vd, "both", "behavioural_only", m) for m in ["macroF1", "fpr", "attack_recall"]}
R["view_diff_both_minus_payload"] = {m: S.paired_diff(vd, "both", "payload_only", m) for m in ["macroF1", "fpr", "attack_recall"]}
ug = np.unique(G)
acc_full = np.array([(VP["both"][G == s] == Y[G == s]).mean() for s in ug])
acc_beh = np.array([(VP["behavioural_only"][G == s] == Y[G == s]).mean() for s in ug])
nz = acc_full != acc_beh
R["session_level_test"] = {"n_sessions": int(len(ug)), "n_sessions_differing": int(nz.sum()), "mean_acc_full": round(float(acc_full.mean()), 4), "mean_acc_behavioural": round(float(acc_beh.mean()), 4),
                           "wilcoxon_p": float(wilcoxon(acc_full[nz], acc_beh[nz]).pvalue) if nz.sum() > 0 else None}
RB = np.concatenate(rbase)
R["threshold_rules_baseline"] = clf_summary(Y, RB, G)
R["enforcement"] = {}
A = {k: np.concatenate(v) for k, v in acts.items()}
for k, aa in A.items():
    R["enforcement"][k] = enf_summary(Y, aa, G)
A1 = np.concatenate(actv1)
R["enforcement"]["original_gateway_policy"] = enf_summary(Y, A1, G)
base = A["classifier_stage"]
ben = Y == "normal"
R["rules"] = {}
for r_, fl in rules_fire.items():
    fl = np.concatenate(fl)
    R["rules"][r_] = {"fires": int(fl.sum()), "fires_on_benign": int((fl & ben).sum()), "new_benign_flags": int((fl & ben & (base == "ALLOW")).sum()),
                      "attacks_recovered": int((fl & ~ben & (base == "ALLOW")).sum()), "precision": round(float((fl & ~ben).sum() / max(fl.sum(), 1)), 4)}
fl_drop = (base != "ALLOW") & (A["+flood_floor_throttle"] == "ALLOW")
R["rules"]["flood_floor_effect"] = {"benign_released": int((fl_drop & ben).sum()), "attacks_released": int((fl_drop & ~ben).sum())}
SV = merge_sweeps(swv); ST = merge_sweeps(swt)
R["sweeps"] = {"validation": SV, "test": ST}
ep = []
A6 = A["+rate_limiter_v6"]
order = np.lexsort((ts_all[IDX], G))
df = pd.DataFrame({"g": G[order], "y": Y[order], "a": A6[order], "t": ts_all[IDX][order]})
df = df[df.y != "normal"]
for (g, c), grp in df.groupby(["g", "y"], sort=False):
    e = (grp.a != "ALLOW").to_numpy()
    first = int(np.argmax(e)) if e.any() else None
    ep.append({"attack": c, "n": len(grp), "detected": bool(e.any()), "first_blocked": bool(e[0]), "passed_before_first": first,
               "time_to_first": float(grp.t.to_numpy()[first] - grp.t.to_numpy()[0]) if first is not None else None, "enf_rate": float(e.mean())})
E = pd.DataFrame(ep)
R["event_level_offline_v6"] = {c: {"episodes": int(len(x)), "episode_detection": round(float(x.detected.mean()), 3), "request_enforcement": round(float(x.enf_rate.mean()), 3),
                                   "first_request_enforced": round(float(x.first_blocked.mean()), 3),
                                   "median_requests_before_first": float(x.passed_before_first.dropna().median()) if x.detected.any() else None,
                                   "median_seconds_to_first": round(float(x.time_to_first.dropna().median()), 3) if x.detected.any() else None} for c, x in E.groupby("attack")}
np.savez_compressed("out/e10_oof.npz", y=Y, g=G, idx=IDX, risk=np.concatenate(risk_oof), **{"pred_" + k.replace(" ", "_").replace("(", "").replace(")", "").replace("=", ""): v for k, v in P.items()}, **{"view_" + k: v for k, v in VP.items()}, **{"act_" + k.replace("+", "plus_"): v for k, v in A.items()}, act_original=A1, rule_baseline=RB)
json.dump(R, open("out/e10_final.json", "w"), indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))
print(json.dumps({k: R[k] for k in ["model_comparison"]}, default=str)[:3000])
print("done")
