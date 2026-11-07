import sys, json
sys.path.insert(0, ".")
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score
import features as F
import common as C

raw = F.load_raw()
static = F.static_features(raw, "gateway")
y = raw["label"].to_numpy(dtype=object)
n = len(raw)
sess = raw["session_id"].astype(str).to_numpy()
folds = list(StratifiedGroupKFold(5, shuffle=True, random_state=42).split(np.zeros(n), y, sess))
SETS0 = {
    "F19_with_hour": F.GW + ["hour"],
    "F18_no_hour": F.GW,
    "F16_no_hour_no_size": [c for c in F.GW if c not in ("body_len", "request_size")],
    "F15_no_hour_no_size_no_endpoint": [c for c in F.GW if c not in ("body_len", "request_size", "endpoint_norm_enc")],
    "F19_robust_acct": [c for c in F.GW if c not in ("body_len", "request_size")] + ["glob_login_fail_10s", "glob_login_users_10s", "acct_fail_60s"],
}
SETS = {k: v for k, v in SETS0.items() if k in sys.argv[1:]} if len(sys.argv) > 1 else SETS0
R = {}
oof = {k: np.empty(n, dtype=object) for k in SETS}
for tr, te in folds:
    tem = np.zeros(n, bool); tem[te] = True
    w = F.window_features(static, key="ip", stream=tem.astype(int), strict=True)
    w = F.account_features(w, stream=tem.astype(int))
    d, _ = F.encode(w); d[F.NUM + ["hour"] + F.ACCT] = d[F.NUM + ["hour"] + F.ACCT].fillna(0)
    for k, cols in SETS.items():
        m = C.cb().fit(d.loc[~tem, cols], y[~tem])
        oof[k][te] = C.predict(m, d.loc[tem, cols])[0]
for k in SETS:
    R[k] = {kk: round(v, 4) for kk, v in C.metrics(y, oof[k]).items()}
    R[k]["per_class_f1"] = {c: round(float(f1_score(y == c, oof[k] == c)), 3) for c in F.LABELS}
    print(k, R[k], flush=True)
json.dump(R, open("out/e6_shortcut_%s.json" % ("all" if len(sys.argv) == 1 else "_".join(sys.argv[1:])), "w"), indent=2)
