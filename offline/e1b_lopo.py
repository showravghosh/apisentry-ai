import sys, json
sys.path.insert(0, ".")
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
import features as F
import common as C
from sklearn.metrics import precision_recall_fscore_support
static = F.static_features(F.load_raw(), "gateway")


def feats(stream=None):
    w = F.window_features(static, key="ip", stream=stream, strict=True)
    w = F.account_features(w, stream=stream)
    e, _ = F.encode(w)
    e[F.ALLNUM] = e[F.ALLNUM].fillna(0)
    return e


def per_class(yt, yp):
    p, r, f, s = precision_recall_fscore_support(yt, yp, labels=F.LABELS, zero_division=0)
    return {c: {"prec": round(float(p[i]), 3), "rec": round(float(r[i]), 3), "f1": round(float(f[i]), 3), "n": int(s[i])} for i, c in enumerate(F.LABELS)}
raw = F.load_raw()
y = raw["label"].to_numpy(dtype=object)
ip = raw["ip_address"].astype(str).to_numpy()
u = raw["user_id"].to_numpy()
anon = np.isin(u, F.ANON)
ai = np.where(anon)[0]
af = np.full(len(raw), -1)
for f, (_, te) in enumerate(StratifiedGroupKFold(2, shuffle=True, random_state=42).split(ai, y[ai], ip[ai])):
    af[ai[te]] = f
rows = []
for k, test_user in enumerate(["alice", "bob"]):
    tem = (u == test_user) | (af == k)
    d = feats(np.where(tem, 1, 0))
    m = C.cb().fit(d.loc[~tem, F.GW], y[~tem])
    p, r = C.predict(m, d.loc[tem, F.GW])
    o = {"protocol": "leave_one_principal_out", "test_principal": test_user, "rebuild_within_partition": True,
         "n_test": int(tem.sum()), "pooled": {kk: round(v, 4) for kk, v in C.metrics(y[tem], p).items()}, "per_class": per_class(y[tem], p)}
    print(test_user, o["pooled"], {c: o["per_class"][c]["f1"] for c in F.LABELS}, flush=True)
    rows.append(o)
json.dump(rows, open("out/e1b_lopo.json", "w"), indent=2)
