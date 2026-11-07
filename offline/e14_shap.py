import sys, json
sys.path.insert(0, ".")
import numpy as np
import joblib
import shap
from catboost import CatBoostClassifier
import features as F

ART = sys.argv[1]
raw = F.load_raw()
d = F.build(raw, "gateway", key="default", strict=True)
y = d["label"].to_numpy(dtype=object)
sc = joblib.load(ART + "/scaler.pkl")
X = np.hstack([sc.transform(d[F.NUM].to_numpy(dtype=float)), d[F.CAT].to_numpy(dtype=float)])
m = CatBoostClassifier(); m.load_model(ART + "/model.cbm")
cls = list(m.classes_)
names = F.NUM + F.CAT
rng = np.random.default_rng(0)
idx = np.concatenate([rng.choice(np.where(y == c)[0], min(300, (y == c).sum()), replace=False) for c in cls])
ex = shap.TreeExplainer(m)
sv = ex.shap_values(X[idx])
sv = np.asarray(sv)
if sv.ndim == 3 and sv.shape[0] == len(idx):
    sv = np.transpose(sv, (2, 0, 1))
out = {}
for k, c in enumerate(cls):
    rows = y[idx] == c
    v = np.abs(sv[k][rows]).mean(0)
    out[c] = {names[j]: round(float(v[j]), 4) for j in range(len(names))}
json.dump({"classes": cls, "features": names, "mean_abs_shap_own_class": out, "n_per_class": 300}, open("out/e14_shap.json", "w"), indent=2)
for c in cls:
    top = sorted(out[c].items(), key=lambda t: -t[1])[:4]
    print(c, top)
