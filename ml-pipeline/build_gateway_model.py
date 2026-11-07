import os
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
import features as F
import common as C

OUT = os.getenv("APISENTRY_ART_OUT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "gateway", "artifacts"))
os.makedirs(OUT, exist_ok=True)
raw = F.load_raw()
d = F.build(raw, "gateway", key="default", strict=True)
y = d["label"].to_numpy(dtype=object)
methods = sorted(d["method"].astype(str).unique())
endpoints = sorted(d["endpoint_norm"].astype(str).unique())
sc = StandardScaler().fit(d[F.NUM].to_numpy(dtype=float))
X = np.hstack([sc.transform(d[F.NUM].to_numpy(dtype=float)), d[F.CAT].to_numpy(dtype=float)])
m = C.cb().fit(X, y)
m.save_model(os.path.join(OUT, "model.cbm"))
joblib.dump(sc, os.path.join(OUT, "scaler.pkl"))
json.dump({"method": methods, "endpoint_norm": endpoints}, open(os.path.join(OUT, "encoders.json"), "w"), indent=2)
json.dump({"source_key": F.KEY, "num_cols": F.NUM, "cat_cols": ["method", "endpoint_norm"], "feature_cols": F.GW, "labels": sorted(m.classes_.tolist())},
          open(os.path.join(OUT, "feature_columns.json"), "w"), indent=2)
print("rows", len(d), "classes", sorted(m.classes_.tolist()))
print("saved", OUT)
