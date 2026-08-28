"""
ablation.py — APIShield ablation study (feature-view contribution), 5-fold cross-validated.

Shows that the causal behavioural features are what let APIShield detect the behavioural
API attacks (BOLA, token replay, flooding, brute force, credential stuffing) that payload
features alone cannot. Uses the exact feature set of the deployed gateway model, and reports
every value as a 5-fold cross-validation mean +/- standard deviation (robust, not a single split).

Run from the repository root (~/apishield-ai) with the ml-pipeline virtual environment:
    ml-pipeline/venv/bin/python ml-pipeline/ablation.py

Outputs (in ml-pipeline/results/):
    ablation_results.csv        - macro-F1 / accuracy / FPR (mean +/- std) for the three configurations
    ablation_per_attack.csv     - per-attack F1 (mean +/- std): payload-only vs full model
    ablation.png                - configuration comparison with error bars
    ablation_per_attack.png     - per-attack F1 improvement with error bars
"""

import json
import warnings
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from catboost import CatBoostClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, accuracy_score

DATA = "ml-pipeline/processed/dataset_processed.csv"
GWCFG = "gateway/artifacts/feature_columns.json"
OUT = "ml-pipeline/results"

df = pd.read_csv(DATA)
gw_num = json.load(open(GWCFG))["num_cols"]                  # exact deployed numeric features
all_features = gw_num + ["method_enc", "endpoint_norm_enc"]  # + deployed categoricals
behavioural = [c for c in gw_num if c.startswith("ip_") or c.startswith("token_")]
payload = [c for c in all_features if c not in behavioural]

y = df["label"].astype(str).to_numpy(dtype=object)
labels = sorted(pd.unique(y))

configs = [
    ("Payload features only", payload),
    ("Behavioural features only", behavioural),
    ("Payload + behavioural (full APIShield)", all_features),
]
PAY, FULL = "Payload features only", "Payload + behavioural (full APIShield)"

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cfg = {n: {"f1": [], "acc": [], "fpr": []} for n, _ in configs}
per = {PAY: {c: [] for c in labels}, FULL: {c: [] for c in labels}}

for tr, te in skf.split(np.arange(len(df)), y):
    y_tr, y_te = y[tr], y[te]
    for name, cols in configs:
        m = CatBoostClassifier(iterations=300, depth=8, verbose=0, random_state=42)
        m.fit(df.iloc[tr][cols], y_tr)
        p = m.predict(df.iloc[te][cols]).ravel()
        cfg[name]["f1"].append(f1_score(y_te, p, average="macro"))
        cfg[name]["acc"].append(accuracy_score(y_te, p))
        mask = y_te == "normal"
        cfg[name]["fpr"].append(float((p[mask] != "normal").mean()))
        if name in per:
            for c in labels:
                per[name][c].append(f1_score((y_te == c).astype(int), (p == c).astype(int), zero_division=0))


def ms(v):
    return round(float(np.mean(v)), 4), round(float(np.std(v)), 4)


# configuration table
rows = []
for name, _ in configs:
    f1m, f1s = ms(cfg[name]["f1"]); am, a_s = ms(cfg[name]["acc"]); fm, fs = ms(cfg[name]["fpr"])
    rows.append({"Configuration": name, "Macro-F1": f1m, "Macro-F1_std": f1s,
                 "Accuracy": am, "Accuracy_std": a_s, "FPR": fm, "FPR_std": fs})
res = pd.DataFrame(rows)
print(res.to_string(index=False))
res.to_csv(f"{OUT}/ablation_results.csv", index=False)

# per-attack table
prows = []
for c in labels:
    am, a_s = ms(per[PAY][c]); fm, fs = ms(per[FULL][c])
    prows.append({"class": c, "payload_only_F1": am, "payload_only_std": a_s,
                  "full_F1": fm, "full_std": fs})
per_df = pd.DataFrame(prows)
print("\nPer-attack F1 (5-fold mean +/- std):")
print(per_df.to_string(index=False))
per_df.to_csv(f"{OUT}/ablation_per_attack.csv", index=False)

# chart 1: configuration comparison (with error bars)
plt.figure(figsize=(9, 4.6))
x = np.arange(len(res)); w = 0.38
plt.bar(x - w / 2, res["Macro-F1"], w, yerr=res["Macro-F1_std"], capsize=4, label="Macro-F1", color="#2e7d32")
plt.bar(x + w / 2, res["FPR"], w, yerr=res["FPR_std"], capsize=4, label="FPR (normal)", color="#c62828")
plt.xticks(x, res["Configuration"], rotation=12, ha="right", fontsize=9)
plt.ylim(0, 1.05); plt.ylabel("score (5-fold mean)"); plt.legend()
plt.title("APIShield ablation: contribution of feature views", fontweight="bold")
for i, v in enumerate(res["Macro-F1"]):
    plt.text(i - w / 2, v + 0.03, f"{v:.2f}", ha="center", fontsize=8, fontweight="bold")
plt.tight_layout(); plt.savefig(f"{OUT}/ablation.png", dpi=150)

# chart 2: per-attack improvement (with error bars)
plt.figure(figsize=(10, 4.6))
x = np.arange(len(per_df)); w = 0.38
plt.bar(x - w / 2, per_df["payload_only_F1"], w, yerr=per_df["payload_only_std"], capsize=3,
        label="Payload features only", color="#ef9a9a")
plt.bar(x + w / 2, per_df["full_F1"], w, yerr=per_df["full_std"], capsize=3,
        label="Payload + behavioural", color="#1565c0")
plt.xticks(x, per_df["class"], rotation=25, ha="right", fontsize=9)
plt.ylim(0, 1.1); plt.ylabel("F1-score (5-fold mean)"); plt.legend()
plt.title("Behavioural features recover behavioural-attack detection", fontweight="bold")
plt.tight_layout(); plt.savefig(f"{OUT}/ablation_per_attack.png", dpi=150)

print(f"\nSaved to {OUT}/: ablation_results.csv, ablation_per_attack.csv, ablation.png, ablation_per_attack.png")
print("\nNote: signature rules and behavioural guards are runtime robustness / false-positive")
print("control mechanisms (evaluated in the adversarial and live tests), not offline gains.")
