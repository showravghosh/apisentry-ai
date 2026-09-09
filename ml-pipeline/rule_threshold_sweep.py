"""Rule-threshold sensitivity: validation-select -> freeze -> test (reviewer item 3).
Sweeps the SQL signature (body_sql_hits >= h) and token-replay signature
(token_ips_10s >= t) on a VALIDATION split, selects by a predefined
high-precision criterion, then reports the untouched TEST split once.
Reuses the exact test split from train.py (test_size=0.2, random_state=42).
Reads data only; does not retrain or modify anything."""
import json, pandas as pd
from sklearn.model_selection import train_test_split

DATA = "ml-pipeline/processed/dataset_processed.csv"
EPS  = 0.005          # predefined criterion: pick smallest threshold with val FPR <= EPS

df = pd.read_csv(DATA)
print("labels present:", sorted(df["label"].unique().tolist()))
print("total rows:", len(df))

y = df["label"]
# 1) reproduce the paper's test set exactly
dev, test = train_test_split(df, test_size=0.2, random_state=42, stratify=y)
# 2) carve a validation set from the dev portion (-> 60/20/20 train/val/test)
_, val = train_test_split(dev, test_size=0.25, random_state=42, stratify=dev["label"])

def norm_mask(d):   # benign rows
    return d["label"] == "normal"

print(f"\nval size={len(val)}  val benign={int(norm_mask(val).sum())}  "
      f"test size={len(test)}  test benign={int(norm_mask(test).sum())}")

def sweep(feature, thresholds, target_substr):
    def stats(d, thr):
        fires = d[feature] >= thr
        benign = norm_mask(d)
        target = d["label"].str.contains(target_substr, case=False)
        fpr = (fires & benign).sum() / max(benign.sum(), 1)          # benign wrongly flagged
        recall = (fires & target).sum() / max(target.sum(), 1)       # target attacks caught
        prec = (fires & ~benign).sum() / max(fires.sum(), 1)         # of fires, fraction attack
        return recall, fpr, prec
    print(f"\n=== {feature}  (target: '{target_substr}') ===")
    print(f"{'thr':>4} | {'val_rec':>7} {'val_fpr':>7} {'val_prec':>8} | {'test_rec':>8} {'test_fpr':>8} {'test_prec':>9}")
    selected = None
    for thr in thresholds:
        vr, vf, vp = stats(val, thr)
        tr, tf, tp = stats(test, thr)
        mark = ""
        if selected is None and vf <= EPS:
            selected = thr; mark = "  <-- selected (smallest thr with val_fpr<=%.3f)" % EPS
        print(f"{thr:>4} | {vr:>7.3f} {vf:>7.3f} {vp:>8.3f} | {tr:>8.3f} {tf:>8.3f} {tp:>9.3f}{mark}")
    print(f"SELECTED {feature} threshold = {selected} (current paper value shown for compare)")
    return selected

sel_h = sweep("body_sql_hits", [1,2,3,4,5], "sql")
sel_t = sweep("token_ips_10s", [2,3,4,5,6], "replay|token")

print("\n--- summary ---")
print(f"SQL signature  : validation-selected h = {sel_h}   (paper a priori = 3)")
print(f"Token signature: validation-selected t = {sel_t}   (paper a priori = 5)")
print("Criterion: smallest threshold whose validation benign FPR <= %.3f" % EPS)
