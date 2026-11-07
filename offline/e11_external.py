import sys, re, json
sys.path.insert(0, ".")
import numpy as np
import pandas as pd
from urllib.parse import unquote_plus
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import f1_score, roc_auc_score, accuracy_score, precision_score, recall_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from catboost import CatBoostClassifier
import features as F

EXT = sys.argv[1]


def parse_csic(path, label):
    rows = []; method = url = None; hdr = True; body = []

    def flush():
        if method is not None:
            rows.append((method, url, " ".join(body), label))
    for line in open(path, errors="ignore"):
        line = line.rstrip("\n")
        m = re.match(r"^(GET|POST|PUT|DELETE)\s+(\S+)", line)
        if m:
            flush(); method, url = m.group(1), m.group(2); hdr = True; body = []; continue
        if method is not None:
            if hdr:
                if line.strip() == "":
                    hdr = False
            elif line.strip():
                body.append(line)
    flush()
    return rows


def parse_ecml(path):
    recs = []; cls = method = uri = None; buf = []; inh = False

    def flush():
        if method is not None:
            recs.append((cls, method, uri, "\n".join(buf)))
    for line in open(path, errors="ignore"):
        line = line.rstrip("\n")
        mc = re.match(r"^class:\s*(\S+)", line)
        if mc:
            flush(); cls = mc.group(1); method = uri = None; buf = []; inh = False; continue
        mr = re.match(r"^(GET|POST|PUT|DELETE|HEAD)\s+(\S+)", line)
        if mr and method is None:
            method = mr.group(1); uri = mr.group(2); inh = True; buf = []; continue
        if method is not None:
            if inh:
                if line.strip() == "":
                    inh = False
            elif not re.match(r"^(Start|End)\s*-\s*Id", line):
                buf.append(line)
    flush()
    return recs


def gw_payload(df, text_col):
    p = np.array([F.payload_features(t, "gateway") for t in df[text_col]], dtype=float)
    q = np.array([F.numeric_features(t) for t in df[text_col]], dtype=float)
    X = pd.DataFrame({"body_special": p[:, 1], "body_sql_hits": p[:, 2], "body_max_num": q[:, 0], "body_min_num": q[:, 1], "body_has_neg": q[:, 2], "body_field_count": q[:, 3],
                      "method_enc": df["method"].map({"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "HEAD": 4}).fillna(5).to_numpy()})
    return X


def split(y, seed=42):
    idx = np.arange(len(y))
    tr, tmp = train_test_split(idx, test_size=0.4, random_state=seed, stratify=y)
    va, te = train_test_split(tmp, test_size=0.5, random_state=seed, stratify=y[tmp])
    return tr, va, te


def boot_ci(fn, yt, yp, n=1000, seed=0):
    rng = np.random.default_rng(seed)
    v = []
    for _ in range(n):
        i = rng.integers(0, len(yt), len(yt))
        v.append(fn(yt[i], yp[i]))
    return [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]


R = {}
rows = parse_csic(EXT + "/csic/normalTrafficTraining.txt", 0) + parse_csic(EXT + "/csic/anomalousTrafficTest.txt", 1)
df = pd.DataFrame(rows, columns=["method", "url", "body", "label"])
df["query"] = df["url"].str.split(r"\?", n=1).str[1].fillna("")
df["path"] = df["url"].str.replace(r"^https?://[^/]+", "", regex=True).str.split("?").str[0]
df["text"] = df["body"] + " " + df["query"]
df["text_full"] = df["body"] + " " + df["path"] + " " + df["query"]
y = df["label"].to_numpy()
tr, va, te = split(y)
R["csic"] = {"n": int(len(df)), "n_attack": int(y.sum()), "split": [len(tr), len(va), len(te)]}
X = gw_payload(df, "text")
m = CatBoostClassifier(iterations=400, depth=8, verbose=0, random_state=42).fit(X.iloc[tr], y[tr])
pv = m.predict_proba(X.iloc[va])[:, 1]; pt = m.predict_proba(X.iloc[te])[:, 1]
yp = (pt >= 0.5).astype(int)
R["csic"]["gateway_payload_features_catboost"] = {"val_F1": round(float(f1_score(y[va], (pv >= 0.5).astype(int))), 4), "test_F1": round(float(f1_score(y[te], yp)), 4),
                                                  "test_F1_ci95": boot_ci(lambda a, b: f1_score(a, b), y[te], yp), "test_acc": round(float(accuracy_score(y[te], yp)), 4),
                                                  "test_prec": round(float(precision_score(y[te], yp)), 4), "test_rec": round(float(recall_score(y[te], yp)), 4),
                                                  "test_fpr": round(float((yp[y[te] == 0] == 1).mean()), 4), "test_AUC": round(float(roc_auc_score(y[te], pt)), 4)}
sh = (X["body_sql_hits"].to_numpy() >= 3).astype(int)
R["csic"]["sql_rule_only_h3"] = {"fires_on_normal_rate": round(float(sh[y == 0].mean()), 4), "fires_on_attack_rate": round(float(sh[y == 1].mean()), 4)}
X2 = gw_payload(df, "text_full")
m2 = CatBoostClassifier(iterations=400, depth=8, verbose=0, random_state=42).fit(X2.iloc[tr], y[tr])
pt2 = m2.predict_proba(X2.iloc[te])[:, 1]; yp2 = (pt2 >= 0.5).astype(int)
R["csic"]["gateway_payload_features_catboost_with_path"] = {"test_F1": round(float(f1_score(y[te], yp2)), 4), "test_AUC": round(float(roc_auc_score(y[te], pt2)), 4), "test_acc": round(float(accuracy_score(y[te], yp2)), 4)}
txt = (df["body"] + " " + df["path"] + " " + df["query"]).map(lambda s: F.normalize_payload(s)).to_numpy()
vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(1, 4), max_features=8000, sublinear_tf=True)
Xt = vec.fit_transform(txt[tr]); Xte = vec.transform(txt[te]); Xva = vec.transform(txt[va])
lr = LogisticRegression(max_iter=2000, C=10, class_weight="balanced").fit(Xt, y[tr])
pt3 = lr.predict_proba(Xte)[:, 1]; yp3 = (pt3 >= 0.5).astype(int)
R["csic"]["reference_char_tfidf_logreg"] = {"val_F1": round(float(f1_score(y[va], lr.predict(Xva))), 4), "test_F1": round(float(f1_score(y[te], yp3)), 4),
                                            "test_F1_ci95": boot_ci(lambda a, b: f1_score(a, b), y[te], yp3), "test_acc": round(float(accuracy_score(y[te], yp3)), 4),
                                            "test_AUC": round(float(roc_auc_score(y[te], pt3)), 4), "note": "vectoriser fitted on the training partition only"}
cv = []
for k, (a, b) in enumerate(StratifiedKFold(5, shuffle=True, random_state=42).split(X, y)):
    mm = CatBoostClassifier(iterations=400, depth=8, verbose=0, random_state=42).fit(X.iloc[a], y[a])
    cv.append(f1_score(y[b], mm.predict(X.iloc[b]).astype(int)))
R["csic"]["gateway_payload_features_cv5_F1"] = {"mean": round(float(np.mean(cv)), 4), "std": round(float(np.std(cv)), 4)}
print(json.dumps(R["csic"], indent=1), flush=True)

er = parse_ecml(EXT + "/wad/OriginalDataSets/ecml_pkdd/dataset_ecml_pkdd_train_test/xml_test.txt") + parse_ecml(EXT + "/wad/OriginalDataSets/ecml_pkdd/dataset_ecml_pkdd_train_test/xml_train.txt")
ed = pd.DataFrame(er, columns=["attack", "method", "uri", "body"])
ed["query"] = ed["uri"].str.split(r"\?", n=1).str[1].fillna("")
ed["text"] = ed["body"] + " " + ed["query"]
ye = ed["attack"].to_numpy(dtype=object)
tr, va, te = split(ye)
R["ecml"] = {"n": int(len(ed)), "classes": {k: int(v) for k, v in ed["attack"].value_counts().items()}, "split": [len(tr), len(va), len(te)]}
Xe = gw_payload(ed, "text")
me = CatBoostClassifier(iterations=400, depth=8, verbose=0, random_state=42).fit(Xe.iloc[tr], ye[tr])
pe = np.asarray(me.predict(Xe.iloc[te])).ravel().astype(object)
R["ecml"]["gateway_payload_features_catboost"] = {"val_macroF1": round(float(f1_score(ye[va], np.asarray(me.predict(Xe.iloc[va])).ravel().astype(object), average="macro")), 4),
                                                  "test_macroF1": round(float(f1_score(ye[te], pe, average="macro")), 4),
                                                  "test_macroF1_ci95": boot_ci(lambda a, b: f1_score(a, b, average="macro"), ye[te], pe), "test_acc": round(float(accuracy_score(ye[te], pe)), 4),
                                                  "per_class_f1": {c: round(float(v), 3) for c, v in zip(sorted(set(ye)), f1_score(ye[te], pe, average=None, labels=sorted(set(ye))))}}
txe = (ed["body"] + " " + ed["uri"]).map(lambda s: F.normalize_payload(s)).to_numpy()
vec2 = TfidfVectorizer(analyzer="char_wb", ngram_range=(1, 4), max_features=8000, sublinear_tf=True)
A = vec2.fit_transform(txe[tr]); B = vec2.transform(txe[te])
lr2 = LogisticRegression(max_iter=3000, C=10, class_weight="balanced").fit(A, ye[tr])
pe2 = lr2.predict(B)
R["ecml"]["reference_char_tfidf_logreg"] = {"test_macroF1": round(float(f1_score(ye[te], pe2, average="macro")), 4), "test_macroF1_ci95": boot_ci(lambda a, b: f1_score(a, b, average="macro"), ye[te], pe2),
                                            "test_acc": round(float(accuracy_score(ye[te], pe2)), 4), "note": "vectoriser fitted on the training partition only"}
print(json.dumps(R["ecml"], indent=1), flush=True)
json.dump(R, open("out/e11_external.json", "w"), indent=2)
print("done")
