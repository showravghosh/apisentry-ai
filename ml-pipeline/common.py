import numpy as np
from catboost import CatBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_recall_fscore_support


def cb(seed=42):
    return CatBoostClassifier(iterations=400, depth=8, verbose=0, random_state=seed, thread_count=-1)


def split60(y, seed=42):
    idx = np.arange(len(y))
    tr, tmp = train_test_split(idx, test_size=0.4, random_state=seed, stratify=y)
    va, te = train_test_split(tmp, test_size=0.5, random_state=seed, stratify=y[tmp])
    return tr, va, te


def fpr(yt, yp):
    m = yt == "normal"
    return float((yp[m] != "normal").mean())


def det(yt, yp):
    m = yt != "normal"
    return float((yp[m] != "normal").mean())


def metrics(yt, yp):
    return {"macroF1": float(f1_score(yt, yp, average="macro")), "fpr": fpr(yt, yp), "attack_recall": det(yt, yp),
            "acc": float((yt == yp).mean())}


def predict(m, X):
    pr = m.predict_proba(X)
    cl = list(m.classes_)
    pred = np.array(cl, dtype=object)[pr.argmax(1)]
    risk = 1 - pr[:, cl.index("normal")]
    return pred, risk
