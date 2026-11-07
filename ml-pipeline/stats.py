import numpy as np
LAB = None


def counts(yt, yp, labels):
    k = len(labels)
    idx = {c: i for i, c in enumerate(labels)}
    ti = np.array([idx[v] for v in yt])
    pi = np.array([idx[v] for v in yp])
    return ti, pi


def session_tables(yt, yp, groups, labels):
    ti, pi = counts(yt, yp, labels)
    ug, gi = np.unique(groups, return_inverse=True)
    S, K = len(ug), len(labels)
    tp = np.zeros((S, K)); fp = np.zeros((S, K)); fn = np.zeros((S, K))
    np.add.at(tp, (gi[ti == pi], ti[ti == pi]), 1)
    np.add.at(fp, (gi[ti != pi], pi[ti != pi]), 1)
    np.add.at(fn, (gi[ti != pi], ti[ti != pi]), 1)
    ni = labels.index("normal")
    ben = np.zeros(S); benfp = np.zeros(S); att = np.zeros(S); attdet = np.zeros(S)
    np.add.at(ben, gi[ti == ni], 1)
    np.add.at(benfp, gi[(ti == ni) & (pi != ni)], 1)
    np.add.at(att, gi[ti != ni], 1)
    np.add.at(attdet, gi[(ti != ni) & (pi != ni)], 1)
    return dict(tp=tp, fp=fp, fn=fn, ben=ben, benfp=benfp, att=att, attdet=attdet)


def from_tables(T, w):
    tp = (T["tp"] * w[:, None]).sum(0); fp = (T["fp"] * w[:, None]).sum(0); fn = (T["fn"] * w[:, None]).sum(0)
    den = 2 * tp + fp + fn
    present = (tp + fn) > 0
    f1 = np.where(den > 0, 2 * tp / np.maximum(den, 1e-12), 0)
    return {"macroF1": float(f1[present].mean()),
            "fpr": float((T["benfp"] * w).sum() / max((T["ben"] * w).sum(), 1e-12)),
            "attack_recall": float((T["attdet"] * w).sum() / max((T["att"] * w).sum(), 1e-12))}


def boot(tables, n_boot=2000, seed=0):
    names = list(tables)
    S = len(next(iter(tables.values()))["ben"])
    rng = np.random.default_rng(seed)
    point = {k: from_tables(T, np.ones(S)) for k, T in tables.items()}
    draws = {k: {m: [] for m in ["macroF1", "fpr", "attack_recall"]} for k in names}
    W = rng.multinomial(S, np.ones(S) / S, size=n_boot)
    for w in W:
        for k, T in tables.items():
            r = from_tables(T, w.astype(float))
            for m in r:
                draws[k][m].append(r[m])
    out = {}
    for k in names:
        out[k] = {}
        for m in ["macroF1", "fpr", "attack_recall"]:
            a = np.array(draws[k][m])
            out[k][m] = {"point": round(point[k][m], 4), "ci95": [round(float(np.percentile(a, 2.5)), 4), round(float(np.percentile(a, 97.5)), 4)]}
    return out, draws


def paired_diff(draws, a, b, metric="macroF1", point=None):
    d = np.array(draws[a][metric]) - np.array(draws[b][metric])
    return {"mean_diff": round(float(d.mean()), 4), "ci95": [round(float(np.percentile(d, 2.5)), 4), round(float(np.percentile(d, 97.5)), 4)],
            "p_two_sided": round(float(min(1.0, 2 * min((d <= 0).mean(), (d >= 0).mean()))), 4)}


def binary_tables(is_attack, flagged, groups):
    ug, gi = np.unique(groups, return_inverse=True)
    S = len(ug)
    ben = np.zeros(S); benf = np.zeros(S); att = np.zeros(S); attf = np.zeros(S)
    np.add.at(ben, gi[~is_attack], 1); np.add.at(benf, gi[~is_attack & flagged], 1)
    np.add.at(att, gi[is_attack], 1); np.add.at(attf, gi[is_attack & flagged], 1)
    return ben, benf, att, attf


def boot_binary(is_attack, flagged, groups, n_boot=2000, seed=0):
    ben, benf, att, attf = binary_tables(is_attack, flagged, groups)
    S = len(ben)
    rng = np.random.default_rng(seed)
    W = rng.multinomial(S, np.ones(S) / S, size=n_boot).astype(float)
    b = (W @ benf) / np.maximum(W @ ben, 1e-12)
    a = (W @ attf) / np.maximum(W @ att, 1e-12)
    return {"benign_flag_rate": {"point": round(float(benf.sum() / ben.sum()), 4), "ci95": [round(float(np.percentile(b, 2.5)), 4), round(float(np.percentile(b, 97.5)), 4)]},
            "attack_enforce_rate": {"point": round(float(attf.sum() / att.sum()), 4), "ci95": [round(float(np.percentile(a, 2.5)), 4), round(float(np.percentile(a, 97.5)), 4)]}}
