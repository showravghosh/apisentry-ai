import sys
import pandas as pd

PH = ["sql_injection", "parameter_tampering", "bola", "brute_force", "credential_stuffing", "api_flooding", "token_replay", "benign"]


def phases(path, seeds=5, offset=0):
    d = pd.read_csv(path)
    rs = d.index[d.endpoint.astype(str).str.contains("ratelimit/reset")].tolist()
    out = []
    for s in range(seeds):
        for k, p in enumerate(PH):
            i = offset + s * len(PH) + k
            st = rs[i] + 1
            en = rs[i + 1] if i + 1 < len(rs) else len(d)
            seg = d.iloc[st:en]
            out.append((s, p, seg.decision.tolist()))
    return out


def summary(path, offset=0):
    rows = []
    for s, p, dec in phases(path, offset=offset):
        if p == "benign":
            continue
        enf = [x != "ALLOW" for x in dec]
        first = enf.index(True) if any(enf) else None
        after = sum(enf[first:]) / len(enf[first:]) if first is not None else 0.0
        rows.append({"attack": p, "seed": s, "detected": first is not None, "passed_before_first": first, "enforced_after_first": after, "n": len(dec)})
    r = pd.DataFrame(rows)
    return r.groupby("attack").agg(episodes=("detected", "size"), detected=("detected", "sum"), median_passed=("passed_before_first", "median"), max_passed=("passed_before_first", "max"), after_first=("enforced_after_first", "mean"))


if __name__ == "__main__":
    print(summary(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0).round(3).to_string())
