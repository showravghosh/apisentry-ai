import os
import sys
import json
import time
import random
import requests

BLOCK = {403, 429}
S = requests.Session()


def send(base, method, path, ip, tok=None, js=None):
    h = {"X-Forwarded-For": ip}
    if tok:
        h["Authorization"] = "Bearer " + tok
    try:
        return S.request(method, base + path, json=js, headers=h, timeout=10)
    except Exception:
        return None


def run(base, seed, pfx, n_users=25):
    g = random.Random(seed)
    nat = ["100.64.%d.%d" % (seed % 200, i) for i in range(1, 3)]
    codes = []
    users = []
    for i in range(n_users):
        ip = g.choice(nat) if g.random() < 0.2 else "100.%d.%d.%d" % (65 + g.randint(0, 50), g.randint(0, 255), g.randint(1, 254))
        users.append(("u%s%d_%d" % (pfx, seed, i), "Pw%d!%d" % (seed, i), ip, "book_%s%d_%d" % (pfx, seed, i)))
    toks = {}
    for u, pw, ip, bk in users:
        r = send(base, "POST", "/users/v1/register", ip, js={"username": u, "password": pw, "email": u + "@example.org"})
        codes.append(r.status_code if r is not None else None)
        time.sleep(abs(g.gauss(0.3, 0.1)))
        if g.random() < 0.1:
            r = send(base, "POST", "/users/v1/login", ip, js={"username": u, "password": pw + "x"})
            codes.append(r.status_code if r is not None else None)
            time.sleep(abs(g.gauss(0.8, 0.2)))
        r = send(base, "POST", "/users/v1/login", ip, js={"username": u, "password": pw})
        codes.append(r.status_code if r is not None else None)
        try:
            toks[u] = r.json().get("auth_token")
        except Exception:
            toks[u] = None
        time.sleep(abs(g.gauss(0.3, 0.1)))
        r = send(base, "POST", "/books/v1", ip, toks[u], {"book_title": bk, "secret": "s" + str(g.randint(0, 9999))})
        codes.append(r.status_code if r is not None else None)
    for step in range(8):
        order = users[:]
        g.shuffle(order)
        for u, pw, ip, bk in order:
            path = g.choice(["/books/v1", "/books/v1/" + bk, "/me", "/users/v1/" + u, "/books/v1"])
            r = send(base, "GET", path, ip, toks[u])
            codes.append(r.status_code if r is not None else None)
            time.sleep(abs(g.gauss(0.15, 0.05)))
    return codes, [x[3] for x in users]


if __name__ == "__main__":
    targets = json.loads(os.getenv("VAMPI_TARGETS", '{"APISentry_v8": "http://127.0.0.1:9110"}'))
    seeds = [int(x) for x in os.getenv("VAMPI_SEEDS", "3001").split(",")]
    tag = sys.argv[1]
    res = {}
    titles = []
    for name, base in targets.items():
        runs = []
        for sd in seeds:
            for p in ("/__apisentry/reset", "/__ratelimit/reset"):
                try:
                    S.post(base + p, timeout=3)
                except Exception:
                    pass
            c, t = run(base, sd, "s%d" % len(res))
            titles += t
            v = [x for x in c if x is not None]
            runs.append({"n": len(v), "n403": sum(1 for x in v if x == 403), "n429": sum(1 for x in v if x == 429), "n_5xx": sum(1 for x in v if x >= 500)})
            print(tag, name, sd, runs[-1], flush=True)
        res[name] = {"runs": runs, "n": sum(r["n"] for r in runs), "n403": sum(r["n403"] for r in runs), "n429": sum(r["n429"] for r in runs)}
    os.makedirs("results", exist_ok=True)
    json.dump(res, open("results/vampi_benign_%s.json" % tag, "w"), indent=2)
    open("results/vampi_titles_%s.txt" % tag, "w").write("\n".join(titles) + "\n")
