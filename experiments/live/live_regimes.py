import os
import sys
import json
import time
import random
import requests

API = os.getenv("APISENTRY_API", "http://127.0.0.1:8000")
GW = os.getenv("APISENTRY_GW", "http://127.0.0.1:9000")
BLOCK = {403, 429}
SEEDS = [int(x) for x in os.getenv("REGIME_SEEDS", "1001,1002,1003,1004,1005").split(",")]
S = requests.Session()


def reset():
    S.post(GW + "/__apisentry/reset", timeout=5)


def token(user):
    r = S.post(API + "/login", json={"username": user, "password": "password123" if user != "admin" else "admin123"}, timeout=5)
    return r.json().get("access_token")


def send(method, path, ip, tok=None, js=None):
    h = {"X-Forwarded-For": ip}
    if tok:
        h["Authorization"] = "Bearer " + tok
    try:
        return S.request(method, GW + path, headers=h, json=js, timeout=10).status_code
    except Exception:
        return None


def rip(rng, a=45):
    return "%d.%d.%d.%d" % (a, rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254))


def atk_brute(rng, rotate):
    return [send("POST", "/login", rip(rng) if rotate else "203.0.113.50", js={"username": "admin", "password": "wrong%d" % rng.randint(0, 99999)}) for _ in range(25)]


def atk_stuffing(rng, rotate):
    return [send("POST", "/login", rip(rng) if rotate else "203.0.113.51", js={"username": "user%d" % rng.randint(4, 60), "password": "Pass%d!" % rng.randint(0, 9999)}) for _ in range(25)]


def atk_flood(rng, rotate):
    return [send("GET", "/products", rip(rng) if rotate else "203.0.113.52") for _ in range(50)]


def legit_browse(rng, ips, n=50, pause=0.1):
    out = []
    for _ in range(n):
        out.append(send("GET", rng.choice(["/products", "/products/%d" % rng.randint(1, 4), "/search?q=" + rng.choice(["laptop", "phone", "o'brien mug"])]), rng.choice(ips)))
        time.sleep(pause * rng.uniform(0.5, 1.5))
    return out


def legit_mobile(rng, tok):
    ips = [rip(rng, 100), rip(rng, 101), rip(rng, 102), rip(rng, 103)]
    out = []
    for i in range(40):
        out.append(send("GET", rng.choice(["/products", "/cart", "/products/%d" % rng.randint(1, 4)]), ips[(i // 10) % len(ips)], tok))
        time.sleep(0.25 * rng.uniform(0.5, 1.5))
    return out


def legit_proxy_auth(rng, toks):
    ip = "198.51.100.77"
    out = []
    for i in range(60):
        u, t, uid = toks[i % len(toks)]
        out.append(send("GET", rng.choice(["/users/%d" % uid, "/cart", "/products"]), ip, t))
        time.sleep(0.1 * rng.uniform(0.5, 1.5))
    return out


def rate(c):
    v = [x for x in c if x is not None]
    return sum(1 for x in v if x in BLOCK), len(v), sum(1 for x in v if x == 403), sum(1 for x in v if x == 429)


def run_regime(fn, sd):
    reset()
    atk_codes, leg_codes = [], []
    g = random.Random(sd)
    atk_fn, leg_fn = fn
    atk_codes = atk_fn(g)
    reset()
    leg_codes = leg_fn(g)
    return rate(atk_codes), rate(leg_codes)


if __name__ == "__main__":
    tag = sys.argv[1]
    users = ["user%d" % i for i in range(4, 24)]
    toks = []
    for u in users:
        r = S.post(API + "/login", json={"username": u, "password": "password123"}, timeout=5).json()
        toks.append((u, r["access_token"], r["user_id"]))
    alice = token("alice")
    stable = ["203.0.%d.%d" % (100 + i // 254, i % 254 + 1) for i in range(50)]
    atk_stable = lambda g: atk_brute(g, False) + atk_stuffing(g, False) + atk_flood(g, False)
    atk_rot = lambda g: atk_brute(g, True) + atk_stuffing(g, True) + atk_flood(g, True)
    REG = {
        "baseline": (atk_stable, lambda g: legit_browse(g, stable)),
        "shared_nat": (atk_stable, lambda g: legit_browse(g, ["198.51.100.10", "198.51.100.11", "198.51.100.12"])),
        "address_rotation": (atk_rot, lambda g: legit_browse(g, stable)),
        "bursty_client": (atk_stable, lambda g: legit_browse(g, ["203.0.113.200"], n=30, pause=0.0)),
        "mobile_client": (atk_stable, lambda g: legit_mobile(g, alice)),
        "shared_proxy_authenticated": (atk_stable, lambda g: legit_proxy_auth(g, toks)),
    }
    res = {}
    for name, fn in REG.items():
        runs = [run_regime(fn, sd) for sd in SEEDS]
        ab = sum(r[0][0] for r in runs); at = sum(r[0][1] for r in runs)
        lb = sum(r[1][0] for r in runs); lt = sum(r[1][1] for r in runs)
        res[name] = {"attack_blocked": ab, "attack_total": at, "legit_blocked": lb, "legit_total": lt,
                     "legit_403": sum(r[1][2] for r in runs), "legit_429": sum(r[1][3] for r in runs),
                     "attack_403": sum(r[0][2] for r in runs), "attack_429": sum(r[0][3] for r in runs),
                     "per_run_detection": [round(r[0][0] / max(r[0][1], 1), 3) for r in runs],
                     "per_run_fpr": [round(r[1][0] / max(r[1][1], 1), 3) for r in runs]}
        print(tag, name, "detect %d/%d FPR %d/%d (403=%d 429=%d)" % (ab, at, lb, lt, res[name]["legit_403"], res[name]["legit_429"]), res[name]["per_run_detection"], res[name]["per_run_fpr"], flush=True)
    os.makedirs("results", exist_ok=True)
    json.dump(res, open("results/live_regimes_%s.json" % tag, "w"), indent=2)
