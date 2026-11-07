import os
import sys
import json
import time
import math
import random
import requests
from urllib.parse import quote

API = os.getenv("APISENTRY_API", "http://127.0.0.1:8000")
TARGETS = json.loads(os.getenv("COVERAGE_TARGETS", '{"APISentry": "http://127.0.0.1:9000"}'))
BLOCK = {403, 429}
SEEDS = [int(x) for x in os.getenv("COVERAGE_SEEDS", "2001,2002,2003,2004,2005").split(",")]
S = requests.Session()


STICKY = os.getenv("COVERAGE_STICKY_AUTH", "1") == "1"
EXTRA_RESET = json.loads(os.getenv("COVERAGE_EXTRA_RESET", "[]"))


def reset(base):
    for b in [base] + EXTRA_RESET:
        for p in ("/__apisentry/reset", "/__ratelimit/reset"):
            try:
                S.post(b + p, timeout=3)
            except Exception:
                pass


def tok():
    return S.post(API + "/login", json={"username": "admin", "password": "admin123"}, timeout=5).json().get("access_token")


def send(base, method, path, ip, headers=None, js=None):
    h = {"X-Forwarded-For": ip}
    if headers:
        h.update(headers)
    try:
        return S.request(method, base + path, headers=h, json=js, timeout=10).status_code
    except Exception:
        return None


def rip(g):
    return "%d.%d.%d.%d" % (g.randint(11, 223), g.randint(0, 255), g.randint(0, 255), g.randint(1, 254))


SQL_BASIC = ["' OR '1'='1", "1' UNION SELECT username,password FROM users--", "'; DROP TABLE users;--", "admin'--", "1 OR 1=1"]
SQL_EXT = SQL_BASIC + ["%27%20OR%20%271%27%3D%271", "1'/**/UNION/**/SELECT/**/NULL--", "' oR 'a'='a", "1; SELECT SLEEP(5)--",
                       "' UNION ALL SELECT NULL,NULL,NULL#", "x' AND 1=CONVERT(int,@@version)--", "' || '1'='1", "1' ORDER BY 3--",
                       "admin' #", "%2527%2520OR%25201%253D1"]


def suite(g, t, base, ext):
    n = 50 if ext else 25
    atk_ip = rip(g)
    auth = {"Authorization": "Bearer " + t}
    out = {}
    pays = SQL_EXT if ext else SQL_BASIC
    out["sql_injection"] = [send(base, "GET", "/search?q=" + quote(pays[i % len(pays)]), atk_ip) for i in range(n)]
    reset(base)
    vals = [lambda: {"product_id": -g.randint(1, 99999), "quantity": -g.randint(1, 99999)}]
    if ext:
        vals += [lambda: {"product_id": 1, "quantity": g.choice([10 ** 9, -1, 0])}, lambda: {"product_id": 99999999, "quantity": 1},
                 lambda: {"product_id": 2, "quantity": 1, "unit_price": -5, "discount": 100}]
    out["parameter_tampering"] = [send(base, "POST", "/cart/add" if i % 2 == 0 or not ext else "/order", atk_ip, auth, g.choice(vals)()) for i in range(n)]
    reset(base)
    ids = list(range(1, 31))
    g.shuffle(ids)
    c = []
    for i in range(n):
        c.append(send(base, "GET", "/users/%d" % ids[i % len(ids)], atk_ip, auth))
        if ext and i % 2:
            time.sleep(0.3)
    out["bola"] = c
    reset(base)
    c = []
    for i in range(n):
        c.append(send(base, "POST", "/login", atk_ip, js={"username": "admin", "password": "wrong%d" % g.randint(0, 99999)}))
        if ext and i % 3 == 0:
            time.sleep(0.4)
    out["brute_force"] = c
    reset(base)
    out["credential_stuffing"] = [send(base, "POST", "/login", rip(g) if (ext and i % 2) else atk_ip, js={"username": "user%d" % g.randint(0, 9999), "password": "Pass%d!" % g.randint(0, 9999)}) for i in range(n)]
    reset(base)
    eps = ["/products"] + (["/search?q=phone", "/products/1", "/cart", "/"] if ext else [])
    out["api_flooding"] = [send(base, "GET", g.choice(eps), atk_ip) for _ in range(2 * n)]
    reset(base)
    out["token_replay"] = [send(base, "GET", g.choice(["/cart", "/products"]) if ext else "/cart", rip(g), auth) for _ in range(n)]
    reset(base)
    c = []
    clients = [rip(g) for _ in range(200 if ext else 50)]
    users = [("user%d" % i, None) for i in range(4, 14)]
    utok = {}
    for u, _ in users:
        r = S.post(API + "/login", json={"username": u, "password": "password123"}, timeout=5).json()
        utok[u] = (r["access_token"], r["user_id"])
    home = {u: g.choice(clients) for u in utok} if STICKY else {}
    for i in range(500 if ext else 50):
        ip = g.choice(clients)
        if ext and g.random() < 0.3:
            u = g.choice(list(utok))
            t2, uid = utok[u]
            c.append(send(base, "GET", g.choice(["/users/%d" % uid, "/cart", "/products"]), home.get(u, ip), {"Authorization": "Bearer " + t2}))
        else:
            c.append(send(base, "GET", g.choice(["/products", "/products/%d" % g.randint(1, 4), "/search?q=" + quote(g.choice(["laptop", "phone", "o'brien mug", "usb-c cable"]))]), ip))
        time.sleep(max(0, g.gauss(0.05 if ext else 0.1, 0.02)))
    out["benign"] = c
    return out


def wilson(k, n):
    if n == 0:
        return [None, None]
    z = 1.96
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h), 3), round(min(1, c + h), 3)]


if __name__ == "__main__":
    tag = sys.argv[1]
    ext = len(sys.argv) > 2 and sys.argv[2] == "extended"
    t = tok()
    res = {}
    for name, base in TARGETS.items():
        per = {}
        for sd in SEEDS:
            reset(base)
            out = suite(random.Random(sd), t, base, ext)
            for k, v in out.items():
                v = [x for x in v if x is not None]
                per.setdefault(k, []).append((sum(1 for x in v if x in BLOCK), len(v), sum(1 for x in v if x == 403), sum(1 for x in v if x == 429)))
        res[name] = {}
        for k, runs in per.items():
            kk = sum(r[0] for r in runs); nn = sum(r[1] for r in runs)
            res[name][k] = {"flagged": kk, "total": nn, "rate": round(kk / max(nn, 1), 3), "wilson95": wilson(kk, nn),
                            "per_run": [round(r[0] / max(r[1], 1), 3) for r in runs], "n403": sum(r[2] for r in runs), "n429": sum(r[3] for r in runs)}
            print(tag, "ext" if ext else "orig", name, k, "%d/%d" % (kk, nn), res[name][k]["wilson95"], res[name][k]["per_run"], "403=%d 429=%d" % (res[name][k]["n403"], res[name][k]["n429"]), flush=True)
    os.makedirs("results", exist_ok=True)
    json.dump(res, open("results/live_coverage_%s_%s.json" % (tag, "extended" if ext else "original"), "w"), indent=2)
