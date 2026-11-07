import os
import sys
import json
import time
import random
import requests
from urllib.parse import quote

API = os.getenv("APISENTRY_API", "http://127.0.0.1:8000")
TARGETS = json.loads(os.getenv("ADV_TARGETS", '{"APISentry": "http://127.0.0.1:9000"}'))
SEED = int(os.getenv("ADV_SEED", "7001"))
PACE = {k: float(v) for k, v in json.loads(os.getenv("ADV_PACE", '{"flood_medium": 0.3, "flood_slow": 1.2, "brute_slow": 4.0, "bola_slow": 2.0, "replay_slow": 3.0}')).items()}
BLOCK = {403, 429}
S = requests.Session()

SQL_STD = ["' OR 1=1--", "admin'--", "' UNION SELECT NULL,NULL--", "' OR 'x'='x", "'; DROP TABLE users--"]
SQL_EVA = ["' oR/**/1=1-- -", "'/**/UnIoN/**/SeLeCT/**/NULL--", "%2527 OR 1=1", "' || '1'='1", "' oR 1 like 1-- -",
           "%252527%252520OR%2525201%25253D1", "1'%09OR%09'1'='1", "' OR 2>1--", "1 AND SLEEP(5)", "'+OR+'a'='a",
           "') OR ('1'='1", "1' AND ASCII(SUBSTRING(@@version,1,1))>0--", "' OR TRUE--", "x'||(SELECT 1)||'", "%27%20oR%20%271"]
TAMPER_STD = [{"product_id": -3, "quantity": -2}, {"product_id": 1, "quantity": -1}, {"product_id": 2, "quantity": 1, "unit_price": 0}]
TAMPER_EVA = [{"product_id": 1, "quantity": "-5"}, {"product_id": 1, "quantity": 1000000000}, {"product_id": 1, "quantity": -0.5},
              {"product_id": 1, "quantity": 1, "item": {"quantity": -3}}, {"product_id": 99999999, "quantity": 1}, {"product_id": 1, "quantity": 1, "coupon": "FREE100"}]


def reset(base):
    for p in ("/__apisentry/reset", "/__ratelimit/reset"):
        try:
            S.post(base + p, timeout=3)
        except Exception:
            pass


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


def token(u, p):
    r = S.post(API + "/login", json={"username": u, "password": p}, timeout=5).json()
    return r.get("access_token")


def rate(c):
    v = [x for x in c if x is not None]
    return {"enforced": sum(1 for x in v if x in BLOCK), "n": len(v), "n403": sum(1 for x in v if x == 403), "n429": sum(1 for x in v if x == 429)}


def run(base, g):
    adm = token("admin", "admin123")
    auth = {"Authorization": "Bearer " + adm}
    out = {}
    reset(base); out["sqli_standard"] = rate([send(base, "GET", "/search?q=" + quote(p), rip(g)) for p in SQL_STD * 4])
    reset(base); out["sqli_evasive"] = rate([send(base, "GET", "/search?q=" + quote(p, safe="%"), rip(g)) for p in SQL_EVA])
    reset(base); out["tamper_standard"] = rate([send(base, "POST", "/cart/add", rip(g), auth, b) for b in TAMPER_STD * 4])
    reset(base); out["tamper_evasive"] = rate([send(base, "POST", "/cart/add", rip(g), auth, b) for b in TAMPER_EVA * 2])
    reset(base); ip = rip(g); out["flood_burst"] = rate([send(base, "GET", "/products", ip) for _ in range(40)])
    reset(base); ip = rip(g); c = []
    for _ in range(40):
        c.append(send(base, "GET", "/products", ip)); time.sleep(PACE["flood_medium"])
    out["flood_medium"] = rate(c)
    reset(base); ip = rip(g); c = []
    for _ in range(30):
        c.append(send(base, "GET", "/products", ip)); time.sleep(PACE["flood_slow"])
    out["flood_slow"] = rate(c)
    reset(base); ip = rip(g); out["brute_fast"] = rate([send(base, "POST", "/login", ip, js={"username": "admin", "password": "w%d" % g.randint(0, 99999)}) for _ in range(20)])
    reset(base); ip = rip(g); c = []
    for _ in range(20):
        c.append(send(base, "POST", "/login", ip, js={"username": "admin", "password": "w%d" % g.randint(0, 99999)})); time.sleep(PACE["brute_slow"])
    out["brute_slow"] = rate(c)
    reset(base); out["credstuff_distributed"] = rate([send(base, "POST", "/login", rip(g), js={"username": "user%d" % g.randint(0, 9999), "password": "P%d!" % g.randint(0, 9999)}) for _ in range(30)])
    reset(base); ip = rip(g); ids = list(range(1, 31)); g.shuffle(ids)
    out["bola_fast"] = rate([send(base, "GET", "/users/%d" % i, ip, auth) for i in ids[:20]])
    reset(base); ip = rip(g); g.shuffle(ids); c = []
    for i in ids[:20]:
        c.append(send(base, "GET", "/users/%d" % i, ip, auth)); time.sleep(PACE["bola_slow"])
    out["bola_slow"] = rate(c)
    reset(base); t1 = token("user4", "password123")
    out["replay_12_ips"] = rate([send(base, "GET", "/products", rip(g), {"Authorization": "Bearer " + t1}) for _ in range(12)])
    reset(base); t2 = token("user5", "password123"); c = []
    for _ in range(4):
        c.append(send(base, "GET", "/products", rip(g), {"Authorization": "Bearer " + t2})); time.sleep(PACE["replay_slow"])
    out["replay_4_ips_slow"] = rate(c)
    reset(base); c = []
    for i in range(60):
        c.append(send(base, "GET", g.choice(["/products", "/products/%d" % g.randint(1, 4), "/search?q=" + quote(g.choice(["laptop", "o'brien mug", "usb-c cable"]))]), rip(g)))
        time.sleep(0.1)
    out["benign_control"] = rate(c)
    return out


if __name__ == "__main__":
    tag = sys.argv[1]
    res = {}
    for name, base in TARGETS.items():
        res[name] = run(base, random.Random(SEED))
        for k, v in res[name].items():
            print(tag, name, k, "%d/%d" % (v["enforced"], v["n"]), "403=%d 429=%d" % (v["n403"], v["n429"]), flush=True)
    os.makedirs("results", exist_ok=True)
    json.dump({"pace": PACE, "seed": SEED, "results": res}, open("results/adv_suite_%s.json" % tag, "w"), indent=2)
