import os
import sys
import json
import time
import tempfile
import subprocess
import requests

RELAY = os.getenv("RELAY", "http://127.0.0.1:9900")
RPORT = RELAY.rsplit(":", 1)[1]
API = os.getenv("TOOLS_BACKEND", "http://127.0.0.1:8000")
KIND = os.getenv("TOOLS_API", "testapi")
TARGETS = json.loads(os.getenv("TOOLS_TARGETS", '{"APISentry_v8": "http://127.0.0.1:9010"}'))
TITLES = os.getenv("TOOLS_TITLES", "")
S = requests.Session()
TOOLDIR = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="apisentry_tools_")


def wl(name, lines):
    p = os.path.join(TMP, name)
    open(p, "w").write("\n".join(lines) + "\n")
    return p


def relay_cfg(target, mode, label, ip):
    S.post(RELAY + "/__relay/config", json={"target": target, "mode": mode, "label": label, "ip": ip}, timeout=5)


def reset(base):
    for p in ("/__apisentry/reset", "/__ratelimit/reset"):
        try:
            S.post(base + p, timeout=3)
        except Exception:
            pass


def token_testapi():
    return S.post(API + "/login", json={"username": "alice", "password": "password123"}, timeout=5).json()["access_token"]


def token_vampi():
    S.post(API + "/users/v1/register", json={"username": "toolsattacker", "password": "Att4ck!pw", "email": "toolsattacker@example.org"}, timeout=5)
    return S.post(API + "/users/v1/login", json={"username": "toolsattacker", "password": "Att4ck!pw"}, timeout=5).json()["auth_token"]


PASSWORDS = ["123456", "password", "qwerty", "letmein", "welcome", "monkey", "dragon", "football", "iloveyou", "admin", "Summer2024", "Winter2025!", "P@ssw0rd", "abc123",
             "111111", "sunshine", "master", "shadow", "baseball", "trustno1", "superman", "michael", "jennifer", "hunter2", "Passw0rd!", "changeme", "secret", "root", "toor",
             "test123", "guest", "login", "access", "freedom", "whatever", "qazwsx", "zaq12wsx", "starwars", "pokemon", "batman"]
NEG = ["-1", "-2", "-3", "-5", "-10", "-20", "-50", "-100", "-999", "-1000", "-0.5", "-99999", "\"-1\"", "\"-5\"", "\"-100\"", "-7", "-12", "-25", "-64", "-250"]
PRICE = ["0", "0.01", "0.1", "1", "0.5", "2", "-1", "0.001", "5", "0.05"]


def jobs_testapi(R, tok):
    combos = wl("combo.txt", ["user%d:%s" % (i, PASSWORDS[i % len(PASSWORDS)]) for i in range(4, 44)])
    return [
        ("sqlmap", "fixed", ["sqlmap", "-u", R + "/search?q=laptop", "-p", "q", "--batch", "--level", "1", "--risk", "1", "--technique", "BEU", "--flush-session", "--output-dir", os.path.join(TMP, "sqlmap"), "-v", "0", "--disable-coloring"]),
        ("hydra_brute", "fixed", ["hydra", "-I", "-l", "admin", "-P", wl("pass.txt", PASSWORDS), "-s", RPORT, "-t", "2", "127.0.0.1", "http-post-form", '/login:{"username"\\:"^USER^","password"\\:"^PASS^"}:H=Content-Type\\: application/json:S=access_token']),
        ("stuffing_fixed", "fixed", ["python3", os.path.join(TOOLDIR, "cred_sender.py"), R, "testapi", json.dumps([["user%d" % i, PASSWORDS[i % len(PASSWORDS)]] for i in range(4, 44)])]),
        ("stuffing_rotate", "rotate", ["python3", os.path.join(TOOLDIR, "cred_sender.py"), R, "testapi", json.dumps([["user%d" % i, PASSWORDS[i % len(PASSWORDS)]] for i in range(4, 44)])]),
        ("ffuf_enumeration", "fixed", ["ffuf", "-u", R + "/users/FUZZ", "-w", wl("ids.txt", [str(i) for i in range(1, 41)]), "-H", "Authorization: Bearer " + tok, "-t", "2", "-p", "0.1", "-s", "-mc", "all"]),
        ("ffuf_token_reuse", "rotate", ["ffuf", "-u", R + "FUZZ", "-w", wl("paths.txt", ["/products", "/cart", "/products/1", "/products/2", "/products/3", "/search?q=phone"] * 5), "-H", "Authorization: Bearer " + tok, "-t", "1", "-p", "0.2", "-s", "-mc", "all"]),
        ("ffuf_tampering_quantity", "fixed", ["ffuf", "-u", R + "/cart/add", "-X", "POST", "-H", "Content-Type: application/json", "-H", "Authorization: Bearer " + tok, "-d", '{"product_id":1,"quantity":FUZZ}', "-w", wl("neg.txt", NEG), "-t", "1", "-p", "0.2", "-s", "-mc", "all"]),
        ("ffuf_tampering_price", "fixed", ["ffuf", "-u", R + "/cart/add", "-X", "POST", "-H", "Content-Type: application/json", "-H", "Authorization: Bearer " + tok, "-d", '{"product_id":1,"quantity":1,"unit_price":FUZZ}', "-w", wl("price.txt", PRICE), "-t", "1", "-p", "0.2", "-s", "-mc", "all"]),
        ("ab_flooding", "fixed", ["ab", "-q", "-n", "300", "-c", "10", R + "/products"]),
    ]


def jobs_vampi(R, tok):
    users = ["name1", "name2", "admin"] + ["u%d" % i for i in range(37)]
    combos = wl("combo_v.txt", ["%s:%s" % (u, PASSWORDS[i % len(PASSWORDS)]) for i, u in enumerate(users)])
    titles = [x.strip() for x in open(TITLES)] if TITLES and os.path.exists(TITLES) else []
    titles = (titles + ["bookTitle%d" % i for i in range(40)])[:40]
    body = '/users/v1/login:{"username"\\:"^USER^","password"\\:"^PASS^"}:H=Content-Type\\: application/json:S=auth_token'
    return [
        ("sqlmap", "fixed", ["sqlmap", "-u", R + "/users/v1/name1*", "--batch", "--level", "1", "--risk", "1", "--technique", "BEU", "--flush-session", "--output-dir", os.path.join(TMP, "sqlmap_v"), "-v", "0", "--disable-coloring"]),
        ("hydra_brute", "fixed", ["hydra", "-I", "-l", "name1", "-P", wl("pass_v.txt", PASSWORDS), "-s", RPORT, "-t", "2", "127.0.0.1", "http-post-form", body]),
        ("stuffing_fixed", "fixed", ["python3", os.path.join(TOOLDIR, "cred_sender.py"), R, "vampi", json.dumps([[u, PASSWORDS[i % len(PASSWORDS)]] for i, u in enumerate(users)])]),
        ("stuffing_rotate", "rotate", ["python3", os.path.join(TOOLDIR, "cred_sender.py"), R, "vampi", json.dumps([[u, PASSWORDS[i % len(PASSWORDS)]] for i, u in enumerate(users)])]),
        ("ffuf_enumeration", "fixed", ["ffuf", "-u", R + "/books/v1/FUZZ", "-w", wl("titles.txt", titles), "-H", "Authorization: Bearer " + tok, "-t", "2", "-p", "0.1", "-s", "-mc", "all"]),
        ("ffuf_token_reuse", "rotate", ["ffuf", "-u", R + "FUZZ", "-w", wl("paths_v.txt", ["/books/v1", "/me", "/users/v1/toolsattacker"] * 10), "-H", "Authorization: Bearer " + tok, "-t", "1", "-p", "0.2", "-s", "-mc", "all"]),
        ("ab_flooding", "fixed", ["ab", "-q", "-n", "300", "-c", "10", R + "/books/v1"]),
    ]


def versions():
    out = {}
    for name, cmd in [("sqlmap", ["sqlmap", "--version"]), ("hydra", ["hydra", "-h"]), ("ffuf", ["ffuf", "-V"]), ("ab", ["ab", "-V"])]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            out[name] = (r.stdout + r.stderr).strip().splitlines()[0]
        except Exception as e:
            out[name] = "unavailable: %s" % e
    return out


if __name__ == "__main__":
    tag = sys.argv[1]
    tok = token_testapi() if KIND == "testapi" else token_vampi()
    res = {"tools": versions(), "api": KIND, "results": {}}
    print(json.dumps(res["tools"]), flush=True)
    S.post(RELAY + "/__relay/clear", timeout=5)
    for name, base in TARGETS.items():
        for k, (job, mode, cmd) in enumerate(jobs_testapi(RELAY, tok) if KIND == "testapi" else jobs_vampi(RELAY, tok)):
            reset(base)
            label = name + "|" + job
            relay_cfg(base, mode, label, "198.18.%d.10" % (k + 1))
            t0 = time.time()
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
            except subprocess.TimeoutExpired:
                pass
            st = S.get(RELAY + "/__relay/stats", timeout=5).json().get(label, {"n": 0, "n403": 0, "n429": 0})
            st["seconds"] = round(time.time() - t0, 1)
            res["results"].setdefault(name, {})[job] = st
            print(tag, name, job, "%d/%d enforced (403=%d 429=%d)" % (st["n403"] + st["n429"], st["n"], st["n403"], st["n429"]), flush=True)
            time.sleep(2)
    os.makedirs("results", exist_ok=True)
    json.dump(res, open("results/tools_%s.json" % tag, "w"), indent=2)
