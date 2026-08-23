"""
Baseline comparison: APIShield vs ModSecurity (OWASP CRS).

Sends the SAME set of attacks (and normal traffic) through two systems and records
what each one BLOCKS, so we can show that a signature-based WAF misses the behavioural
API attacks that APIShield detects.

Targets (all proxy to the same test API on port 8000):
  - ModSecurity WAF : http://localhost:8081   (from baseline/docker-compose.yml)
  - APIShield       : http://localhost:9000   (from ./run.sh)

Run (from project root, with the traffic-generator venv that has 'requests'):
  traffic-generator/venv/bin/python baseline/run_comparison.py
"""

import time
import csv
import requests

TEST_API = "http://localhost:8000"          # direct backend (to fetch a valid token)
TARGETS = {
    "ModSecurity (CRS)": "http://localhost:8081",
    "APIShield":         "http://localhost:9000",
}
N = 25                                        # requests per attack
TIMEOUT = 5
BLOCK_CODES = {403, 429}                      # both WAFs use these when blocking


def get_token():
    try:
        r = requests.post(f"{TEST_API}/login",
                          json={"username": "admin", "password": "admin123"}, timeout=TIMEOUT)
        return r.json().get("access_token")
    except Exception:
        return None


def send(base, method, path, **kw):
    try:
        r = requests.request(method, base + path, timeout=TIMEOUT, **kw)
        return r.status_code
    except Exception:
        return None


# ---- one function per attack type: returns list of status codes ----
def atk_sql_injection(base, token):
    codes = []
    payloads = ["' OR '1'='1", "1' UNION SELECT username,password FROM users--",
                "'; DROP TABLE users;--", "admin'--", "1 OR 1=1"]
    for i in range(N):
        p = payloads[i % len(payloads)]
        codes.append(send(base, "GET", f"/search?q={requests.utils.quote(p)}"))
    return codes


def atk_parameter_tampering(base, token):
    codes = []
    h = {"Authorization": f"Bearer {token}"} if token else {}
    for i in range(N):
        body = {"product_id": -9999 - i, "quantity": -50000}
        codes.append(send(base, "POST", "/cart/add", json=body, headers=h))
    return codes


def atk_bola(base, token):
    codes = []
    h = {"Authorization": f"Bearer {token}"} if token else {}
    for i in range(N):
        codes.append(send(base, "GET", f"/users/{i+1}", headers=h))   # accessing many users' objects
    return codes


def atk_brute_force(base, token):
    codes = []
    for i in range(N):
        codes.append(send(base, "POST", "/login",
                          json={"username": "admin", "password": f"wrong{i}"}))
    return codes


def atk_credential_stuffing(base, token):
    codes = []
    for i in range(N):
        codes.append(send(base, "POST", "/login",
                          json={"username": f"user{i}", "password": f"Pass{i}!"}))
    return codes


def atk_api_flooding(base, token):
    codes = []
    for i in range(N * 2):                     # high rate
        codes.append(send(base, "GET", "/products"))
    return codes


def atk_token_replay(base, token):
    codes = []
    h = {"Authorization": f"Bearer {token}"} if token else {}
    for i in range(N):
        hh = dict(h); hh["X-Forwarded-For"] = f"10.0.{i}.{i+1}"   # same token, many IPs
        codes.append(send(base, "GET", "/cart", headers=hh))
    return codes


def normal_traffic(base, token):
    # Realistic legitimate traffic: many DIFFERENT users (distinct IPs) browsing at a human
    # pace and unauthenticated - so we measure false positives on genuine traffic, not on a
    # burst from a single IP (which would look like flooding). No shared token (that is replay).
    codes = []
    for i in range(N * 2):
        h = {"X-Forwarded-For": f"203.0.{i // 254}.{(i % 254) + 1}"}
        ep = "/products" if i % 2 == 0 else f"/products/{(i % 4) + 1}"
        codes.append(send(base, "GET", ep, headers=h))
        time.sleep(0.1)
    return codes


ATTACKS = {
    "sql_injection": atk_sql_injection,
    "parameter_tampering": atk_parameter_tampering,
    "bola": atk_bola,
    "brute_force": atk_brute_force,
    "credential_stuffing": atk_credential_stuffing,
    "api_flooding": atk_api_flooding,
    "token_replay": atk_token_replay,
}


def block_rate(codes):
    valid = [c for c in codes if c is not None]
    if not valid:
        return 0.0
    return sum(1 for c in valid if c in BLOCK_CODES) / len(valid)


def main():
    token = get_token()
    print("token:", "ok" if token else "NONE (BOLA/token tests will be limited)")
    rows = []
    for atk, fn in ATTACKS.items():
        row = {"attack": atk}
        for tname, base in TARGETS.items():
            rate = block_rate(fn(base, token))
            row[tname] = round(rate, 3)
            time.sleep(1)                       # let per-IP windows reset between systems
        rows.append(row)
        print(f"{atk:22s}  " + "  ".join(f"{t}={row[t]*100:4.0f}%" for t in TARGETS))

    # let per-IP rate windows fully decay after the attack burst before measuring false positives
    print("cooling down 65s before false-positive test ...")
    time.sleep(65)
    fp = {"attack": "normal (false positive)"}
    for tname, base in TARGETS.items():
        fp[tname] = round(block_rate(normal_traffic(base, token)), 3)
        time.sleep(1)
    rows.append(fp)
    print(f"{'normal (FP)':22s}  " + "  ".join(f"{t}={fp[t]*100:4.0f}%" for t in TARGETS))

    with open("baseline/comparison_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["attack"] + list(TARGETS))
        w.writeheader(); w.writerows(rows)
    print("\nSaved: baseline/comparison_results.csv")
    print("Detection = fraction of malicious requests blocked (403/429). Higher is better;")
    print("for the 'normal' row, LOWER is better (false positives).")


if __name__ == "__main__":
    main()
