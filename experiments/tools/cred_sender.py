import sys
import json
import requests

BASE = sys.argv[1]
KIND = sys.argv[2]
PATH = "/users/v1/login" if KIND == "vampi" else "/login"
PAIRS = json.loads(sys.argv[3])
S = requests.Session()
for u, p in PAIRS:
    try:
        S.post(BASE + PATH, json={"username": u, "password": p}, timeout=10)
    except Exception:
        pass
