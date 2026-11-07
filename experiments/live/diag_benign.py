import sys, random, time, csv, collections, requests
from urllib.parse import quote
sys.argv = ["x"]
import live_coverage as L
G = "http://127.0.0.1:9000"
L.reset(G)
g = random.Random(3001)
clients = [L.rip(g) for _ in range(200)]
utok = {}
for i in range(4, 14):
    r = L.S.post(L.API + "/login", json={"username": "user%d" % i, "password": "password123"}).json()
    utok["user%d" % i] = (r["access_token"], r["user_id"])
codes = collections.Counter()
for i in range(500):
    ip = g.choice(clients)
    if g.random() < 0.3:
        u = g.choice(list(utok)); t2, uid = utok[u]
        c = L.send(G, "GET", g.choice(["/users/%d" % uid, "/cart", "/products"]), ip, {"Authorization": "Bearer " + t2}); codes[("auth", c)] += 1
    else:
        c = L.send(G, "GET", g.choice(["/products", "/products/%d" % g.randint(1, 4), "/search?q=" + quote(g.choice(["laptop", "phone", "o'brien mug", "usb-c cable"]))]), ip); codes[("anon", c)] += 1
    time.sleep(max(0, g.gauss(0.05, 0.02)))
print(dict(codes))
time.sleep(1.5)
rows = list(csv.DictReader(open("../../gateway/gateway_decisions.csv")))[-500:]
print(collections.Counter((r["predicted"], r["decision"]) for r in rows if r["decision"] != "ALLOW"))
