import os, sys, json, tracemalloc, gc
sys.path.insert(0, sys.argv[1])
os.environ.setdefault("APISENTRY_POLICY", "v7")
os.environ["APISENTRY_DECISION_LOG"] = "/tmp/state_mem_dec.csv"
import gateway as G
from starlette.requests import Request


def req(ip, i):
    scope = {"type": "http", "method": "GET", "path": "/products/%d" % (i % 4 + 1), "query_string": b"", "headers": [(b"x-forwarded-for", ip.encode())], "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 9000), "scheme": "http"}
    return Request(scope)


out = []
for n in [1000, 10000, 50000, 100000]:
    for st in (G.state, G.state_long, G.token_state, G.token_state_long, G.account_state, G.object_state, G.buckets, G.src_long, G.object_long, G.fail_long):
        st.clear()
    gc.collect()
    tracemalloc.start()
    s0 = tracemalloc.take_snapshot()
    for i in range(n):
        ip = "%d.%d.%d.%d" % (10 + (i >> 24) % 200, (i >> 16) & 255, (i >> 8) & 255, i & 255)
        f, m = G.extract(req(ip, i), b"")
        m["dq"].append((m["now"], 0, 0, m["ep_norm"], m["tuser"]))
        m["dq_long"].append(m["now"])
        G.rate_exceeded(ip, m["now"])
    gc.collect()
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    keys = sum(len(st) for st in (G.state, G.state_long, G.src_long, G.object_long, G.fail_long, G.buckets))
    out.append({"tracked_sources": n, "state_MB": round(cur / 1e6, 1), "keys_total": keys, "bytes_per_source": round(cur / n)})
    print(out[-1], flush=True)
json.dump({"max_keys_per_structure": G.MAX_KEYS, "rows": out}, open(sys.argv[2], "w"), indent=2)
