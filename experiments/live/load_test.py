import os
import sys
import json
import time
import asyncio
import random
import statistics
import httpx
import psutil

DURATION = float(os.getenv("LOAD_DURATION", "15"))
LEVELS = [int(x) for x in os.getenv("LOAD_LEVELS", "1,8,32,64").split(",")]


def pct(a, q):
    a = sorted(a)
    return a[min(len(a) - 1, int(q * len(a)))]


async def worker(client, url, lat, codes, stop, rng, churn):
    while time.time() < stop:
        ip = "%d.%d.%d.%d" % (rng.randint(11, 223), rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254)) if churn else "10.%d.%d.%d" % (rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254))
        t0 = time.perf_counter()
        try:
            r = await client.get(url + "/products/%d" % rng.randint(1, 4), headers={"X-Forwarded-For": ip})
            codes.append(r.status_code)
        except Exception:
            codes.append(None)
        lat.append((time.perf_counter() - t0) * 1000)


async def level(url, conc, pid, churn=False):
    lat, codes = [], []
    proc = psutil.Process(pid) if pid else None
    if proc:
        proc.cpu_percent(None)
    rss0 = proc.memory_info().rss / 1e6 if proc else None
    stop = time.time() + DURATION
    async with httpx.AsyncClient(timeout=30.0, limits=httpx.Limits(max_connections=conc + 10)) as client:
        await asyncio.gather(*[worker(client, url, lat, codes, stop, random.Random(i), churn) for i in range(conc)])
    cpu = proc.cpu_percent(None) if proc else None
    rss1 = proc.memory_info().rss / 1e6 if proc else None
    ok = [c for c in codes if c is not None]
    return {"concurrency": conc, "requests": len(lat), "rps": round(len(lat) / DURATION, 1),
            "p50_ms": round(pct(lat, 0.5), 2), "p95_ms": round(pct(lat, 0.95), 2), "p99_ms": round(pct(lat, 0.99), 2),
            "mean_ms": round(statistics.mean(lat), 2), "errors": len(codes) - len(ok),
            "blocked_or_limited": sum(1 for c in ok if c in (403, 429)),
            "cpu_percent": round(cpu, 1) if cpu is not None else None, "rss_mb_start": round(rss0, 1) if rss0 else None,
            "rss_mb_end": round(rss1, 1) if rss1 else None}


if __name__ == "__main__":
    tag, url = sys.argv[1], sys.argv[2]
    pid = int(sys.argv[3]) if len(sys.argv) > 3 else None
    churn = len(sys.argv) > 4 and sys.argv[4] == "churn"
    out = []
    for c in LEVELS:
        r = asyncio.run(level(url, c, pid, churn))
        out.append(r)
        print(tag, json.dumps(r), flush=True)
    os.makedirs("results", exist_ok=True)
    json.dump(out, open("results/load_%s.json" % tag, "w"), indent=2)
