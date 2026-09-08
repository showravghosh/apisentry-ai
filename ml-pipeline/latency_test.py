import time
import statistics
import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BACKEND = "http://localhost:8000/products"
GATEWAY = "http://localhost:9000/products"
N = 300


def bench(url, gateway=False):
    lat = []
    ok = 0
    for i in range(N):
        headers = {}
        if gateway:
            headers["X-Forwarded-For"] = f"10.{i // 256 % 256}.{i % 256}.1"
        t0 = time.perf_counter()
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                ok += 1
        except Exception:
            pass
        lat.append((time.perf_counter() - t0) * 1000)
    return lat, ok


def summarize(name, lat, ok):
    s = sorted(lat)
    mean = statistics.mean(lat)
    print(f"\n{name}")
    print(f"  requests     : {len(lat)}  (200 OK: {ok})")
    print(f"  mean latency : {mean:.2f} ms")
    print(f"  median       : {statistics.median(lat):.2f} ms")
    print(f"  p95          : {s[int(0.95 * len(s)) - 1]:.2f} ms")
    print(f"  p99          : {s[int(0.99 * len(s)) - 1]:.2f} ms")
    print(f"  throughput   : {1000 / mean:.1f} req/sec")
    return mean


def main():
    print("Warming up...")
    bench(BACKEND); bench(GATEWAY, gateway=True)

    print(f"\nBenchmarking {N} requests each...")
    b_lat, b_ok = bench(BACKEND)
    g_lat, g_ok = bench(GATEWAY, gateway=True)

    b_mean = summarize("BACKEND (direct)", b_lat, b_ok)
    g_mean = summarize("GATEWAY (APISentry AI)", g_lat, g_ok)

    print(f"\nGateway overhead: {g_mean - b_mean:.2f} ms per request")

    plt.figure(figsize=(6, 5))
    plt.bar(["Backend\n(direct)", "Gateway\n(APISentry AI)"], [b_mean, g_mean],
            color=["#22c55e", "#3b82f6"])
    plt.ylabel("Mean latency (ms)")
    plt.title("Latency: Direct vs APISentry Gateway", fontweight="bold")
    for i, v in enumerate([b_mean, g_mean]):
        plt.text(i, v, f"{v:.1f} ms", ha="center", va="bottom", fontweight="bold")
    plt.tight_layout()
    plt.savefig("results/latency.png", dpi=150)
    print("\nChart saved to results/latency.png")


if __name__ == "__main__":
    main()
