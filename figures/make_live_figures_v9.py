import sys, json, os
sys.path.insert(0, ".")
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

OUT = sys.argv[1]
K = sys.argv[2]
RT = sys.argv[3]
os.makedirs(OUT, exist_ok=True)
C1, C2, C3, C4 = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e6e5e0", "#ffffff"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
                     "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
                     "legend.frameon": False, "figure.facecolor": SURF, "axes.facecolor": SURF, "savefig.dpi": 300, "savefig.bbox": "tight"})
NICE = {"api_flooding": "API flooding", "bola": "BOLA-like access", "brute_force": "Brute force", "credential_stuffing": "Credential stuffing", "normal": "Normal",
        "parameter_tampering": "Parameter tampering", "sql_injection": "SQL injection", "token_replay": "Token replay"}
ATK = ["sql_injection", "parameter_tampering", "bola", "brute_force", "credential_stuffing", "api_flooding", "token_replay"]


def save(fig, name):
    fig.savefig(os.path.join(OUT, name)); plt.close(fig)


cov = json.load(open(os.path.join(K, "live_coverage_final10_extended.json")))
cov0 = json.load(open(os.path.join(K, "live_coverage_final10_original.json")))
SYS = [("ModSecurity_CRS", "ModSecurity CRS", C3), ("RateLimit_baseline", "Rate-limit baseline", C4), ("APISentry_original_fresh", "APISentry-SIG", C2), ("APISentry_v9", "APISentry", C1)]
fig, axs = plt.subplots(1, 2, figsize=(7.4, 3.7), gridspec_kw={"width_ratios": [3.2, 1]})
x = np.arange(len(ATK)); w = 0.2
for k, (key, nm, col) in enumerate(SYS):
    vals = [cov[key][a]["rate"] for a in ATK]
    axs[0].bar(x + (k - 1.5) * w, vals, width=w - 0.02, color=col, label=nm, edgecolor=SURF, linewidth=0.6)
axs[0].set_xticks(x); axs[0].set_xticklabels([NICE[a] for a in ATK], rotation=35, ha="right")
axs[0].set_ylabel("Attack requests blocked or rate-limited"); axs[0].set_ylim(0, 1.05); axs[0].grid(axis="x", visible=False)
axs[0].legend(loc="lower center", bbox_to_anchor=(0.62, 1.0), ncol=2, fontsize=7.5)
for k, (key, nm, col) in enumerate(SYS):
    b = cov[key]["benign"]
    axs[1].bar(k, b["n403"], color=col, edgecolor=SURF)
    axs[1].bar(k, b["n429"], bottom=b["n403"], color=col, hatch="///", alpha=0.55, edgecolor=SURF)
    axs[1].text(k, b["n403"] + b["n429"] + 1, "%d" % (b["n403"] + b["n429"]), ha="center", fontsize=8, color=INK)
ext_o = cov["APISentry_original"]["benign"]
axs[1].set_xticks(range(len(SYS))); axs[1].set_xticklabels(["ModSec", "Rate-limit", "SIG", "APISentry"], rotation=35, ha="right")
axs[1].set_ylabel("Benign requests flagged (of 2,500)"); axs[1].set_ylim(0, 62); axs[1].grid(axis="x", visible=False)
axs[1].text(0.5, 0.97, "APISentry-SIG\nwithout reset: %d" % ext_o["flagged"], transform=axs[1].transAxes, ha="center", va="top", fontsize=7, color=INK2)
save(fig, "fig_live_coverage_rev.png")

REG = ["baseline", "shared_nat", "address_rotation", "bursty_client", "mobile_client", "shared_proxy_authenticated"]
RN = {"baseline": "Baseline", "shared_nat": "Shared NAT", "address_rotation": "Address rotation", "bursty_client": "Bursty client", "mobile_client": "Mobile client", "shared_proxy_authenticated": "Shared auth. proxy"}
RS = [("ratelimit_final10", "Rate-limit baseline", C4), ("original_fresh_final10", "APISentry-SIG", C2), ("v9_final10", "APISentry", C1)]
regs = {k: json.load(open(os.path.join(K, "live_regimes_%s.json" % k))) for k, _, _ in RS}
fig, axs = plt.subplots(1, 2, figsize=(7.4, 3.4))
x = np.arange(len(REG)); w = 0.26
for k, (key, nm, col) in enumerate(RS):
    r = regs[key]
    blk = [r[g]["legit_403"] / r[g]["legit_total"] for g in REG]
    thr = [r[g]["legit_429"] / r[g]["legit_total"] for g in REG]
    det = [r[g]["attack_blocked"] / r[g]["attack_total"] for g in REG]
    axs[0].bar(x + (k - 1) * w, blk, width=w - 0.02, color=col, edgecolor=SURF, label=nm)
    axs[0].bar(x + (k - 1) * w, thr, bottom=blk, width=w - 0.02, color=col, alpha=0.5, hatch="///", edgecolor=SURF)
    axs[1].bar(x + (k - 1) * w, det, width=w - 0.02, color=col, edgecolor=SURF)
for ax, yl in [(axs[0], "Legitimate requests affected\n(solid: blocked, hatched: rate-limited)"), (axs[1], "Attack requests blocked or rate-limited")]:
    ax.set_xticks(x); ax.set_xticklabels([RN[g] for g in REG], rotation=35, ha="right"); ax.set_ylabel(yl); ax.set_ylim(0, 1.0); ax.grid(axis="x", visible=False)
axs[0].legend(loc="upper left", fontsize=7.5)
save(fig, "fig_regimes_rev.png")

adv = json.load(open(os.path.join(K, "adv_suite_final10.json")))
A = adv["results"]; pace = adv["pace"]
CONDS = [("sqli_standard", "SQLi, standard"), ("sqli_evasive", "SQLi, encoded/obfuscated"), ("tamper_standard", "Tampering, standard"), ("tamper_evasive", "Tampering, disguised"),
         ("flood_burst", "Flooding, burst"), ("flood_medium", "Flooding, %g s gap" % pace["flood_medium"]), ("flood_slow", "Flooding, %g s gap" % pace["flood_slow"]),
         ("brute_fast", "Brute force, fast"), ("brute_slow", "Brute force, %g s gap" % pace["brute_slow"]), ("credstuff_distributed", "Cred. stuffing, rotating sources"),
         ("bola_fast", "BOLA-like, fast"), ("bola_slow", "BOLA-like, %g s gap" % pace["bola_slow"]), ("replay_12_ips", "Token replay, 12 sources"), ("replay_4_ips_slow", "Token replay, 4 sources slow"),
         ("benign_control", "Benign control (flagged)")]
AS = [("ModSecurity_CRS", "ModSecurity CRS", C3), ("RateLimit_baseline", "Rate-limit baseline", C4), ("APISentry_original_fresh", "APISentry-SIG", C2), ("APISentry_v9", "APISentry", C1)]
fig, ax = plt.subplots(figsize=(6.8, 6.4))
y = np.arange(len(CONDS)); h = 0.2
for k, (key, nm, col) in enumerate(AS):
    vals = [A[key][c]["enforced"] / max(A[key][c]["n"], 1) for c, _ in CONDS]
    ax.barh(y + (k - 1.5) * h, vals, height=h - 0.02, color=col, label=nm, edgecolor=SURF, linewidth=0.5)
ax.set_yticks(y); ax.set_yticklabels([n for _, n in CONDS]); ax.invert_yaxis(); ax.set_xlim(0, 1.02)
ax.set_xlabel("Requests blocked or rate-limited"); ax.grid(axis="y", visible=False)
ax.legend(loc="lower center", bbox_to_anchor=(0.4, 1.0), ncol=2, fontsize=7.5)
save(fig, "fig_adversarial_rev.png")

g = json.load(open(os.path.join(RT, "load_gateway_v9.json"))); s = json.load(open(os.path.join(RT, "load_stub_direct.json")))
cc = [r["concurrency"] for r in g]
fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.9))
for key, col, nm in [("p50_ms", C1, "p50"), ("p95_ms", C2, "p95"), ("p99_ms", C3, "p99")]:
    axs[0].plot(cc, [r[key] for r in g], "-o", color=col, lw=2, ms=4, label="Gateway " + nm)
    axs[0].plot(cc, [r[key] for r in s], "--", color=col, lw=1.2, label="Direct " + nm)
axs[0].set_xscale("log", base=2); axs[0].set_yscale("log"); axs[0].set_xticks(cc); axs[0].set_xticklabels(cc)
axs[0].set_xlabel("Concurrent clients"); axs[0].set_ylabel("Latency (ms)"); axs[0].legend(fontsize=6.5, ncol=2)
axs[1].plot(cc, [r["rps"] for r in g], "-o", color=C1, lw=2, ms=4, label="Gateway")
axs[1].plot(cc, [r["rps"] for r in s], "--o", color=INK2, lw=1.2, ms=3, label="Direct to stub backend")
axs[1].set_xscale("log", base=2); axs[1].set_xticks(cc); axs[1].set_xticklabels(cc)
axs[1].set_xlabel("Concurrent clients"); axs[1].set_ylabel("Sustained requests per second"); axs[1].legend(fontsize=7)
fig.tight_layout(w_pad=2.5)
save(fig, "fig_runtime_rev.png")

