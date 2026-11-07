import sys, json, os
sys.path.insert(0, ".")
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import stats as S

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
E10 = json.load(open("out/e10_final.json"))
OOF = np.load("out/e10_oof.npz", allow_pickle=True)


def save(fig, name):
    fig.savefig(os.path.join(OUT, name)); plt.close(fig)


lab = E10["confusion_catboost"]["labels"]; M = np.array(E10["confusion_catboost"]["matrix"], dtype=float)
R = M / M.sum(1, keepdims=True)
fig, ax = plt.subplots(figsize=(6.6, 5.4))
ax.grid(False)
im = ax.imshow(R, cmap="Blues", vmin=0, vmax=1)
for i in range(len(lab)):
    for j in range(len(lab)):
        if M[i, j] > 0:
            ax.text(j, i, "%d" % M[i, j], ha="center", va="center", fontsize=7.5, color="#ffffff" if R[i, j] > 0.55 else INK)
ax.set_xticks(range(len(lab))); ax.set_xticklabels([NICE[c] for c in lab], rotation=40, ha="right")
ax.set_yticks(range(len(lab))); ax.set_yticklabels([NICE[c] for c in lab])
ax.set_xlabel("Predicted class"); ax.set_ylabel("True class")
cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.03); cb.set_label("Row-normalised share")
save(fig, "fig_confusion_rev.png")

V = E10["feature_view_ablation"]
cls = ATK + ["normal"]
fig, ax = plt.subplots(figsize=(6.8, 4.2))
y = np.arange(len(cls)); h = 0.26
for k, (vn, col, nm) in enumerate([("payload_only", C3, "Payload only"), ("behavioural_only", C2, "Behavioural only"), ("both", C1, "Payload + behavioural")]):
    vals = [V[vn]["per_class"][c]["f1"] for c in cls]
    ax.barh(y + (k - 1) * h, vals, height=h - 0.03, color=col, label=nm, edgecolor=SURF, linewidth=0.8)
ax.set_yticks(y); ax.set_yticklabels([NICE[c] for c in cls]); ax.invert_yaxis()
ax.set_xlim(0, 1.05); ax.set_xlabel("Per-class F1 (pooled out-of-fold, session-grouped)")
ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3)
ax.grid(axis="y", visible=False)
save(fig, "fig_ablation_views_rev.png")

MC = E10["model_comparison"]; CI = E10["model_ci"]
order = sorted(MC, key=lambda k: -MC[k]["macroF1"])
fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.9), sharey=True)
for ax, met, xl in [(axs[0], "macroF1", "Macro-F1 (95% CI)"), (axs[1], "fpr", "False-positive rate on benign (95% CI)")]:
    for i, mname in enumerate(order):
        p = CI[mname][met]["point"]; lo, hi = CI[mname][met]["ci95"]
        col = C1 if mname == "CatBoost" else INK2
        ax.errorbar(p, i, xerr=[[p - lo], [hi - p]], fmt="o", color=col, ms=6, capsize=3, lw=1.4)
        ax.text(hi + (0.004 if met == "macroF1" else 0.004), i, "%.3f" % p, va="center", fontsize=8, color=INK)
    ax.set_xlabel(xl); ax.grid(axis="y", visible=False)
axs[0].set_yticks(range(len(order))); axs[0].set_yticklabels(order); axs[0].invert_yaxis()
axs[0].set_xlim(0.78, 0.97); axs[1].set_xlim(0, 0.24)
save(fig, "fig_modelcmp_rev.png")

SW = E10["sweeps"]
fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.9))
for part, ls, nm in [("validation", "--", "Validation (selection)"), ("test", "-", "Test (reported)")]:
    t = [r["t"] for r in SW[part]["thresh"]]
    det = [r["flag_att"] / r["n_att"] for r in SW[part]["thresh"]]
    fp = [r["flag_ben"] / r["n_ben"] for r in SW[part]["thresh"]]
    axs[0].plot(t, det, ls, color=C1, lw=2, marker="o", ms=4, label=nm)
    axs[1].plot(t, fp, ls, color=C2, lw=2, marker="o", ms=4, label=nm)
for ax in axs:
    for tv, nm in [(0.75, r"$\tau_r$"), (0.99, r"$\tau_b$")]:
        ax.axvline(tv, color=INK2, lw=0.8, ls=":")
        ax.text(tv, ax.get_ylim()[1], nm, ha="center", va="bottom", fontsize=8, color=INK2)
    ax.set_xlabel("Risk threshold $t$"); ax.legend(loc="best", fontsize=7.5)
axs[0].set_ylabel("Attack requests flagged"); axs[1].set_ylabel("Benign requests flagged")
save(fig, "fig_threshold_rev.png")


SH = json.load(open("out/e14_shap.json"))
FN = {"body_special": "special chars", "body_sql_hits": "SQL keywords $h$", "body_max_num": "max numeric", "body_min_num": "min numeric", "body_has_neg": "negative value",
      "body_field_count": "field count", "is_login": "login endpoint", "ip_req_10s": "$R_s$ requests 10 s", "ip_fail_10s": "$F_s$ errors 10 s", "ip_fail_ratio_10s": r"$\rho$ error ratio",
      "ip_login_10s": "$L_s$ logins 10 s", "ip_uniq_ep_10s": "distinct endpoints", "ip_distinct_users_10s": "$U_s$ distinct objects", "token_ips_10s": "$T_k$ token sources",
      "glob_login_fail_10s": "global login failures", "glob_login_users_10s": "global login accounts", "acct_fail_60s": "account failures 60 s", "method_enc": "method", "endpoint_norm_enc": "endpoint"}
fig, axs = plt.subplots(2, 4, figsize=(9.6, 4.6))
for ax, c in zip(axs.ravel(), ATK):
    d = sorted(SH["mean_abs_shap_own_class"][c].items(), key=lambda t: -t[1])[:5][::-1]
    ax.barh(range(len(d)), [v for _, v in d], color=C1, height=0.6)
    ax.set_yticks(range(len(d))); ax.set_yticklabels([FN.get(k, k) for k, _ in d], fontsize=7)
    ax.set_title(NICE[c], fontsize=8.5, color=INK); ax.grid(axis="y", visible=False); ax.tick_params(axis="x", labelsize=7)
axs.ravel()[-1].axis("off")
fig.text(0.5, -0.01, "Mean |SHAP| contribution to the class's own score (300 requests per class)", ha="center", fontsize=8, color=INK2)
fig.tight_layout()
save(fig, "fig_shap_rev.png")

Y = OOF["y"]; G = OOF["g"]; LAB = sorted(set(Y))
tabs = {"both": S.session_tables(Y, OOF["view_both"], G, LAB), "beh": S.session_tables(Y, OOF["view_behavioural_only"], G, LAB)}
_, dr = S.boot(tabs, n_boot=2000, seed=0)
diff = np.array(dr["both"]["macroF1"]) - np.array(dr["beh"]["macroF1"])
lo, hi = np.percentile(diff, [2.5, 97.5])
fig, ax = plt.subplots(figsize=(5.6, 2.8))
ax.hist(diff, bins=40, color=C1, edgecolor=SURF)
for v in (lo, hi):
    ax.axvline(v, color=INK2, ls="--", lw=1)
ax.axvline(0, color="#e34948", lw=1.2)
ax.set_xlabel("Macro-F1 difference, payload + behavioural minus behavioural only"); ax.set_ylabel("Bootstrap resamples")
ax.text(hi, ax.get_ylim()[1] * 0.9, "  95%% CI [%.3f, %.3f]" % (lo, hi), fontsize=8, color=INK)
ax.grid(axis="x", visible=False)
save(fig, "fig_session_test_rev.png")
json.dump({"session_bootstrap_diff_ci95": [round(float(lo), 4), round(float(hi), 4)], "mean": round(float(diff.mean()), 4)}, open(os.path.join(OUT, "fig_session_test_values.json"), "w"))
print("figures written to", OUT)
