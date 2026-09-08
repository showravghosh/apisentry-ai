"""Make a comparison bar chart from baseline/comparison_results.csv."""
import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

rows = list(csv.DictReader(open("baseline/comparison_results.csv")))
systems = [c for c in rows[0].keys() if c != "attack"]
attacks = [r["attack"] for r in rows]
x = np.arange(len(attacks)); w = 0.8 / len(systems)
colors = ["#c62828", "#1565c0", "#2e7d32", "#f9a825"]

plt.figure(figsize=(11, 5))
for i, s in enumerate(systems):
    vals = [float(r[s]) * 100 for r in rows]
    plt.bar(x + i * w, vals, w, label=s, color=colors[i % len(colors)])
plt.xticks(x + w * (len(systems) - 1) / 2, attacks, rotation=30, ha="right")
plt.ylabel("Detection / block rate (%)")
plt.title("APISentry vs ModSecurity - detection by attack type", fontweight="bold")
plt.ylim(0, 105); plt.legend(); plt.grid(axis="y", alpha=0.3)
plt.tight_layout(); plt.savefig("baseline/comparison_chart.png", dpi=150)
print("Saved: baseline/comparison_chart.png")
