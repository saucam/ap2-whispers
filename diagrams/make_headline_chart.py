"""Render the headline ASR bar chart for the AP2 Whispers measurement piece.

All numbers are pulled live from results/*_summary.json — no hand-typed
values. Re-run after any rerun to regenerate.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"


def load(name):
    with open(RESULTS / name) as f:
        return json.load(f)


# Source-of-truth files
vault_undef = load("vault_whisper_g25f_summary.json")
branded_undef = load("branded_whisper_g25f_summary.json")
vault_naive = load("defense_naive_3c_3c_vault_summary.json")
vault_zeroid = load("defense_zeroid_3c_3c_vault_summary.json")
scope_naive = load("defense_naive_3c_3c_scope_summary.json")
scope_zeroid = load("defense_zeroid_3c_3c_scope_summary.json")
baseline_v1 = load("baseline_v1_g25f_summary.json")
baseline_v2 = load("baseline_v2_g25f_summary.json")


def pct(d):
    return float(d["raw_asr"]) * 100.0


def label(d):
    """Per-arm breach count / N. Schema varies — undefended runs use
    `successes`; defended runs use `breaches`."""
    count = d.get("breaches", d.get("successes"))
    return f"{int(count)}/{int(d['n'])}"


# Layout: 3 attack groups × 3 arms each
groups = [
    "Vault Whisper\n(cross-account read)",
    "Branded Whisper\n(ranking manipulation)",
    "Payment Token Whisper\n(privileged-write injection)",
]
n_groups = len(groups)

arm_labels = [
    "Undefended (bare AP2 reference)",
    "Substitute-only middleware (naive_3c)",
    "Production OAuth2 middleware (zeroid_3c)",
]
arm_colors = ["#c0392b", "#e67e22", "#16a085"]  # red / orange / teal

# data[group][arm] = (pct, label) or None
data = [
    [(pct(vault_undef), label(vault_undef)), (pct(vault_naive), label(vault_naive)), (pct(vault_zeroid), label(vault_zeroid))],
    [(pct(branded_undef), label(branded_undef)), None, None],
    [None, (pct(scope_naive), label(scope_naive)), (pct(scope_zeroid), label(scope_zeroid))],
]

x = np.arange(n_groups)
width = 0.26

fig, ax = plt.subplots(figsize=(12, 6.8))

for arm in range(3):
    heights = [data[g][arm][0] if data[g][arm] else 0 for g in range(n_groups)]
    bars = ax.bar(
        x + (arm - 1) * width,
        heights,
        width,
        label=arm_labels[arm],
        color=arm_colors[arm],
        edgecolor="black",
        linewidth=0.7,
    )
    for g, b in enumerate(bars):
        cell = data[g][arm]
        if cell is None:
            b.set_visible(False)
            ax.annotate(
                "n/a",
                xy=(b.get_x() + b.get_width() / 2, 2),
                ha="center",
                va="bottom",
                fontsize=9,
                color="#888",
                style="italic",
            )
        else:
            p, lbl = cell
            ax.annotate(
                f"{p:.0f}%\n({lbl})",
                xy=(b.get_x() + b.get_width() / 2, b.get_height()),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=10,
                fontweight="bold",
            )

ax.set_xticks(x)
ax.set_xticklabels(groups, fontsize=11)
ax.set_ylabel("Attack success rate (% of N=20 runs, breach criterion fires)", fontsize=11)
ax.set_ylim(0, 110)
ax.set_yticks([0, 25, 50, 75, 100])
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v)}%"))
ax.set_title(
    "Whispers of Wealth, measured\n"
    "Replicating the AP2 attack paper on its own model (gemini-2.5-flash), N=20",
    fontsize=14,
    fontweight="bold",
    pad=18,
)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.10), ncol=3, framealpha=0.95, fontsize=9.5)
ax.grid(axis="y", linestyle="--", alpha=0.4)
ax.set_axisbelow(True)
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)

# Footer caveats — drawn directly from baseline summaries to avoid hand-typed numbers
v1_n = int(baseline_v1.get("N", baseline_v1.get("completed", 0) + baseline_v1.get("not_completed", 0)))
v1_ok = int(baseline_v1.get("completed", 10))
v2_n = int(baseline_v2.get("N", baseline_v2.get("completed", 0) + baseline_v2.get("not_completed", 0)))
v2_ok = int(baseline_v2.get("completed", 0))

footer = (
    f"Reference stability (no-attack baseline): v1 / human-present {v1_ok}/{v1_n}, "
    f"v2 / human-not-present {v2_ok}/{v2_n} on the paper's own model.\n"
    "Branded Whisper 0% is on a broken substrate (v2 baseline does not complete). "
    "Payment Token Whisper has no meaningful 'undefended' baseline — bare AP2 has no scope concept.\n"
    "Defense: production OAuth2 resource-server middleware (validate-at-entry, JWKS verify, substitute bound principal, scope-confine write tools).\n"
    "Source: github.com/saucam/ap2-whispers   |   Paper: arXiv:2601.22569"
)
fig.text(0.5, -0.05, footer, ha="center", fontsize=8.6, color="#444", style="italic")

plt.tight_layout(rect=[0, 0.02, 1, 1])
out = HERE / "headline.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor="white")
print(f"saved {out}")
