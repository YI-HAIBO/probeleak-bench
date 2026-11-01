"""E1 跨模型图件生成器：fig8_e1_cross_model.pdf

从 results/e1_cross_model_v1.json 现算数据，matplotlib 生成 PDF
（pdf.fonttype=42，Times New Roman，与论文其他图件一致）。
幂等：重跑 sha256 一致。
"""

import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "paper", "figures", "fig8_e1_cross_model.pdf")
E1_JSON = os.path.join(ROOT, "results", "e1_cross_model_v1.json")

rcParams["font.family"] = "serif"
rcParams["font.serif"] = ["Times New Roman"]
rcParams["mathtext.fontset"] = "stix"
rcParams["pdf.fonttype"] = 42
rcParams["axes.linewidth"] = 0.8
rcParams["xtick.major.width"] = 0.8
rcParams["ytick.major.width"] = 0.8


def wilson_ci(k, n, z=1.959963985):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5 / denom
    return (max(0.0, center - half), min(1.0, center + half))


def short_name(model):
    """Paper short names (Table tab:e1cross) instead of internal model codes."""
    m = model.lower()
    if "beam" in m:
        return "Beam"
    if "nemotron-3-super" in m:
        return "Nemotron-3-Super"
    if "nemotron-3-nano" in m:
        return "Nemotron-3-Nano"
    return model.split("/")[-1]


def main():
    d = json.load(open(E1_JSON, encoding="utf-8"))
    comps = d["cross_model_comparisons"]
    ref_rate = comps[0]["ref_rate"]
    ref_n = comps[0]["ref_n"]
    ref_leaks = comps[0]["ref_leaks"]

    labels = []
    rates = []
    los = []
    his = []
    colors = []
    for c in comps:
        labels.append(short_name(c["model"]))
        rates.append(c["rate"])
        lo, hi = wilson_ci(c["cot_leaks"], c["n"])
        los.append(lo)
        his.append(hi)
        colors.append("#2E86AB" if c["vendor"] == "Reflection AI" else "#A23B72")

    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    xs = list(range(len(comps)))
    yerr_lo = [rates[i] - los[i] for i in xs]
    yerr_hi = [his[i] - rates[i] for i in xs]
    ax.errorbar(xs, rates, yerr=[yerr_lo, yerr_hi], fmt="none",
                ecolor="#333333", elinewidth=1.2, capsize=5, capthick=1.2)
    ax.scatter(xs, rates, s=70, c=colors, zorder=3, edgecolors="#222222",
               linewidths=0.6)

    # reference line
    ax.axhline(ref_rate, color="#888888", linestyle="--", linewidth=1.0,
               zorder=1)
    ax.text(-0.45, ref_rate + 0.05,
            "reference (primary model) %.1f%% (%d/%d)" % (100 * ref_rate,
                                                          ref_leaks, ref_n),
            fontsize=9, color="#666666", ha="left")

    # annotate rates above each point, clear of the CI bar
    for i, (x, r) in enumerate(zip(xs, rates)):
        if his[i] + 0.05 <= 1.0:
            ax.text(x, his[i] + 0.04, "%.1f%%" % (100 * r),
                    ha="center", va="bottom", fontsize=10, fontweight="bold",
                    color=colors[i])
        else:
            ax.text(x, los[i] - 0.04, "%.1f%%" % (100 * r),
                    ha="center", va="top", fontsize=10, fontweight="bold",
                    color=colors[i])

    ax.set_xticks(xs)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylabel("CoT leak rate", fontsize=11)
    ax.set_ylim(0, 1.0)
    ax.set_xlim(-0.6, 2.6)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0%", "25%", "50%", "75%", "100%"], fontsize=10)
    
    ax.tick_params(direction="out", length=4)

    # legend
    from matplotlib.patches import Patch
    handles = [
        Patch(facecolor="#2E86AB", label="Reflection AI"),
        Patch(facecolor="#A23B72", label="NVIDIA"),
    ]
    ax.legend(handles=handles, loc="upper right", fontsize=9.5,
              frameon=False, ncol=1)

    fig.tight_layout(pad=0.6)
    fig.savefig(OUT, format="pdf", bbox_inches="tight")
    plt.close(fig)
    print("WROTE", OUT, os.path.getsize(OUT), "bytes")


if __name__ == "__main__":
    main()