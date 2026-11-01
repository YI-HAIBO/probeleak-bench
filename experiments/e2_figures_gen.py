"""E2 论文图件生成器（fig5）：全部数值直接读取 results/e2_baseline_comparison_v1.json
与 results/e2_real_schema_hiding_v1.json（若存在）。

产出：
  paper/figures/fig5_e2_baseline.pdf   双面板：左=W-R 机制触及面/边际残差；右=W-S 交叉点
  paper/figures/fig5b_e2_real_schema_hiding.pdf（E2b 存在时）逐探针基线 vs hidden
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(BASE, "results")
F = os.path.join(BASE, "paper", "figures")
os.makedirs(F, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 10,
    "axes.labelsize": 10,
    "axes.titlesize": 10,
    "legend.fontsize": 8.5,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "pdf.fonttype": 42,
    "savefig.dpi": 300,
})


def load(fn):
    with open(os.path.join(R, fn), encoding="utf-8") as f:
        return json.load(f)


a = load("e2_baseline_comparison_v1.json")
b = None
if os.path.exists(os.path.join(R, "e2_real_schema_hiding_v1.json")):
    b = load("e2_real_schema_hiding_v1.json")

COT = "#c0392b"
FINAL = "#2e86c1"
UNION = "#7d3c98"
TAU = "#117a65"
GRAY = "#7f8c8d"
GOLD = "#b7950b"
BASELINE_C = "#8e44ad"

MODES = ["prefix_extraction", "step_reconstruction", "tool_injection",
         "reasoning_escalation", "thinking_leak"]
MODE_LAB = {"prefix_extraction": "prefix-extr.",
            "step_reconstruction": "step-recon.",
            "tool_injection": "tool-inj.",
            "reasoning_escalation": "reason-escal.",
            "thinking_leak": "thinking-leak"}
CFG_LAB = {"C0_passthrough": "C0 pass",
           "C1_tau_scrub": "C1 $\\tau$",
           "C4_d30_s10": "C4 D30 s=1",
           "B1_pccsql": "B1 PCC-SQL",
           "B2_schema_hiding": "B2 schema-hid.",
           "B3_combined": "B3 combined"}

r = a["results"]
attr = r["real_event_attribution"]

# ---------------------------------------------------------------- Fig 5
# Two-panel: (a) W-R marginal residual vs p_cot for key configs;
#            (b) W-S crossover with leak-only / utility p* markers.
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.2, 3.2))

# ---- panel (a): W-R consumer-channel residual ----
wr = r["marginal_W_R"]["table"]
pcot_keys = list(a["config"]["pcot_grid"])
pcots = [float(x) for x in pcot_keys]
for key, col, mk in [("C0_passthrough", COT, "o-"),
                     ("B1_pccsql", BASELINE_C, "s--"),
                     ("B2_schema_hiding", GOLD, "^:"),
                     ("C1_tau_scrub", TAU, "D-")]:
    ys = [wr[key]["resid_by_pcot"][str(pc)]["resid"] for pc in pcot_keys]
    ax1.plot(pcots, ys, mk, color=col, lw=1.6, ms=4.5, label=CFG_LAB[key])
ax1.set_xlabel("consumer CoT-channel visibility $p_{cot}$")
ax1.set_ylabel("residual leak rate (W-R)")
ax1.set_title("(a) real-calibrated world", fontsize=9.5)
ax1.legend(loc="upper left", framealpha=0.95)
ax1.grid(alpha=0.3)
ax1.set_xticks(pcots)

# ---- panel (b): W-S crossover ----
ws = r["marginal_W_S"]["table"]
for key, col, mk in [("C0_passthrough", COT, "o-"),
                     ("B1_pccsql", BASELINE_C, "s--"),
                     ("C4_d30_s10", UNION, "^-")]:
    ys = [ws[key]["resid_by_pcot"][str(pc)]["resid"] for pc in pcot_keys]
    ax2.plot(pcots, ys, mk, color=col, lw=1.6, ms=4.5, label=CFG_LAB[key])
cov = r["optimal_map_W_S"]["crossover"]
p_leak = cov["leak_only_p_star"]
ax2.axvline(p_leak, ls="-.", color=GRAY, lw=1.2)
ax2.annotate("leak-only $p^*$=%.2f" % p_leak, xy=(p_leak, 0.05),
             xytext=(0.06, 0.05), fontsize=8, color=GRAY)
lam2 = cov["utility_p_star_by_lambda"]["2.0"]
if lam2 is not None:
    ax2.axvline(lam2, ls=":", color=TAU, lw=1.4)
    ax2.annotate("utility $p^*$($\\lambda$=2)=%.2f" % lam2, xy=(lam2, 0.13),
                 xytext=(0.06, 0.13), fontsize=8, color=TAU)
ax2.set_xlabel("consumer CoT-channel visibility $p_{cot}$")
ax2.set_ylabel("residual leak rate (W-S)")
ax2.set_title("(b) simulated-calibrated world", fontsize=9.5)
ax2.legend(loc="upper left", framealpha=0.95)
ax2.grid(alpha=0.3)
ax2.set_xticks(pcots)

fig.tight_layout()
fig.savefig(os.path.join(F, "fig5_e2_baseline.pdf"), bbox_inches="tight")
plt.close(fig)

# ---------------------------------------------------------------- Fig 5b
# E2b per-probe baseline vs schema-hidden CoT leak rates (only if measured).
if b is not None:
    pids = [p for p in b["per_probe_comparison"]
            if b["per_probe_comparison"][p]["baseline"] is not None]
    pids.sort()
    bl = [b["per_probe_comparison"][p]["baseline_cot_rate"] for p in pids]
    hd = [b["per_probe_comparison"][p]["hidden_cot_rate"] for p in pids]
    x = range(len(pids))
    fig, ax = plt.subplots(figsize=(4.4, 2.9))
    ax.bar([i - 0.19 for i in x], bl, width=0.38, color=GRAY,
           label="B1+B3 baseline")
    ax.bar([i + 0.19 for i in x], hd, width=0.38, color=BASELINE_C,
           label="schema hidden")
    ax.set_xticks(list(x))
    ax.set_xticklabels(pids, fontsize=8)
    ax.set_ylabel("CoT leak rate")
    ax.set_title("Real schema-hiding arm on dots3-note-prev", fontsize=9.5)
    ax.legend(framealpha=0.95)
    ax.grid(alpha=0.3, axis="y")
    fig.tight_layout()
    fig.savefig(os.path.join(F, "fig5b_e2_real_schema_hiding.pdf"),
                bbox_inches="tight")
    plt.close(fig)
    print("[E2-fig] wrote fig5_e2_baseline.pdf + fig5b_e2_real_schema_hiding.pdf")
else:
    print("[E2-fig] wrote fig5_e2_baseline.pdf (E2b JSON absent; fig5b skipped)")
