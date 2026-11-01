"""Generate figures for the P3 paper. All values are read directly from the
result JSONs so every plotted number is traceable to the stored artifacts."""
import json, os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

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
    "legend.fontsize": 9,
    "xtick.labelsize": 9.5,
    "ytick.labelsize": 9.5,
    "pdf.fonttype": 42,
    "savefig.dpi": 300,
})


def load(fn):
    with open(os.path.join(R, fn), encoding="utf-8") as f:
        return json.load(f)


p51 = load("phase51_cot_firewall_ablation_v1.json")
p52 = load("phase52_d23prime_d30_two_layer_stack_v1.json")
p53 = load("phase53_displacement_countermeasure_v1.json")
p55 = load("phase55_real_calibrated_defense_v1.json")

COT = "#c0392b"      # red (leak)
FINAL = "#2e86c1"    # blue
UNION = "#7d3c98"    # purple
TAU = "#117a65"      # teal
GRAY = "#7f8c8d"
GOLD = "#b7950b"

# ---------------------------------------------------------------- Fig 1
# Measurement framework schematic (no data -- structural diagram).
fig, ax = plt.subplots(figsize=(7.2, 3.4))
ax.set_xlim(0, 10)
ax.set_ylim(0, 5.2)
ax.axis("off")


def box(x, y, w, h, text, fc="#fdf6e3", ec="#34495e", fs=9.5, lw=1.1):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.06",
                                fc=fc, ec=ec, lw=lw))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, color="#1b2631", linespacing=1.25)


def arrow(x1, y1, x2, y2, style="-|>", lw=1.2, color="#34495e"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                 mutation_scale=12, lw=lw, color=color))


box(0.15, 3.15, 1.35, 0.95, "Attacker\nprompt", fc="#ffffff", ec="#c0392b")
box(1.85, 3.15, 1.6, 0.95, "Input-side\ngateway\n(content safety)", fc="#ffffff", ec="#d4ac0d")
box(3.75, 3.15, 1.7, 0.95, "LLM\n(reasoning model)", fc="#ffffff", ec="#2e86c1")
box(5.75, 4.05, 1.75, 0.75, "reasoning\nchannel", fc="#ffffff", ec="#c0392b")
box(5.75, 2.5, 1.75, 0.75, "final answer\nchannel", fc="#ffffff", ec="#2e86c1")
box(7.7, 4.05, 1.55, 0.75, "output-side\nfilter", fc="#ffffff", ec="#d4ac0d")
box(7.7, 2.5, 1.55, 0.75, "literal scrub\n$\\tau$", fc="#ffffff", ec="#117a65")
box(5.75, 0.55, 1.75, 0.95, "SQL / tool\nexecution on\nhoneypot database", fc="#ffffff", ec="#7f8c8d")
box(7.7, 0.55, 1.7, 0.95, "Consumer\n(channel visibility\n$p_{cot}$)", fc="#ffffff", ec="#7d3c98")

arrow(1.5, 3.62, 1.85, 3.62)
arrow(3.45, 3.62, 3.75, 3.62)
arrow(5.45, 3.9, 5.75, 4.42)
arrow(5.45, 3.35, 5.75, 2.87)
arrow(7.5, 4.42, 7.7, 4.42)
arrow(7.5, 2.87, 7.7, 2.87)
arrow(4.6, 3.15, 5.75, 1.1)

arrow(8.65, 2.5, 8.65, 1.5)
arrow(7.5, 1.025, 7.7, 1.025)
ax.text(4.3, 2.3, "tool calls", fontsize=8.5, color=GRAY, rotation=90)
fig.savefig(os.path.join(F, "fig1_framework.pdf"), bbox_inches="tight")
plt.close(fig)

# ---------------------------------------------------------------- Fig 2
# Defense correlation: measured discount factor vs rho (product/min law
# validation cell pair qa=0.221, qb=0.1513), the original Phase-47 anchor,
# and the achievable bound.
pair = p52["results"]["self_checks"]["product_and_min_law"]["per_pair"]["qa=0.2210__qb=0.1513"]
rhos = [v["rho"] for v in pair.values()]
disc = [v["discount_factor"] for v in pair.values()]
rc = p52["results"]["rho_calibration"]

fig, ax = plt.subplots(figsize=(3.6, 3.0))
ax.plot(rhos, disc, "o-", color=COT, lw=1.6, ms=5,
        label="measured discount")
ax.axhline(rc["clean_gap_at_rho1"], ls="--", color=GRAY, lw=1.2,
           label=f"upper bound {rc['clean_gap_at_rho1']:.2f}$\\times$")
ax.axhline(rc["phase47_anchor_gap"], ls=":", color=GOLD, lw=1.5,
           label=f"previously reported {rc['phase47_anchor_gap']:.2f}$\\times$")
ax.axhline(p52["results"]["deployed_summary"]["discount_factor_at_rho_eff"],
           ls="-.", color=TAU, lw=1.2,
           label=f"measured $\\rho$=1 {p52['results']['deployed_summary']['discount_factor_at_rho_eff']:.2f}$\\times$")
ax.set_xlabel("shared-blindspot coefficient $\\rho$")
ax.set_ylabel("joint residual $\\div$ product prediction")
ax.legend(loc="upper left", fontsize=7.5, framealpha=0.95, ncol=2, bbox_to_anchor=(0.0, 0.86))
ax.grid(alpha=0.3)
fig.savefig(os.path.join(F, "fig2_correlation.pdf"), bbox_inches="tight")
plt.close(fig)

# ---------------------------------------------------------------- Fig 3
# Output-side filtering sweep: CoT-effective, final-effective and union leak
# rates vs strictness s; tau countermeasure markers at s=1.
anchors = p53["results"]["anchors"]
ss = sorted(anchors.keys(), key=float)
cot_s = [anchors[s]["cot_eff_leak_rate"] for s in ss]
fin_s = [anchors[s]["final_eff_leak_rate"] for s in ss]
cvu = p53["results"]["cot_metric_vs_union"]
union_s = [p53["results"]["base_union_rate"] - cvu[s]["union_leak_reduction"] for s in ss]
g10 = p53["results"]["grid"]["1.0"]
union_tau1 = g10["1.0"]["rate"]["union"]
union_floor = g10["1.0"]["rate"]["union_floor"]

fig, ax = plt.subplots(figsize=(7.0, 3.1))
ax.plot([float(s) for s in ss], cot_s, "o-", color=COT, lw=1.6, ms=4.5,
        label="CoT-effective leak")
ax.plot([float(s) for s in ss], fin_s, "s-", color=FINAL, lw=1.6, ms=4.5,
        label="final-effective leak")
ax.plot([float(s) for s in ss], union_s, "^-", color=UNION, lw=1.6, ms=4.5,
        label="union leak")
ax.plot([1.0], [union_tau1 + 0.008], "*", color=TAU, ms=10,
        label=f"$\\tau$ scrub {union_tau1*100:.1f}%")
ax.axhline(union_floor, ls=":", color=GRAY, lw=1.1,
           label=f"residual floor {union_floor*100:.1f}%")
ax.set_xlabel("output-filter strictness $s$")
ax.set_ylabel("leak rate")
ax.legend(loc="upper right", fontsize=7.5, framealpha=0.95, ncol=2)
ax.grid(alpha=0.3)
ax.set_ylim(0, 0.65)
fig.savefig(os.path.join(F, "fig3_output_filter.pdf"), bbox_inches="tight")
plt.close(fig)

# ---------------------------------------------------------------- Fig 4
# Simulated vs real per-attack-mode CoT leak rates.
r0 = p55["results"]["r0_sim_vs_real"]
modes = ["prefix_extraction", "step_reconstruction", "tool_injection",
         "reasoning_escalation", "thinking_leak"]
labels = ["prefix\nextract", "step\nreconstr.", "tool\ninject", "reasoning\nescalat.", "thinking\nleak"]
sim = [r0[m]["sim_phase49"] for m in modes]
real = [r0[m]["real_b1b3"] for m in modes]
x = range(len(modes))
w = 0.38
fig, ax = plt.subplots(figsize=(3.6, 3.3))
ax.bar([i - w / 2 for i in x], sim, w, color=GRAY, label="simulated")
ax.bar([i + w / 2 for i in x], real, w, color=COT,
       label="real model (n=112)")
ax.set_xticks(list(x))
ax.set_xticklabels(labels, fontsize=8.5)
ax.set_ylabel("CoT leak rate")
ax.set_ylim(0, 0.65)
ax.legend(fontsize=8.5, loc="lower center", ncol=2, bbox_to_anchor=(0.5, 1.02))
ax.grid(alpha=0.3, axis="y")
for i, (a, b) in enumerate(zip(sim, real)):
    ax.text(i - w / 2, a + 0.008, f"{a*100:.1f}", ha="center", fontsize=8.5, color="#566573")
    if b > 0.001:
        ax.text(i + w / 2, b + 0.008, f"{b*100:.1f}", ha="center", fontsize=8.5, color=COT)
fig.savefig(os.path.join(F, "fig4_sim_vs_real.pdf"), bbox_inches="tight")
plt.close(fig)

print("figures written to", F)
for fn in sorted(os.listdir(F)):
    print(" ", fn, os.path.getsize(os.path.join(F, fn)), "bytes")
