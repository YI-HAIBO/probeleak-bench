"""Pass-24: move every legend INSIDE the plot frame (user: 单词跨越边框).
fig3 legend: outside-right -> inside upper-right (clear zone y>0.48 at s in [0.8,1]).
fig4 legend: below frame -> above axes (centered, ncol=2).
fig6 legend: outside-right -> above axes (centered, ncol=3).
fig8 ref-line label: ended on right spine (x=2.5, ha=right) -> inside left end of line.
All verify-then-apply; abort (no file write) if any OLD not matched exactly once.
"""
import io, os, sys

BASE = "C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/experiments"

# (path, [(old, new), ...])
PATCHES = [
    (os.path.join(BASE, "p3_figures_gen.py"), [
        # fig3: drop outside-right margin (legend moves inside upper-right)
        ("fig, ax = plt.subplots(figsize=(7.0, 3.1))\n"
         "fig.subplots_adjust(right=0.82)\n"
         "ax.plot([float(s) for s in ss], cot_s, \"o-\", color=COT, lw=1.6, ms=4.5,\n",
         "fig, ax = plt.subplots(figsize=(7.0, 3.1))\n"
         "ax.plot([float(s) for s in ss], cot_s, \"o-\", color=COT, lw=1.6, ms=4.5,\n"),
        # fig3: legend inside upper-right (no bbox_to_anchor)
        ("ax.legend(loc=\"upper left\", fontsize=8, framealpha=0.95, bbox_to_anchor=(1.0, 1.0))",
         "ax.legend(loc=\"upper right\", fontsize=8, framealpha=0.95)"),
        # fig4: drop below-frame margin (legend moves above axes)
        ("fig, ax = plt.subplots(figsize=(3.6, 3.3))\n"
         "fig.subplots_adjust(bottom=0.20)\n",
         "fig, ax = plt.subplots(figsize=(3.6, 3.3))\n"),
        # fig4: legend above axes (centered, inside the figure, not below frame)
        ("ax.legend(fontsize=8.5, loc=\"upper center\", ncol=2, bbox_to_anchor=(0.5, -0.18))",
         "ax.legend(fontsize=8.5, loc=\"lower center\", ncol=2, bbox_to_anchor=(0.5, 1.02))"),
    ]),
    (os.path.join(BASE, "e6_report_gen.py"), [
        # fig6: drop outside-right margin (legend moves above axes)
        ("    fig, ax = plt.subplots(figsize=(5.6, 3.6))\n"
         "    fig.subplots_adjust(right=0.82)\n"
         "    ys = range(len(modes))\n",
         "    fig, ax = plt.subplots(figsize=(5.6, 3.6))\n"
         "    ys = range(len(modes))\n"),
        # fig6: legend above axes (centered, ncol=3)
        ("    ax.legend(loc=\"upper left\", fontsize=8, framealpha=0.95, bbox_to_anchor=(1.0, 1.0))",
         "    ax.legend(loc=\"lower center\", fontsize=8, framealpha=0.95, ncol=3, bbox_to_anchor=(0.5, 1.02))"),
    ]),
    (os.path.join(BASE, "e1_figures_gen.py"), [
        # fig8: explicit xlim so the inside ref label anchors within the frame
        ("    ax.set_ylim(-0.05, 1.0)\n"
         "    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])\n",
         "    ax.set_ylim(-0.05, 1.0)\n"
         "    ax.set_xlim(-0.6, 2.6)\n"
         "    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])\n"),
        # fig8: ref label -> inside, at left end of the dashed line (was x=2.5 ha=right on spine)
        ("    ax.text(len(comps) - 0.5, ref_rate + 0.08,\n"
         "            \"ref. dots3-note-prev %.1f%% (%d/%d)\" % (100 * ref_rate,\n"
         "                                                       ref_leaks, ref_n),\n"
         "            fontsize=9, color=\"#666666\", ha=\"right\")",
         "    ax.text(-0.45, ref_rate + 0.05,\n"
         "            \"ref. dots3-note-prev %.1f%% (%d/%d)\" % (100 * ref_rate,\n"
         "                                                       ref_leaks, ref_n),\n"
         "            fontsize=9, color=\"#666666\", ha=\"left\")"),
    ]),
]


def apply(path, edits):
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    n = 0
    for old, new in edits:
        c = data.count(old)
        if c != 1:
            raise SystemExit(f"ABORT {path}: OLD not matched exactly once (count={c})\n---OLD---\n{old}")
        data = data.replace(old, new)
        n += 1
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)
    print(f"OK {path} ({n} edits, {os.path.getsize(path)} bytes)")


for path, edits in PATCHES:
    apply(path, edits)
print("Pass-24 applied: all legends moved inside the plot frame.")
