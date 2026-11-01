"""Pass-25: fix the 5 red-boxed overlap/occlusion/crossing-frame issues.

fig1: 3 right-side boxes 7.8->7.7 (clear frame-hugging arrows at x=9.35);
      vertical LLM->SQL arrow -> clean diagonal (4.6,3.15)->(5.75,1.1);
      drop redundant short horizontal arrow (5.45->5.75) and redundant
      literal-scrub->Consumer arrow at x=9.35 (keep the one at x=8.65);
      "tool calls" text 5.25->4.3 (clear of the diagonal).
fig2: legend lower-right (overlapped by red data line) -> upper-left,
      ncol=2, fontsize 8.2->7.5, bbox_to_anchor=(0.0,0.86).
fig3: legend overlapped by purple union line -> ncol=2, fontsize 8->7.5;
      ylim 0.62->0.65.
fig4: "58.9" label crossing top frame -> ylim 0->0.65, label offset 0.012->0.008.
fig7a: overlapping xticklabels -> rotate 30 deg, ha=right.
All verify-then-apply; abort (no write) if any OLD not matched exactly once.
"""
import os

BASE = "C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/experiments"

PATCHES = [
    (os.path.join(BASE, "p3_figures_gen.py"), [
        # ---- fig1: move 3 right-side boxes 7.8 -> 7.7 ----
        ('box(7.8, 4.05, 1.55, 0.75, "output filter\\nD30 (s)", fc="#ffffff", ec="#d4ac0d")',
         'box(7.7, 4.05, 1.55, 0.75, "output filter\\nD30 (s)", fc="#ffffff", ec="#d4ac0d")'),
        ('box(7.8, 2.5, 1.55, 0.75, "literal scrub\\n$\\\\tau$", fc="#ffffff", ec="#117a65")',
         'box(7.7, 2.5, 1.55, 0.75, "literal scrub\\n$\\\\tau$", fc="#ffffff", ec="#117a65")'),
        ('box(7.8, 0.55, 1.7, 0.95, "Consumer\\n(channel visibility\\n$p_{cot}$)", fc="#ffffff", ec="#7d3c98")',
         'box(7.7, 0.55, 1.7, 0.95, "Consumer\\n(channel visibility\\n$p_{cot}$)", fc="#ffffff", ec="#7d3c98")'),
        # ---- fig1: arrows from the left follow the boxes ----
        ('arrow(7.5, 4.42, 7.8, 4.42)', 'arrow(7.5, 4.42, 7.7, 4.42)'),
        ('arrow(7.5, 2.87, 7.8, 2.87)', 'arrow(7.5, 2.87, 7.7, 2.87)'),
        # ---- fig1: replace vertical LLM->SQL arrow + drop 2 redundant arrows ----
        ('arrow(4.6, 3.15, 4.6, 1.5)\n'
         'arrow(5.45, 1.02, 5.75, 1.02)\n'
         'arrow(9.35, 4.05, 9.35, 3.25)\n'
         'arrow(9.35, 2.5, 9.35, 1.5)\n'
         'arrow(8.65, 2.5, 8.65, 1.5)',
         'arrow(4.6, 3.15, 5.75, 1.1)\n'
         'arrow(9.35, 4.05, 9.35, 3.25)\n'
         'arrow(8.65, 2.5, 8.65, 1.5)'),
        # ---- fig1: "tool calls" text clear of the diagonal ----
        ('ax.text(5.25, 2.3, "tool calls", fontsize=8.5, color=GRAY, rotation=90)',
         'ax.text(4.3, 2.3, "tool calls", fontsize=8.5, color=GRAY, rotation=90)'),
        # ---- fig2: legend lower-right (overlapped by data line) -> upper-left ----
        ('ax.legend(loc="lower right", fontsize=8.2, framealpha=0.95)',
         'ax.legend(loc="upper left", fontsize=7.5, framealpha=0.95, ncol=2, bbox_to_anchor=(0.0, 0.86))'),
        # ---- fig3: legend overlapped by purple union line -> 2 col + ylim ----
        ('ax.set_ylim(0, 0.62)', 'ax.set_ylim(0, 0.65)'),
        ('ax.legend(loc="upper right", fontsize=8, framealpha=0.95)',
         'ax.legend(loc="upper right", fontsize=7.5, framealpha=0.95, ncol=2)'),
        # ---- fig4: "58.9" label crossing top frame ----
        ('ax.set_ylabel("CoT leak rate")\n'
         'ax.legend(fontsize=8.5, loc="lower center", ncol=2, bbox_to_anchor=(0.5, 1.02))',
         'ax.set_ylabel("CoT leak rate")\n'
         'ax.set_ylim(0, 0.65)\n'
         'ax.legend(fontsize=8.5, loc="lower center", ncol=2, bbox_to_anchor=(0.5, 1.02))'),
        ('ax.text(i - w / 2, a + 0.012, f"{a*100:.1f}", ha="center", fontsize=8.5, color="#566573")',
         'ax.text(i - w / 2, a + 0.008, f"{a*100:.1f}", ha="center", fontsize=8.5, color="#566573")'),
        ('ax.text(i + w / 2, b + 0.012, f"{b*100:.1f}", ha="center", fontsize=8.5, color=COT)',
         'ax.text(i + w / 2, b + 0.008, f"{b*100:.1f}", ha="center", fontsize=8.5, color=COT)'),
    ]),
    (os.path.join(BASE, "e4_report_gen.py"), [
        # ---- fig7a: overlapping xticklabels -> rotate ----
        ('    ax1.set_xticklabels([ARM_EN[a].replace(" (raw)", "")\n'
         '                         for a in keys], fontsize=8.5)\n'
         '    ax1.set_ylabel("Downstream exposure rate")',
         '    ax1.set_xticklabels([ARM_EN[a].replace(" (raw)", "")\n'
         '                         for a in keys], fontsize=8.5)\n'
         '    plt.setp(ax1.get_xticklabels(), rotation=30, ha="right")\n'
         '    ax1.set_ylabel("Downstream exposure rate")'),
    ]),
]


def apply(path, edits):
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    n = 0
    for old, new in edits:
        c = data.count(old)
        if c != 1:
            raise SystemExit(f"ABORT {path}: OLD count={c}\n---OLD---\n{old}")
        data = data.replace(old, new)
        n += 1
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)
    print(f"OK {os.path.basename(path)} ({n} edits, {os.path.getsize(path)} bytes)")


for path, edits in PATCHES:
    apply(path, edits)
print("Pass-25 applied: 5 red-boxed issues fixed.")