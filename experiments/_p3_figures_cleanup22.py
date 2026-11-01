"""Pass-22 figure cleanup: fix overlap/occlusion + remove AI-style drawing conventions.

Based on visual inspection of all 7 rendered PNGs. Each fix targets a specific
overlap/occlusion observed in the rendered output, plus AI-typical styling.

Rules addressed:
1. 去除AI味道 — pastel fills → white fills with colored borders (fig1);
   large infographic markers → smaller academic markers (fig8).
2. 不能有重叠 — legends repositioned to clear areas; x-labels shortened (fig7a).
3. 不能有遮掩 — legends moved outside plot area where internal placement
   inevitably occludes data (fig3, fig6); label offsets increased (fig8).
4. 不能内嵌标题 — already done in Pass-21.
5. 能清晰的展示 — all changes serve this.
"""
import os

BS = chr(92)
NL = chr(10)
EXP = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(EXP)

EDITS = [
    # ------------------------------------------------------------- fig1-4
    ("experiments/p3_figures_gen.py", [
        # ---- fig1: pastel fills → white fills with colored borders (AI-style removal)
        # Each box() call: change fc= pastel color to fc="#ffffff", add ec= border color
        # Box 1: Attacker prompt  fc="#fadbd8" → white, ec="#c0392b"
        (
            'box(0.15, 3.15, 1.35, 0.95, "Attacker\\nprompt", fc="#fadbd8")',
            'box(0.15, 3.15, 1.35, 0.95, "Attacker\\nprompt", fc="#ffffff", ec="#c0392b")',
        ),
        # Box 2: Input-side gateway  fc="#fef9e7" → white, ec="#d4ac0d"
        (
            'box(1.85, 3.15, 1.6, 0.95, "Input-side\\ngateway\\n(content safety)", fc="#fef9e7")',
            'box(1.85, 3.15, 1.6, 0.95, "Input-side\\ngateway\\n(content safety)", fc="#ffffff", ec="#d4ac0d")',
        ),
        # Box 3: LLM  fc="#ebf5fb" → white, ec="#2e86c1"
        (
            'box(3.75, 3.15, 1.7, 0.95, "LLM\\n(reasoning model)", fc="#ebf5fb")',
            'box(3.75, 3.15, 1.7, 0.95, "LLM\\n(reasoning model)", fc="#ffffff", ec="#2e86c1")',
        ),
        # Box 4: reasoning_content channel  fc="#fadbd8" → white, ec="#c0392b"
        (
            'box(5.75, 4.05, 1.75, 0.75, "reasoning_content\\nchannel", fc="#fadbd8")',
            'box(5.75, 4.05, 1.75, 0.75, "reasoning_content\\nchannel", fc="#ffffff", ec="#c0392b")',
        ),
        # Box 5: final answer channel  fc="#d6eaf8" → white, ec="#2e86c1"
        (
            'box(5.75, 2.5, 1.75, 0.75, "final answer\\nchannel", fc="#d6eaf8")',
            'box(5.75, 2.5, 1.75, 0.75, "final answer\\nchannel", fc="#ffffff", ec="#2e86c1")',
        ),
        # Box 6: output filter D30  fc="#fef9e7" → white, ec="#d4ac0d"
        (
            'box(7.8, 4.05, 1.55, 0.75, "output filter\\nD30 (s)", fc="#fef9e7")',
            'box(7.8, 4.05, 1.55, 0.75, "output filter\\nD30 (s)", fc="#ffffff", ec="#d4ac0d")',
        ),
        # Box 7: literal scrub tau  fc="#e8f6f3" → white, ec="#117a65"
        (
            'box(7.8, 2.5, 1.55, 0.75, "literal scrub\\n$\\\\tau$", fc="#e8f6f3")',
            'box(7.8, 2.5, 1.55, 0.75, "literal scrub\\n$\\\\tau$", fc="#ffffff", ec="#117a65")',
        ),
        # Box 8: SQL/tool execution  fc="#eaecee" → white, ec="#7f8c8d"
        (
            'box(5.75, 0.55, 1.75, 0.95, "SQL / tool\\nexecution on\\nhoneypot DB", fc="#eaecee")',
            'box(5.75, 0.55, 1.75, 0.95, "SQL / tool\\nexecution on\\nhoneypot DB", fc="#ffffff", ec="#7f8c8d")',
        ),
        # Box 9: Consumer  fc="#f4ecf7" → white, ec="#7d3c98"
        (
            'box(7.8, 0.55, 1.7, 0.95, "Consumer\\n(channel visibility\\n$p_{cot}$)", fc="#f4ecf7")',
            'box(7.8, 0.55, 1.7, 0.95, "Consumer\\n(channel visibility\\n$p_{cot}$)", fc="#ffffff", ec="#7d3c98")',
        ),
        # ---- fig1: move "tool calls" text further from arrow (x 4.98 → 5.25)
        (
            'ax.text(4.98, 2.3, "tool calls", fontsize=8.5, color=GRAY, rotation=90)',
            'ax.text(5.25, 2.3, "tool calls", fontsize=8.5, color=GRAY, rotation=90)',
        ),
        # ---- fig2: legend upper-right (overlaps gold line at y=7.63) → upper-left
        (
            'ax.legend(loc="upper right", fontsize=8.2, framealpha=0.95)',
            'ax.legend(loc="upper left", fontsize=8.2, framealpha=0.95)',
        ),
        # ---- fig3: legend upper-right (overlaps purple union line + tau star) →
        #      place outside plot to the right
        (
            'ax.legend(loc="upper right", framealpha=0.95)',
            'ax.legend(loc="upper left", fontsize=8, framealpha=0.95, '
            'bbox_to_anchor=(1.0, 1.0))',
        ),
        # fig3: make room for legend to the right
        (
            'fig, ax = plt.subplots(figsize=(7.0, 3.1))',
            'fig, ax = plt.subplots(figsize=(7.0, 3.1))\n'
            'fig.subplots_adjust(right=0.82)',
        ),
        # ---- fig4: legend lower-left (overlaps first group bars) →
        #      place below plot, two columns
        (
            'ax.legend(fontsize=8.5, loc="lower left")',
            'ax.legend(fontsize=8.5, loc="upper center", ncol=2, '
            'bbox_to_anchor=(0.5, -0.18))',
        ),
        # fig4: increase height to make room for legend below
        (
            'fig, ax = plt.subplots(figsize=(3.6, 2.7))',
            'fig, ax = plt.subplots(figsize=(3.6, 3.3))\n'
            'fig.subplots_adjust(bottom=0.20)',
        ),
    ]),
    # ------------------------------------------------------------- fig6
    ("experiments/e6_report_gen.py", [
        # fig6: legend upper-left (overlaps thinking-leak data) →
        #       place outside plot to the right
        (
            'ax.legend(loc="upper left", framealpha=0.95)',
            'ax.legend(loc="upper left", fontsize=8, framealpha=0.95, '
            'bbox_to_anchor=(1.0, 1.0))',
        ),
        # fig6: make room for legend to the right
        (
            'fig, ax = plt.subplots(figsize=(5.6, 3.6))',
            'fig, ax = plt.subplots(figsize=(5.6, 3.6))\n'
            'fig.subplots_adjust(right=0.82)',
        ),
    ]),
    # ------------------------------------------------------------- fig7
    ("experiments/e4_report_gen.py", [
        # fig7 panel (a): x-labels overlap → shorten to single-line abbreviations
        (
            'ax1.set_xticklabels([ARM_EN[a].replace(" (raw)", "\\n(raw)")\n'
            '                         for a in keys], fontsize=8.5)',
            'ax1.set_xticklabels([ARM_EN[a].replace(" (raw)", "")\n'
            '                         for a in keys], fontsize=8.5)',
        ),
        # fig7 panel (b): legend lower-right (overlaps D30/tau lines at y=0) →
        #       upper-left (clear of all lines since they start at y=0)
        (
            'ax2.legend(fontsize=8.5, loc="lower right", framealpha=0.95)',
            'ax2.legend(fontsize=8.5, loc="upper left", framealpha=0.95)',
        ),
    ]),
    # ------------------------------------------------------------- fig8
    ("experiments/e1_figures_gen.py", [
        # fig8: "62.5%" label at y=0.555 overlaps reference line at y=0.536 →
        #       increase offset from -0.12 to -0.18
        (
            'ax.text(x, r + (0.10 if r < 0.5 else -0.12), "%.1f%%" % (100 * r),',
            'ax.text(x, r + (0.10 if r < 0.5 else -0.18), "%.1f%%" % (100 * r),',
        ),
        # fig8: large infographic markers (s=130) → smaller academic markers (s=70)
        (
            'ax.scatter(xs, rates, s=130, c=colors, zorder=3, edgecolors="#222222",\n'
            '               linewidths=0.8)',
            'ax.scatter(xs, rates, s=70, c=colors, zorder=3, edgecolors="#222222",\n'
            '               linewidths=0.6)',
        ),
        # fig8: restore top/right spines (removed in original → AI-chart style)
        (
            'ax.spines["top"].set_visible(False)\n'
            '    ax.spines["right"].set_visible(False)',
            '',
        ),
    ]),
]


def apply_edits(rel_path, pairs):
    fp = os.path.join(ROOT, rel_path)
    with open(fp, encoding="utf-8") as f:
        s = f.read()
    for i, (old, new) in enumerate(pairs):
        c = s.count(old)
        if c != 1:
            raise SystemExit(
                "ABORT %s edit #%d: found %d occurrences (need 1):\nOLD=%r"
                % (rel_path, i, c, old[:150]))
        s = s.replace(old, new, 1)
    if s.count("{") != s.count("}"):
        raise SystemExit("ABORT %s: brace imbalance after edits" % rel_path)
    tmp = fp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, fp)
    print("OK %s  (%d edits, %d bytes)" % (rel_path, len(pairs), os.path.getsize(fp)))


for rel, pairs in EDITS:
    apply_edits(rel, pairs)

print("\nAll figure generators updated (Pass-22).")