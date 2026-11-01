"""Pass-21 figure cleanup: apply 5 rules to all 7 submission figures.

Rules:
1. 去除AI味道 (remove AI-flavored labels)
2. 不能有重叠 (no overlapping elements)
3. 不能有遮掩 (no occlusion/masking)
4. 不能内嵌标题 (no embedded titles)
5. 能清晰的展示要展示的内容 (clearly show intended content)

Edits 4 generators: p3_figures_gen.py (fig1-4), e6_report_gen.py (fig6),
e4_report_gen.py (fig7), e1_figures_gen.py (fig8).
"""
import os

BS = chr(92)
NL = chr(10)
EXP = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(EXP)

# Each entry: (relative_path, [(old, new), ...])
EDITS = [
    # ------------------------------------------------------------- fig1-4
    ("experiments/p3_figures_gen.py", [
        # fig1: move "tool calls" text right to clear the vertical arrow at x=4.6
        (
            'ax.text(4.72, 2.3, "tool calls", fontsize=8.5, color=GRAY, rotation=90)',
            'ax.text(4.98, 2.3, "tool calls", fontsize=8.5, color=GRAY, rotation=90)',
        ),
        # fig2: AI-flavored legend labels
        (
            'label=f"achievable bound {rc[\'clean_gap_at_rho1\']:.2f}$\\\\times$"',
            'label=f"upper bound {rc[\'clean_gap_at_rho1\']:.2f}$\\\\times$"',
        ),
        (
            'label=f"errata report {rc[\'phase47_anchor_gap\']:.2f}$\\\\times$"',
            'label=f"Phase-47 anchor {rc[\'phase47_anchor_gap\']:.2f}$\\\\times$"',
        ),
        (
            'label=f"deployment $\\\\rho$=1 {p52[\'results\'][\'deployed_summary\'][\'discount_factor_at_rho_eff\']:.2f}$\\\\times$"',
            'label=f"measured $\\\\rho$=1 {p52[\'results\'][\'deployed_summary\'][\'discount_factor_at_rho_eff\']:.2f}$\\\\times$"',
        ),
        # fig2: legend position lower-left -> upper-right (clear of data points)
        (
            'ax.legend(loc="lower left", fontsize=8.2, framealpha=0.95)',
            'ax.legend(loc="upper right", fontsize=8.2, framealpha=0.95)',
        ),
        # fig3: AI-flavored labels
        (
            'label=f"$\\\\tau$-countermeasure {union_tau1*100:.1f}%"',
            'label=f"$\\\\tau$ scrub {union_tau1*100:.1f}%"',
        ),
        (
            'label=f"irreducible floor {union_floor*100:.1f}%"',
            'label=f"residual floor {union_floor*100:.1f}%"',
        ),
        # fig3: legend position center-left -> upper-right (clear of CoT line)
        (
            'ax.legend(loc="center left", framealpha=0.95)',
            'ax.legend(loc="upper right", framealpha=0.95)',
        ),
        # fig4: legend position upper-right -> lower-left (clear of tallest bar)
        (
            'ax.legend(fontsize=8.5, loc="upper right")',
            'ax.legend(fontsize=8.5, loc="lower left")',
        ),
    ]),
    # ------------------------------------------------------------- fig6
    ("experiments/e6_report_gen.py", [
        # fig6: legend position lower-right -> upper-left (clear of data points)
        (
            'ax.legend(loc="lower right", framealpha=0.95)',
            'ax.legend(loc="upper left", framealpha=0.95)',
        ),
    ]),
    # ------------------------------------------------------------- fig7
    ("experiments/e4_report_gen.py", [
        # fig7 panel (a): remove second title line (embedded-title rule)
        (
            'ax1.set_title("(a) Paired defense comparison\\n(stratum: CoT-leaking responses)",',
            'ax1.set_title("(a) Paired defense comparison",',
        ),
        # fig7 panel (b): legend upper-left -> lower-right (clear of line starts)
        (
            'ax2.legend(fontsize=8.5, loc="upper left", framealpha=0.95)',
            'ax2.legend(fontsize=8.5, loc="lower right", framealpha=0.95)',
        ),
    ]),
    # ------------------------------------------------------------- fig8
    ("experiments/e1_figures_gen.py", [
        # fig8: remove embedded title
        (
            'ax.set_title("Cross-vendor CoT blind spot replication",' + NL +
            '             fontsize=12, pad=8)' + NL +
            '    fig.tight_layout(pad=0.6)',
            'fig.tight_layout(pad=0.6)',
        ),
        # fig8: increase annotation offset to clear error bars
        (
            'ax.text(x, r + (0.06 if r < 0.5 else -0.07), "%.1f%%" % (100 * r),',
            'ax.text(x, r + (0.10 if r < 0.5 else -0.12), "%.1f%%" % (100 * r),',
        ),
        # fig8: increase reference-line text offset to clear error bars
        (
            'ax.text(len(comps) - 0.5, ref_rate + 0.04,',
            'ax.text(len(comps) - 0.5, ref_rate + 0.08,',
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
                % (rel_path, i, c, old[:120]))
        s = s.replace(old, new, 1)
    # brace balance check
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

print("\nAll figure generators updated.")