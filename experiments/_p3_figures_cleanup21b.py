"""Pass-21 figure cleanup part 2: e4_report_gen.py (fig7) + e1_figures_gen.py (fig8).
p3_figures_gen.py and e6_report_gen.py already applied in cleanup21.py."""
import os

BS = chr(92)
NL = chr(10)
EXP = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(EXP)

EDITS = [
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
    ("experiments/e1_figures_gen.py", [
        # fig8: remove embedded title (3 lines -> 1 line)
        (
            '    ax.set_title("Cross-vendor CoT blind spot replication",' + NL +
            '                 fontsize=12, pad=8)' + NL +
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

print("\nRemaining figure generators updated.")