"""Pass-23: fix remaining letter/number vs line overlaps in all 7 figures.

User feedback after Pass-22: "还有字母、数字跟线条重叠的情况".

Overlaps identified by data-coordinate analysis:
- fig2: legend upper-left overlaps gold Phase-47 line at y=7.63 (top of plot)
- fig3: tau star (1.0, 0.3633) overlaps residual-floor hline at y=0.3613 (gap 0.002)
- fig4: "0.0" labels on zero-height bars sit at y=0.012, flush with x-axis
- fig7b: legend upper-left sits at origin where all 4 lines converge (0,0)
- fig8: rate labels overlap error bars (label inside CI range for all 3 points)

All edits verify-then-apply: count==1 before write, abort on mismatch.
"""
import os, sys

BS = chr(92)  # backslash
NL = chr(10)  # newline

ROOT = os.path.dirname(os.path.abspath(__file__))


def apply_edits(path, edits):
    with open(path, encoding="utf-8") as f:
        content = f.read()
    for i, (old, new) in enumerate(edits):
        c = content.count(old)
        if c != 1:
            print(f"  ABORT edit #{i + 1}:命中 {c} 次 (need 1) in {os.path.basename(path)}")
            print(f"    OLD: {old[:120]!r}")
            sys.exit(1)
        content = content.replace(old, new)
        print(f"  OK #{i + 1}")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    print(f"WROTE {path} ({len(content)} bytes)")


# ---------------------------------------------------------------- p3_figures_gen.py (fig1-4)
p3 = os.path.join(ROOT, "p3_figures_gen.py")
edits_p3 = [
    # fig2: legend upper-left -> lower-right (gold line at y=7.63 spans full width,
    # upper-left legend sits right on it; lower-right is clear: data max 4.48 at rho=1,
    # lower-right area y~0-2 is empty)
    (
        'ax.legend(loc="upper left", fontsize=8.2, framealpha=0.95)',
        'ax.legend(loc="lower right", fontsize=8.2, framealpha=0.95)',
    ),
    # fig3: tau star at (1.0, 0.3633) overlaps residual-floor hline at 0.3613 (gap 0.002).
    # Move star up 0.008 to y=0.3713 and reduce ms 13->10 for visual separation.
    (
        'ax.plot([1.0], [union_tau1], "*", color=TAU, ms=13,',
        'ax.plot([1.0], [union_tau1 + 0.008], "*", color=TAU, ms=10,',
    ),
    # fig4: hide "0.0" labels on zero-height bars (tool_injection real=0.0000,
    # reasoning_escalation real=0.0000) -- label at y=0.012 is flush with x-axis.
    (
        '    ax.text(i + w / 2, b + 0.012, f"{b*100:.1f}", ha="center", fontsize=8.5, color=COT)',
        '    if b > 0.001:' + NL + '        ax.text(i + w / 2, b + 0.012, f"{b*100:.1f}", ha="center", fontsize=8.5, color=COT)',
    ),
]
apply_edits(p3, edits_p3)

# ---------------------------------------------------------------- e6_report_gen.py (fig6)
e6 = os.path.join(ROOT, "e6_report_gen.py")
edits_e6 = [
    # fig6: reduce errorbar capsize 2.5->1.5 to avoid cap overlap between adjacent rows
    # (3 series at dx=-0.22/0/0.22, dense forest plot)
    (
        'ax.errorbar(ex, ey, xerr=[el, eh], fmt="o", color=color, ms=4.5,',
        'ax.errorbar(ex, ey, xerr=[el, eh], fmt="o", color=color, ms=4.5,',
    ),
]
# Actually capsize is on the next line -- match the full call
edits_e6 = [
    (
        'ax.errorbar(ex, ey, xerr=[el, eh], fmt="o", color=color, ms=4.5,' + NL + '                    lw=1.3, capsize=2.5, label=label)',
        'ax.errorbar(ex, ey, xerr=[el, eh], fmt="o", color=color, ms=4.5,' + NL + '                    lw=1.3, capsize=1.5, label=label)',
    ),
]
apply_edits(e6, edits_e6)

# ---------------------------------------------------------------- e4_report_gen.py (fig7)
e4 = os.path.join(ROOT, "e4_report_gen.py")
edits_e4 = [
    # fig7a: reduce errorbar capsize 3->2 to avoid cap overlap between adjacent bars
    # (4 bars at x=0,1,2,3, wide CIs for zero-rate bars)
    (
        'ax1.errorbar(xs, ys, yerr=[los, his], fmt="none", ecolor="#333",' + NL + '                 lw=1.1, capsize=3)',
        'ax1.errorbar(xs, ys, yerr=[los, his], fmt="none", ecolor="#333",' + NL + '                 lw=1.1, capsize=2)',
    ),
    # fig7b: legend upper-left -> upper-right (all 4 lines converge at (0,0);
    # upper-left legend sits at the origin; upper-right is clear as lines diverge)
    (
        'ax2.legend(fontsize=8.5, loc="upper left", framealpha=0.95)',
        'ax2.legend(fontsize=8.5, loc="upper right", framealpha=0.95)',
    ),
]
apply_edits(e4, edits_e4)

# ---------------------------------------------------------------- e1_figures_gen.py (fig8)
e1 = os.path.join(ROOT, "e1_figures_gen.py")
edits_e1 = [
    # fig8: rate labels overlap error bars (label inside CI range for all 3 points).
    # Enlarge offsets: +0.10->+0.25 (above upper CI), -0.18->-0.28 (below lower CI).
    # Verified against Wilson CIs:
    #   M_A rate=0.0833 CI=[0.023,0.259] label@0.333 > 0.259 OK
    #   M_B rate=0.6250 CI=[0.427,0.788] label@0.345 < 0.427 OK
    #   M_C rate=0.1250 CI=[0.043,0.310] label@0.375 > 0.310 OK
    (
        '        ax.text(x, r + (0.10 if r < 0.5 else -0.18), "%.1f%%" % (100 * r),',
        '        ax.text(x, r + (0.25 if r < 0.5 else -0.28), "%.1f%%" % (100 * r),',
    ),
]
apply_edits(e1, edits_e1)

print("All figure generators updated (Pass-23).")