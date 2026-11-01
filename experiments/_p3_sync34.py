"""Sync submission_2026-10-21 with the Pass-34 rebuild."""
import os, shutil

ROOT = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval"
SUB = os.path.join(ROOT, "submission_2026-10-21")
PAPER = os.path.join(ROOT, "paper")
FIGS = ["fig1_framework.pdf", "fig2_correlation.pdf", "fig3_output_filter.pdf",
        "fig4_sim_vs_real.pdf", "fig6_e6_confidence.pdf",
        "fig7_e4_consumer_channel.pdf", "fig8_e1_cross_model.pdf"]

shutil.copy2(os.path.join(PAPER, "p3_tifs.tex"), os.path.join(SUB, "p3_tifs.tex"))
shutil.copy2(os.path.join(PAPER, "p3_tifs.pdf"), os.path.join(SUB, "p3_tifs.pdf"))
for ext in (".aux", ".log", ".out"):
    src = os.path.join(PAPER, "p3_tifs" + ext)
    if os.path.exists(src):
        shutil.copy2(src, os.path.join(SUB, "p3_tifs" + ext))
for f in FIGS:
    shutil.copy2(os.path.join(PAPER, "figures", f), os.path.join(SUB, "figures", f))

# orphan figures (never referenced by the paper) removed from the submission copy
for f in ("fig5_e2_baseline.pdf", "fig5b_e2_real_schema_hiding.pdf"):
    p = os.path.join(SUB, "figures", f)
    if os.path.exists(p):
        os.remove(p)
        print("removed orphan", f)

print("synced files:")
for root, _, files in os.walk(SUB):
    for f in sorted(files):
        p = os.path.join(root, f)
        print("  %-24s %8d bytes" % (os.path.relpath(p, SUB), os.path.getsize(p)))
