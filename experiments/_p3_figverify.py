"""Verify regenerated figures contain no internal codes; check key label strings."""
import os, re, fitz  # PyMuPDF

F = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\figures"
BAD = ["Phase-47", "P49", "B1+B3", "E6 batch", "M_A", "M_B", "M_C",
       "dots3-note-prev", "D30", "reasoning_content", "honeypot DB",
       "p_cot", "errata"]
ok = True
for fn in sorted(os.listdir(F)):
    if not fn.endswith(".pdf"):
        continue
    txt = fitz.open(os.path.join(F, fn)). load_page(0).get_text()
    hits = [b for b in BAD if b in txt]
    status = "CLEAN" if not hits else "HITS: %s" % hits
    if hits:
        ok = False
    print("%-38s %s" % (fn, status))

# expected new labels present
EXPECT = {
    "fig1_framework.pdf": ["reasoning", "output-side", "honeypot database"],
    "fig2_correlation.pdf": ["previously reported"],
    "fig4_sim_vs_real.pdf": ["simulated", "real model (n=112)"],
    "fig6_e6_confidence.pdf": ["second sample (N=112)", "third sample (N=84)", "pooled"],
    "fig7_e4_consumer_channel.pdf": ["output filter", "CoT-positive layer"],
    "fig8_e1_cross_model.pdf": ["Nemotron-3-Super", "Beam", "Nemotron-3-Nano",
                                "reference (primary model)"],
}
print()
for fn, keys in EXPECT.items():
    txt = fitz.open(os.path.join(F, fn)). load_page(0).get_text()
    miss = [k for k in keys if k not in txt]
    print("%-38s %s" % (fn, "ALL PRESENT" if not miss else "MISSING: %s" % miss))
    if miss:
        ok = False
print("\nRESULT:", "PASS" if ok else "FAIL")
