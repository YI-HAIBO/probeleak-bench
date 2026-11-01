#!/usr/bin/env python3
"""Apply P1a/P1b-resolved text edits to paper/p3_tifs.tex (atomic, one pass)."""
import os
import sys

P = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"
s = open(P, encoding="utf-8").read()
NL = chr(10)

EDITS = [
    # --- Third-gateway paragraph: N_C resolved to clean ---------------------
    ("(an inverted baseline), and Atria-Dawn-Preview remains ambiguous" + NL
     + "(1/40 controls, $p=0.025$). Part of",
     "(an inverted baseline), and Atria-Dawn-Preview, the last backend left" + NL
     + "ambiguous at 1/40 controls, is resolved to clean by a further expansion" + NL
     + "to 64 controls: its control rate falls to 1/64 while its attack rate" + NL
     + "holds at 5/24 (Fisher $p=0.0053$). Part of"),
    # --- Limitations: classification 3/1/3 -> 4/1/2 ------------------------
    ("prompts more often than to attacks---a model-level property, not noise), and 3 as ambiguous" + NL
     + "(CIs overlap). The clean classifications for Agents-A1 and Atria-Dawn were obtained by" + NL
     + "expanding the control sample from 8 to 40 per model; Atria-Dawn-Preview remains" + NL
     + "ambiguous at 1/40 controls and would need approximately 58.",
     "prompts more often than to attacks---a model-level property, not noise), and 2 as ambiguous" + NL
     + "(CIs overlap). The clean classifications for Agents-A1 and Atria-Dawn were obtained by" + NL
     + "expanding the control sample from 8 to 40 per model, and Atria-Dawn-Preview, the last" + NL
     + "backend left ambiguous at 1/40 controls, was resolved by a further expansion to 64" + NL
     + "controls (1/64 controls versus 5/24 attack, Fisher $p=0.0053$)."),
    # --- Multi-gateway replication summary: three of seven -> four ---------
    ("clean probe-attributed comparisons; on the third gateway, three of seven" + NL
     + "backends are clean after control expansion, one is inverted, and three" + NL
     + "remain ambiguous.",
     "clean probe-attributed comparisons; on the third gateway, four of seven" + NL
     + "backends are clean after control expansion, one is inverted, and two" + NL
     + "remain ambiguous."),
]

for old, new in EDITS:
    n = s.count(old)
    if n != 1:
        print("ABORT: anchor matched %d times:" % n)
        print(repr(old[:90]))
        sys.exit(1)
    s = s.replace(old, new)

tmp = P + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as f:
    f.write(s)
os.replace(tmp, P)
print("applied %d edits OK; new size %d B" % (len(EDITS), len(s)))
