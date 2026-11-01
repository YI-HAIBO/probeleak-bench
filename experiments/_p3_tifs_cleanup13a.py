#!/usr/bin/env python3
"""Pass-13 cleanup A: Rule 1 (abstract: no formulas / code identifiers),
Rule 2 (keywords: 5, drop text-to-SQL), Rule 3 (Gap 1/2/3 labels -> plain).

verify-then-apply: every OLD must be present exactly once before any write.
"""
import os, sys

PATH = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"

pairs = [
    # ---- Rule 1: abstract -------------------------------------------------
    ("on 268 fresh-probe responses \\texttt{reasoning\\_content} leaks at 14.55\\%",
     "on 268 fresh-probe responses the reasoning channel leaks at 14.55\\%"),
    ("at 62.5\\% ($n=8$), and the pooled rate",
     "at 62.5\\% (eight requests), and the pooled rate"),
    ("stacking at 4.48$\\times$ the independence",
     "stacking at 4.48-fold the independence"),
    # ---- Rule 2: keywords --------------------------------------------------
    ("\\IEEEkeywords{Information forensics, LLM agent security, chain-of-thought\n"
     "leakage, credential exfiltration, defense composition, text-to-SQL}",
     "\\IEEEkeywords{Information forensics, LLM agent security, chain-of-thought\n"
     "leakage, credential exfiltration, defense composition}"),
    # ---- Rule 3: Gap labels ------------------------------------------------
    ("\\textbf{Gap 1: the reasoning channel is not measured separately.}",
     "\\textbf{The reasoning channel is not measured separately.}"),
    ("\\textbf{Gap 2: defense stacking is evaluated under an independence\n"
     "assumption.}",
     "\\textbf{Defense stacking is evaluated under an independence\n"
     "assumption.}"),
    ("\\textbf{Gap 3: simulation results are not calibrated against real models.}",
     "\\textbf{Simulation results are not calibrated against real models.}"),
]

with open(PATH, "r", encoding="utf-8") as f:
    text = f.read()

errors = []
for i, (old, new) in enumerate(pairs):
    n = text.count(old)
    if n != 1:
        errors.append(f"pair {i}: expected 1 occurrence, found {n}\nOLD={old!r}")

if errors:
    sys.stderr.write("VERIFY FAILED -- no write performed:\n")
    sys.stderr.write("\n".join(errors))
    sys.exit(1)

# apply
for old, new in pairs:
    text = text.replace(old, new, 1)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print(f"APPLIED {len(pairs)} replacements; new size {os.path.getsize(PATH)} bytes")