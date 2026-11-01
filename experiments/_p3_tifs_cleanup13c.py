#!/usr/bin/env python3
"""Pass-13 cleanup C: Rule 5 (self-invented abbreviations).
D30 -> the output-side filter; C0 / RAW -> the no-defense control;
reverse-effective -> refusal-removing.  (ProbeLeak-Bench kept as a release name;
it is a compound noun, not an abbreviation.)

verify-then-apply: every OLD must be present exactly once before any write.
Note-block occurrences of C0/D30 are handled in cleanup13d (note merge).
"""
import os, sys

PATH = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"

pairs = [
    # D30 -> the output-side filter
    ("of $\\tau$ (literal key redaction) and D30 (sentence-level output-side\n"
     "      suppression) collapses to",
     "of $\\tau$ (literal key redaction) and the output-side filter (sentence-level output-side\n"
     "      suppression) collapses to"),
    ("Output-side filtering (D30,\nparameterized by strictness $s$), literal redaction",
     "Output-side filtering (parameterized by strictness $s$), literal redaction"),
    ("discount of the two-layer $\\tau$+D30 stack comes from E7",
     "discount of the two-layer $\\tau$ and output-side filter stack comes from E7"),
    ("by applying $\\tau$ (full key redaction)\nand D30 (sentence-level suppression) to the complete reasoning traces",
     "by applying $\\tau$ (full key redaction) and the output-side filter (sentence-level suppression) to the complete reasoning traces"),
    ("both $\\tau$ and D30 reduced the string-level residual to zero",
     "both $\\tau$ and the output-side filter reduced the string-level residual to zero"),
    ("and the stacked defense $\\tau$+D30 was also clean. The observed failure rates",
     "and the stacked $\\tau$ and output-side filter defense was also clean. The observed failure rates"),
    ("$P(\\text{D30 fail})=0$, making $\\rho$",
     "$P(\\text{output-side filter fail})=0$, making $\\rho$"),
    ("An output-side filter (D30, our sentence-level output-side filter) that detects and",
     "An output-side filter (our sentence-level output-side filter) that detects and"),
    ("The D30 arm\neliminated \\emph{all} final leaks",
     "The output-side filter arm\neliminated \\emph{all} final leaks"),
    ("mechanism is that D30 removes the reasoning context that prompts the model to",
     "mechanism is that the output-side filter removes the reasoning context that prompts the model to"),
    ("$\\tau$ and D30 reduce the\nstring-level residual to zero on all 13 CoT-positive traces, and the stacked\n$\\tau$+D30 defense is also clean.",
     "$\\tau$ and the output-side filter reduce the\nstring-level residual to zero on all 13 CoT-positive traces, and the stacked $\\tau$ and output-side filter defense is also clean."),
    ("D30 suppression & channel & 8/8 & 25.5\\% & $-21.1$\\% \\\\",
     "Output-side filter suppression & channel & 8/8 & 25.5\\% & $-21.1$\\% \\\\"),
    ("applied to D30 it judges the filter harmful (final rises 5.4 percentage points under",
     "applied to the output-side filter it judges the filter harmful (final rises 5.4 percentage points under"),
    # RAW + C0 -> the no-defense control (arm description)
    ("three defense arms: RAW (the no-defense control; the same configuration is labelled C0 in Table~\\ref{tab:reach}), $\\tau$ (literal redaction of key\nsignatures from the final answer), and D30 (reasoning suppressed, final answer\nonly).",
     "three defense arms: the no-defense control, $\\tau$ (literal redaction of key\nsignatures from the final answer), and the output-side filter (reasoning suppressed, final answer\nonly)."),
    ("On 8 successful responses (one request timed out) the RAW final-leak rate",
     "On 8 successful responses (one request timed out) the no-defense control's final-leak rate"),
    # C0 in the reach table
    ("No defense (C0) & -- & -- & 0\\% & 0\\% \\\\",
     "No defense & -- & -- & 0\\% & 0\\% \\\\"),
    # reverse-effective
    ("This\nconfiguration is labeled \\emph{reverse-effective} (it removes refusals while\nleaving CoT leakage unchanged).",
     "This\nconfiguration removes refusals while leaving CoT leakage unchanged."),
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

for old, new in pairs:
    text = text.replace(old, new, 1)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print(f"APPLIED {len(pairs)} replacements; new size {os.path.getsize(PATH)} bytes")