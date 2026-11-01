# -*- coding: utf-8 -*-
"""Pass-6 on p3_tifs.tex: figure axis clarifications + reference-tier notes.

Targets the remaining Turn-4 items:
- Figure captions that do not describe their axes (Fig 2, Fig 3, Fig 6).
- Reference entries whose publication tier is ambiguous to a first reader
  (bengio2025 edition, leaky2025 venue type, pandey2026 preprint status,
  peng2025 journal tier).
"""
import os, re

PATH = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

with open(PATH, "r", encoding="utf-8") as f:
    text = f.read()

def to_regex(s):
    parts = re.split(r"\s+", s)
    return r"\s+".join(re.escape(p) for p in parts)

PAIRS = [
# ==================== FIGURE CAPTION IMPROVEMENTS ====================

# Fig 2 (fig:corr): caption does not describe axes or curves
("\\caption{Joint-residual discount versus the independence prediction.}",
 "\\caption{Joint-residual discount versus the independence prediction. The discount\n"
 "factor (joint residual $\\div$ product-law prediction) is plotted against the\n"
 "shared-blindspot coefficient $\\rho$; the measured curve, the achievable bound\n"
 "(4.48$\\times$), the errata anchor (7.63$\\times$), and the deployment point are\n"
 "shown separately.\"}"),

# Fig 3 (fig:output): caption does not describe the three curves or axes
("\\caption{Output-side filtering displaces rather than removes leakage (simulated world).}",
 "\\caption{Output-side filtering displaces rather than removes leakage (simulated world).\n"
 "CoT-effective, final-effective, and union leak rates are plotted against\n"
 "output-filter strictness $s$; the $\\tau$ countermeasure at $s=1$ and the\n"
 "irreducible union floor are marked.\"}"),

# Fig 6 (fig:e6ci): caption is brief; add axis description
("\\caption{Per-class reasoning-channel leak rates and 95\\% intervals for B3, E6, and pooled.}",
 "\\caption{Per-class reasoning-channel leak rates and 95\\% intervals for B3, E6, and\n"
 "pooled. Points show the CoT leak rate by attack class; horizontal bars show\n"
 "Wilson 95\\% intervals; the vertical dashed line marks the pooled rate.\"}"),

# ==================== REFERENCE-TIER NOTES ====================

# bengio2025: clarify it is the 2025 edition of the international report
("Y.~Bengio \\emph{et al.}, ``International AI safety report,'' 2025, available:",
 "Y.~Bengio \\emph{et al.}, ``International AI safety report,'' 2025 edition,\n"
 "available:"),

# leaky2025: clarify publication type (conference paper, not journal)
("arXiv:2506.15674}, 2025 (accepted at EMNLP 2025).",
 "arXiv:2506.15674}, 2025 (accepted at EMNLP 2025; conference paper)."),

# pandey2026: clarify preprint status
("systems: Asymptotic floors, dilution thresholds, and defense stack\n"
 "certification,'' \\emph{arXiv preprint arXiv:2607.24625}, 2026.",
 "systems: Asymptotic floors, dilution thresholds, and defense stack\n"
 "certification,'' \\emph{arXiv preprint arXiv:2607.24625}, 2026\n"
 "(preprint; not yet peer-reviewed)."),

# peng2025: add journal tier context
("J.~Peng, ``Data privacy risks of large language models: A comprehensive review,''\n"
"\\emph{Applied and Computational Engineering}, vol.\\ 218, pp.\\ 148--160, 2025.\n"
"ISSN 2755-2721.",
"J.~Peng, ``Data privacy risks of large language models: A comprehensive review,''\n"
"\\emph{Applied and Computational Engineering}, vol.\\ 218, pp.\\ 148--160, 2025.\n"
"ISSN 2755-2721 (journal article; a peer-reviewed applied-engineering outlet)."),
]

ok = True
for i, (old, new) in enumerate(PAIRS):
    rx = to_regex(old)
    n = len(re.findall(rx, text))
    if n != 1:
        print("pair %d: regex found %d matches (need 1):" % (i + 1, n))
        print("OLD:", repr(old[:140]))
        ok = False
        continue
    text = re.sub(rx, lambda m: new, text, count=1)

if not ok:
    print("ABORTING - no file written.")
    raise SystemExit(1)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("OK: %d pairs applied, %d bytes" % (len(PAIRS), os.path.getsize(PATH)))