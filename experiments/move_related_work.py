#!/usr/bin/env python3
"""Move the Related Work section from its current position (after Forensic
Implications) to right after the Introduction, before Background and Threat
Model. Section labels move with their content; no other text is touched.

Idempotent: if Related Work is already before Background, this is a no-op.
"""
import sys

PATH = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

with open(PATH, encoding="utf-8") as f:
    text = f.read()

RW = "\\section{Related Work}"
BG = "\\section{Background and Threat Model}"
LM = "\\section{Limitations}"

rw = text.index(RW)
bg = text.index(BG)
lm = text.index(LM)

if rw < bg:
    print("Related Work already precedes Background; nothing to do.")
    sys.exit(0)

# Block = everything from \section{Related Work} up to (not including)
# \section{Limitations}. This includes the trailing blank line(s).
block = text[rw:lm]

# Remove block from its current position.
text2 = text[:rw] + text[lm:]

# Re-find Background in the trimmed text (index may have shifted).
bg2 = text2.index(BG)

# Insert block verbatim before Background. Block already ends with the
# blank line that previously separated it from Limitations, and text2[:bg2]
# ends with the blank line that separated Introduction from Background.
result = text2[:bg2] + block + text2[bg2:]

with open(PATH, "w", encoding="utf-8") as f:
    f.write(result)

print("Moved Related Work from after Forensic Implications to after Introduction.")