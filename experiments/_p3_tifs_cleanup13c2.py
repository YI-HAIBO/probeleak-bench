#!/usr/bin/env python3
"""Pass-13 cleanup C2: the two prose D30 occurrences that cleanup13c left behind
(the E4 consumer sentence and the Limitations scrubber-scope item).  The
remaining D30/C0 live in the experiment-notation legend (cleanup13e) and the
Table~VI note block (cleanup13d)."""
import os, sys

PATH = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"

pairs = [
    ("coverage), and D30 sentence suppression each reduced consumer leaks from 11 to 0",
     "coverage), and sentence-level output-side suppression each reduced consumer leaks from 11 to 0"),
    ("      applies $\\tau$ and D30 and finds zero string-level residual on all 13",
     "      applies $\\tau$ and the output-side filter and finds zero string-level residual on all 13"),
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