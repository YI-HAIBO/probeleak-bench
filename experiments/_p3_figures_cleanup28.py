"""Pass-28: Remove parenthetical subtitles from section titles."""
import os, sys

TEX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "paper", "p3_tifs.tex")

with open(TEX, "r", encoding="utf-8") as f:
    tex = f.read()

edits = []

# --- Edit 1: Section "Theoretical Boundary on Defense Stacking" ---
old1 = ('\\section{Theoretical Boundary on Defense Stacking\n'
        '\\textnormal{(calibrated-model analysis)}}')
new1 = '\\section{Theoretical Boundary on Defense Stacking}'
edits.append((old1, new1))

# --- Edit 2: Section "Adaptive Defense Under Weak Signal" ---
old2 = ('\\section{Adaptive Defense Under Weak Signal\n'
        '\\textnormal{(model-driven analysis)}}')
new2 = '\\section{Adaptive Defense Under Weak Signal}'
edits.append((old2, new2))

for old, new in edits:
    cnt = tex.count(old)
    if cnt != 1:
        print(f"ABORT: expected 1 occurrence of {repr(old[:60])}, found {cnt}")
        sys.exit(1)
    tex = tex.replace(old, new)
    print(f"OK: removed parenthetical from {repr(old[:50])}...")

tmp = TEX + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(tex)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, TEX)
print(f"Written {TEX} ({len(tex)} bytes)")
print("Pass-28 complete.")