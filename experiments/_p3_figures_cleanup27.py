"""Pass-27: Fix fig7 caption/label inconsistencies found in audit."""
import os, sys

BS = chr(92)
NL = chr(10)

TEX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "paper", "p3_tifs.tex")
GEN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "e4_report_gen.py")

# --- Fix 1: caption in tex ---
with open(TEX, "r", encoding="utf-8") as f:
    tex = f.read()

old_cap = ("The left panel shows the number of samples from which the downstream "
           "consumer recovered at least one honeypot key, by channel and after each "
           "output-side filter; the right panel plots consumer benefit in "
           "leak-equivalents per request against channel visibility $p_{cot}$, "
           "which is zero at $p_{cot}=0$.")

new_cap = ("The left panel shows the downstream exposure rate on the positive-layer "
           "paired subset ($n=13$), by channel and after each output-side filter; "
           "the right panel plots consumer-side residual leak against channel "
           "visibility $p_{cot}$, which is zero at $p_{cot}=0$.")

cnt = tex.count(old_cap)
if cnt != 1:
    print(f"ABORT tex: expected 1 occurrence, found {cnt}")
    sys.exit(1)
tex = tex.replace(old_cap, new_cap)
print("OK: caption fixed")

# --- Fix 2: y-axis label in fig generator ---
with open(GEN, "r", encoding="utf-8") as f:
    gen = f.read()

old_y = 'ax1.set_ylabel("Downstream exposure rate")'
new_y = 'ax1.set_ylabel("Downstream exposure rate (positive-layer)")'

cnt = gen.count(old_y)
if cnt != 1:
    print(f"ABORT gen: expected 1 occurrence of y-label, found {cnt}")
    sys.exit(1)
gen = gen.replace(old_y, new_y)
print("OK: y-axis label fixed")

# Write back
tmp = TEX + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(tex)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, TEX)
print(f"Written {TEX}")

tmp = GEN + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(gen)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, GEN)
print(f"Written {GEN}")
print("Pass-27 complete.")