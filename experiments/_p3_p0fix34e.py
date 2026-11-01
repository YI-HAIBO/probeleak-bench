"""Pass-34: fig:corr caption exceeded the strict <=15-token count after the
errata-anchor rewrite; drop the parenthetical line-style key (the in-figure
legend already identifies every line)."""
import os, sys
P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
data = open(P, "rb").read().decode("utf-8")
old = "\\caption{Joint-residual discount versus the independence prediction (solid: measured; dashed: achievable bound; dotted: previously reported gap).}"
new = "\\caption{Joint-residual discount versus the independence prediction.}"
if data.count(old) != 1:
    sys.exit("ABORT: matched %d" % data.count(old))
data = data.replace(old, new)
tmp = P + ".tmp"
open(tmp, "wb").write(data.encode("utf-8"))
os.replace(tmp, P)
print("OK fig:corr caption shortened")
