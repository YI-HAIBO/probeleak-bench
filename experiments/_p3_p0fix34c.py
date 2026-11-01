"""Pass-34: keep fig:corr caption consistent with the redrawn fig2 legend."""
import os, sys
P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
data = open(P, "rb").read().decode("utf-8")
old = "dotted: errata anchor)."
new = "dotted: previously reported gap)."
if data.count(old) != 1:
    sys.exit("ABORT: matched %d" % data.count(old))
data = data.replace(old, new)
tmp = P + ".tmp"
open(tmp, "wb").write(data.encode("utf-8"))
os.replace(tmp, P)
print("OK caption aligned with fig2 legend")
