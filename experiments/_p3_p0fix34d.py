"""Pass-34: fig7 panel titles removed from the figure, so the caption carries (a)/(b)."""
import os, sys
P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
data = open(P, "rb").read().decode("utf-8")
old = "\\caption{Consumer exposure by channel and filter; right: residual leak versus visibility.}"
new = "\\caption{(a) Consumer exposure by channel and filter. (b) Residual leak versus visibility.}"
if data.count(old) != 1:
    sys.exit("ABORT: matched %d" % data.count(old))
data = data.replace(old, new)
tmp = P + ".tmp"
open(tmp, "wb").write(data.encode("utf-8"))
os.replace(tmp, P)
print("OK fig7 caption updated")
