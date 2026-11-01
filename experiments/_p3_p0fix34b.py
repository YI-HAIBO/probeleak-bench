"""Follow-up: remove redundancy introduced by the g2 replacement."""
import os, sys
P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
CR = chr(13) + chr(10)
data = open(P, "rb").read().decode("utf-8")
old = ("The stress test gate result (the stress-test reduction gate did not" + CR +
       "hold, because $\\tau$ has zero reduction on this probe set)" + CR +
       "is reported as such:")
new = ("The stress-test reduction gate did not" + CR +
       "hold ($\\tau$ shows zero reduction on this probe set) and is reported as such:")
if data.count(old) != 1:
    sys.exit("ABORT: matched %d" % data.count(old))
data = data.replace(old, new)
tmp = P + ".tmp"
open(tmp, "wb").write(data.encode("utf-8"))
os.replace(tmp, P)
print("OK redundancy removed")
