# Pass-42 fix: remove orphaned fragment in Limitations introduced by the M5
# c*-sensitivity insertion. Restore the original sentence join:
#   "...parameterized rather than observed, with the zero tau residual measured
#    only on the probe families that produced leaks in the consumer arm."
# The M5 edit had severed "rather" from "than observed, with the zero tau
# residual..." and left the tail dangling after the c* sensitivity paragraph.
import os, sys

P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
CRLF = chr(13) + chr(10)

data = open(P, "rb").read()
text = data.decode("utf-8")

orphan = ("than observed, with the zero $\\tau$ residual measured only on the probe"
          + CRLF + "families that produced leaks in the consumer arm. ")
restore = ("than observed, with the zero $\\tau$ residual measured only on the probe"
           + CRLF + "families that produced leaks in the consumer arm. The"
           + CRLF + "equivalence-class threshold")

old_head = "than observed. The equivalence-class threshold"
new_head = ("than observed, with the zero $\\tau$ residual measured only on the probe"
            + CRLF + "families that produced leaks in the consumer arm. The"
            + CRLF + "equivalence-class threshold")

assert text.count(old_head) == 1, f"head anchor count = {text.count(old_head)}"
assert text.count(orphan) == 1, f"orphan count = {text.count(orphan)}"

# 1) remove the dangling orphan after "upper CI alone."
assert text.count(orphan) == 1, f"orphan count before removal = {text.count(orphan)}"
text = text.replace(orphan, "", 1)
# 2) restore the sentence join at the head
assert text.count(old_head) == 1, f"head anchor count = {text.count(old_head)}"
text = text.replace(old_head, new_head, 1)

tmp = P + ".tmp"
open(tmp, "wb").write(text.encode("utf-8"))
os.replace(tmp, P)
print("Fix applied: sentence restored, orphan removed.")
print("size:", os.path.getsize(P))
