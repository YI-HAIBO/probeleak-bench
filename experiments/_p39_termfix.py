#!/usr/bin/env python3
"""Pass-39 follow-up: disambiguate "wave-3" (third gateway) from the new
"window-3" rows (third quota window of the cross-vendor gateway)."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
P = os.path.join(os.path.dirname(HERE), "paper", "p3_tifs.tex")
CRLF = chr(13) + chr(10)

EDITS = [
    ("The wave-3 rows require a control-baseline reading",
     "The third-gateway rows require a control-baseline reading"),
    ("the wave-3 leak signal is therefore spontaneous",
     "the third-gateway leak signal is therefore spontaneous"),
]


def main():
    raw = open(P, "rb").read().decode("utf-8")
    cur = raw
    for i, (old, new) in enumerate(EDITS):
        c = cur.count(old)
        if c != 1:
            print("ABORT edit %d count=%d" % (i + 1, c))
            sys.exit(1)
        cur = cur.replace(old, new, 1)
        print("edit %d ok" % (i + 1))
    tmp = P + ".tmp"
    open(tmp, "wb").write(cur.encode("utf-8"))
    os.replace(tmp, P)
    print("--> %s (%d -> %d)" % (P, len(raw), len(cur)))
    print("remaining wave-3:", cur.count("wave-3"))


if __name__ == "__main__":
    main()
