#!/usr/bin/env python3
"""Pass-13 cleanup G: fix bare underscores left by the 13b \texttt{} removal.

The 13b pass stripped \texttt{} wrappers around field names such as
reasoning_leak and cot_leak, leaving the raw identifiers with underscores
in text mode, which makes LaTeX emit "Missing $ inserted".  This pass
replaces the one surviving instance with prose that needs no underscore.
"""
import os, sys

PATH = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"
t = open(PATH, encoding="utf-8").read()

OLD = ("in addition the stress test stores the reasoning\n"
       "leak in a field named reasoning_leak rather than cot_leak. None of the")
NEW = ("in addition the stress test stores the reasoning leak under a field\n"
       "name that differs from the one used by other runs. None of the")

n = t.count(OLD)
if n != 1:
    sys.exit("OLD %r: expected 1, found %d" % (OLD, n))

new = t.replace(OLD, NEW, 1)

# verify the specific field names are gone
for bad_name in ["reasoning_leak", "cot_leak"]:
    if new.count(bad_name) > 0:
        sys.exit("VERIFY: %r still present" % bad_name)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(new)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("APPLIED; new size %d (was %d)" % (os.path.getsize(PATH), len(t)))