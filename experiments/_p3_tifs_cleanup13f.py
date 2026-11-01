#!/usr/bin/env python3
"""Pass-13 cleanup F: Rule 4 -- probe identifiers (tl1/pe1/sr4/te1/rp1/ii2/ci2/...).

The probe classes are already named in the rewritten legend (thinking leak,
prefix extraction, step reconstruction, translation-exfiltration, role-play,
stress key-extraction, indirect injection, code interpretation, refusal cliff);
a trailing index selects the individual probe.  This script replaces every
remaining bare probe id with "the <ordinal> <class> probe".

Order: ranges first (te1--te3, rp1--rp2, se1--se3), then individual ids.
"""
import os, sys, re

PATH = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"
t = open(PATH, encoding="utf-8").read()

# ---------------------------------------------------------- ranges first
ranges = [
    (r"\bte1--te3\b", "the first to third translation-exfiltration probes"),
    (r"\brp1--rp2\b", "the first and second role-play probes"),
    (r"\bse1--se3\b", "the first to third stress key-extraction probes"),
]

# ---------------------------------------------------------- individual ids
# rp1/rp2 and te1/te3 and se1/se3 only appear inside the ranges above
# (rp1--rp2, te1--te3, se1--se3), which are consumed first; the remaining
# ids are standalone.
ids = [
    (r"\bsr4\b", "the fourth step-reconstruction probe"),
    (r"\btl4\b", "the fourth thinking-leak probe"),
    (r"\btl1\b", "the first thinking-leak probe"),
    (r"\bpe1\b", "the first prefix-extraction probe"),
    (r"\bci2\b", "the second code-interpretation probe"),
    (r"\bii2\b", "the second indirect-injection probe"),
    (r"\bii1\b", "the first indirect-injection probe"),
    (r"\brp3\b", "the third role-play probe"),
    (r"\bre1\b", "the first refusal-cliff probe"),
]

# ---------------------------------------------------------- apply
new = t
for pat, rep in ranges:
    new, k = re.subn(pat, rep, new)
    if k == 0:
        sys.exit("range regex %r matched 0 times" % pat)
    print("range  %-20s -> %d" % (pat, k))

for pat, rep in ids:
    new, k = re.subn(pat, rep, new)
    if k == 0:
        sys.exit("id regex %r matched 0 times" % pat)
    print("id     %-20s -> %d" % (pat, k))

# ---------------------------------------------------------- verify
left = []
for pat in [r"\btl1\b", r"\btl4\b", r"\bpe1\b", r"\bsr4\b", r"\bte1\b", r"\bte3\b",
            r"\brp1\b", r"\brp2\b", r"\brp3\b", r"\bse1\b", r"\bse3\b", r"\bre1\b",
            r"\bii1\b", r"\bii2\b", r"\bci2\b"]:
    n = len(re.findall(pat, new))
    if n > 0:
        left.append((pat, n))
if left:
    sys.exit("VERIFY: probe ids still present: %s" % left)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(new)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("APPLIED %d range + %d id regex groups; new size %d (was %d)"
      % (len(ranges), len(ids), os.path.getsize(PATH), len(t)))