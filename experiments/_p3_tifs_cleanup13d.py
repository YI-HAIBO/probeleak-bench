#!/usr/bin/env python3
"""Pass-13 cleanup D: Rule 7 -- no standalone note blocks.  Every
{\raggedright\footnotesize ... \par} block is folded into the caption of its
table/figure, and the block (plus the preceding \\vspace) is deleted.

Marker-driven (no hand-escaped LaTeX): locate each note block by its literal
marker, locate its caption by brace-matching backward from the note, merge,
and rebuild the string from a sorted non-overlapping edit list.
"""
import os, sys
from collections import defaultdict

PATH = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"

t = open(PATH, encoding="utf-8").read()

MARKER = "\\raggedright\\footnotesize "      # literal: \raggedright\footnotesize
PAR_END = "\\par}"                          # literal: \par}
CAP_TAG = "\\caption{"                       # literal: \caption{
VSPACE = "\\vspace{-4pt}\n"                  # literal: \vspace{-4pt} + newline

# --- 1. locate every note block -------------------------------------------
notes = []
pos = 0
while True:
    idx = t.find(MARKER, pos)
    if idx == -1:
        break
    nstart = idx - 1                                  # the opening '{'
    pend = t.find(PAR_END, idx)
    if pend == -1:
        sys.exit("unterminated note block at %d" % nstart)
    nend = pend + len(PAR_END)
    notes.append([nstart, nend])
    pos = nend
print("found %d note blocks" % len(notes))

# --- 2. for each note, find its caption (brace-matched) -------------------
def find_caption(s, before):
    cstart = s.rfind(CAP_TAG, 0, before)
    if cstart == -1:
        return None
    depth = 0
    i = cstart + len(CAP_TAG)
    while i < len(s):
        ch = s[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            if depth == 0:
                return (cstart, i + 1)
            depth -= 1
        i += 1
    return None

note_info = []
for (nstart, nend) in notes:
    cap = find_caption(t, nstart)
    if cap is None:
        sys.exit("no caption found before note at %d" % nstart)
    fs = t.find("\\footnotesize ", nstart)
    inner_start = fs + len("\\footnotesize ")
    inner_end = nend - len(PAR_END)
    note_inner = t[inner_start:inner_end].strip()
    note_info.append({"nstart": nstart, "nend": nend, "cap": cap, "inner": note_inner})

# --- 3. group notes by caption region; merge inners -----------------------
cap_groups = defaultdict(list)
for info in note_info:
    cap_groups[(info["cap"][0], info["cap"][1])].append(info)

edits = []  # (start, end, replacement_or_None)
for cap_key, infos in cap_groups.items():
    cstart, cend = cap_key
    caption_inner = t[cstart + len(CAP_TAG):cend - 1]
    merged = caption_inner
    for info in infos:            # preserve note order as in the file
        merged = merged + " " + info["inner"]
    edits.append((cstart, cend, CAP_TAG + merged + "}"))
    for info in infos:
        ds = info["nstart"]
        if t[ds - len(VSPACE):ds] == VSPACE:
            ds -= len(VSPACE)
        edits.append((ds, info["nend"], None))

# --- 4. verify no overlap, then rebuild -----------------------------------
edits.sort(key=lambda e: e[0])
for i in range(1, len(edits)):
    if edits[i][0] < edits[i - 1][1]:
        sys.exit("overlapping edits at %d" % edits[i][0])

out = []
cur = 0
for (s, e, rep) in edits:
    out.append(t[cur:s])
    if rep is not None:
        out.append(rep)
    cur = e
out.append(t[cur:])
new = "".join(out)

# --- 5. convert the C0 / D30 that survived inside the merged Table~VI caption
post = [
    ("no mechanism exists for C0, so its reach is undefined",
     "no mechanism exists for the no-defense control, so its reach is undefined"),
    ("The $\\tau$ and C0 rows both read 0\\% in the Final-only column",
     "The $\\tau$ and no-defense rows both read 0\\% in the Final-only column"),
    ("while C0 applies no mechanism and so reduces nothing",
     "while the no-defense applies no mechanism and so reduces nothing"),
    ("The D30\nentry is negative because displacement",
     "The output-side filter\nentry is negative because displacement"),
]
for i, (old, rep) in enumerate(post):
    n = new.count(old)
    if n != 1:
        sys.exit("post %d: expected 1, found %d\n%r" % (i, n, old))
    new = new.replace(old, rep, 1)

# --- 6. assert no note blocks remain --------------------------------------
if MARKER in new:
    sys.exit("VERIFY: a note block still remains after merge")
if new.count(CAP_TAG) != t.count(CAP_TAG):
    sys.exit("VERIFY: caption count changed")
# the only C0/D30 left at this point are in the experiment-notation legend,
# which cleanup13e rewrites; the Table~VI caption is now clean of both.

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(new)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("APPLIED %d edits; new size %d bytes (was %d)" % (len(edits), os.path.getsize(PATH), len(t)))