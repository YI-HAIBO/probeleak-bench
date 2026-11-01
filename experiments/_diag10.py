#!/usr/bin/env python3
# Diagnostic: for each failing pair, locate the exact mismatch point.
import io, sys, importlib.util

PATH = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
text = io.open(PATH, encoding='utf-8').read()

spec = importlib.util.spec_from_file_location(
    "c10", r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\experiments\_p3_tifs_cleanup10.py')
# We cannot import (it aborts), so re-extract PAIRS by parsing the source.
src = io.open(r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\experiments\_p3_tifs_cleanup10.py',
              encoding='utf-8').read()
ns = {}
exec(src.split('# ---- verify first ----')[0], ns)
PAIRS = ns['PAIRS']

IDS = [6, 12, 16, 18, 19, 20, 29, 38, 46]
for i in IDS:
    old = PAIRS[i][0]
    print("=" * 78)
    print("PAIR", i)
    # longest matching prefix
    hi = 0
    for L in range(len(old), -1, -1):
        if old[:L] in text:
            hi = L
            break
    # find location of that prefix
    loc = text.find(old[:hi])
    print("prefix matched len %d / %d" % (hi, len(old)))
    print("  prefix tail : %r" % (old[max(0, hi - 45):hi],))
    print("  FILE after  : %r" % (text[loc + hi:loc + hi + 120],))
    print("  OLD after   : %r" % (old[hi:hi + 120],))
    # show whether the rest of OLD is present verbatim somewhere
    rest = old[hi:]
    print("  rest in file verbatim?", rest in text)
