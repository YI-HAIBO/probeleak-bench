#!/usr/bin/env python3
"""Pass-14e: fix brace imbalance introduced by cleanup14b's forensic regex.
The regex changed \\textbf{1) ...} to \\textbf{1.} ...} which left the closing
} unmatched. Fix: move the } from after "1." to after the full sentence."""
import re, os, sys

PATH = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(PATH, encoding='utf-8').read()
orig = s

# Fix: change "\textbf{1.} The" to "\textbf{1. The" (move the closing brace
# to the end of the sentence where it originally was)
pairs = [
    ('\\textbf{1.} The reasoning channel',
     '\\textbf{1. The reasoning channel', 1, False),
    ('\\textbf{2.} The honeypot judge',
     '\\textbf{2. The honeypot judge', 1, False),
    ('\\textbf{3.} Channel separation',
     '\\textbf{3. Channel separation', 1, False),
    ('\\textbf{4.} Evidence integrity',
     '\\textbf{4. Evidence integrity', 1, False),
]

for old, new, expected, ra in pairs:
    cnt = s.count(old)
    if cnt != expected:
        print(f'VERIFY FAIL: "{old}" count={cnt} expected={expected}')
        sys.exit(1)
    if ra:
        s = s.replace(old, new)
    else:
        s = s.replace(old, new, 1)
    print(f'OK: "{old}" -> "{new}" ({cnt})')

# Verify brace balance
depth = 0
for i, c in enumerate(s):
    if c == '{':
        depth += 1
    elif c == '}':
        depth -= 1
        if depth < 0:
            print(f'VERIFY FAIL: extra }} at position {i}')
            sys.exit(1)
print(f'VERIFIED: brace balance = {depth} (should be 0)')

# Verify no \textbf{N.} with stray closing brace
for m in re.finditer(r'\\textbf\{\d\.\}', s):
    print(f'VERIFY FAIL: stray \\textbf{{{m.group()}}} at {m.start()}')
    sys.exit(1)
print('VERIFIED: no stray \\textbf{N.} patterns')

# --- write back atomically ---------------------------------------------------
if s == orig:
    print('\nNO CHANGES')
    sys.exit(0)

tmp = PATH + '.tmp'
with open(tmp, 'w', encoding='utf-8') as f:
    f.write(s)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print(f'\nWROTE {PATH} ({len(s)} bytes, delta {len(s)-len(orig)})')