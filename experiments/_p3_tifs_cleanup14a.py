#!/usr/bin/env python3
"""Pass-14a: duplicate words + section title (verify-then-apply)."""
import re, os, sys

PATH = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(PATH, encoding='utf-8').read()
orig = s

# --- duplicate-word fixes -------------------------------------------------
# "the second sample sample" -> "the second sample"  (all occurrences)
# "third sample sample" -> "third sample"
# "second sample\nsample" -> "second sample"  (newline-separated)
# "The Theoretical Boundary on Defense Stacking" -> "Theoretical Boundary on Defense Stacking"

pairs = [
    # (old, new, replace_all, verify_count)
    ('the second sample sample', 'the second sample', True, None),   # count checked below
    ('third sample sample', 'third sample', True, None),
    ('The Theoretical Boundary on Defense Stacking', 'Theoretical Boundary on Defense Stacking', False, 1),
]

# Handle newline-separated "sample\nsample" separately (regex with \s+)
# We'll do this with a regex that catches "second sample\nsample" and "third sample\nsample"
# Actually let's handle all "sample sample" variants with a single regex approach

# First, do the simple string replacements
for old, new, ra, vc in pairs:
    cnt = s.count(old)
    if vc is not None and cnt != vc:
        print(f'VERIFY FAIL: "{old}" count={cnt} expected={vc}')
        sys.exit(1)
    if cnt == 0:
        print(f'VERIFY FAIL: "{old}" not found')
        sys.exit(1)
    if ra:
        s = s.replace(old, new)
    else:
        s = s.replace(old, new, 1)
    print(f'OK: "{old}" -> "{new}" ({cnt} occurrences)')

# Now handle "sample\nsample" and "sample sample" remaining via regex
# Pattern: word "sample" followed by whitespace+newline? "sample"
# Actually let's just catch any "sample" followed by optional spaces/newlines then "sample"
# that is NOT already fixed
pat = re.compile(r'\bsample\s+sample\b')
matches = pat.findall(s)
print(f'\nremaining "sample ... sample" matches: {len(matches)}')
for m in pat.finditer(s):
    print('  ', repr(s[max(0,m.start()-50):m.end()+50]))

if pat.search(s):
    # Replace all remaining "sample\s+sample" -> "sample"
    s2 = pat.sub('sample', s)
    n = len(pat.findall(s))
    s = s2
    print(f'OK: regex sub "sample\\s+sample" -> "sample" ({n} occurrences)')

# Verify no more duplicates
dup = re.findall(r'\b(\w+)\s+\1\b', s, re.I)
# Filter out legitimate doubles like "is is", "the the" etc that might be in math
print(f'\nremaining any-duplicate words: {len(dup)}')
for d in set(dup):
    print(f'  "{d}"')

# --- write back atomically -------------------------------------------------
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