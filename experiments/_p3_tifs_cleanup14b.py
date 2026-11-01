#!/usr/bin/env python3
"""Pass-14b: terminology unification + rbac2026 bibitem fix (verify-then-apply)."""
import re, os, sys

PATH = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(PATH, encoding='utf-8').read()
orig = s

# Each tuple: (old, new, expected_count_or_None, replace_all)
# expected_count=None means "must be >0" (checked separately)
pairs = []

# --- no-defense: unify to "no-defense control" --------------------------------
pairs.append(('the\nno-defense point', 'the\nno-defense control point', 1, False))
pairs.append(('no-defense configuration', 'no-defense control', 1, False))
pairs.append(('no-defense\nleak rate', 'no-defense control\nleak rate', 1, False))
pairs.append(('the no-defense applies', 'the no-defense control applies', 1, False))

# --- output-side: unify "defense" -> "filter" --------------------------------
# "three output-side defenses" (3 occurrences)
pairs.append(('three output-side defenses', 'three output-side filters', 3, True))
# "output-side defense question" -> "output-side filter question"
pairs.append(('the output-side defense question', 'the output-side filter question', 1, False))
# "each output-side defense" -> "each output-side filter"
pairs.append(('each output-side defense', 'each output-side filter', 1, False))
# "output-side filter defense" -> "output-side filter" (2 occurrences)
pairs.append(('output-side filter defense', 'output-side filter', 2, True))

# --- literal scrub: unify to "literal scrubber" / "literal scrubbing" ----------
pairs.append(('literal-scrub coverage', 'literal scrubber coverage', 1, False))
pairs.append(('literal-scrub defense', 'literal scrubber', 1, False))
pairs.append(('$\\tau$ literal scrub &', '$\\tau$ literal scrubber &', 1, False))
# "literal redaction" -> "literal scrubbing" (2 occurrences)
pairs.append(('literal redaction', 'literal scrubbing', 3, True))

# --- rbac2026 bibitem: remove first-person editorial comment ------------------
pairs.append((
    '2026 (we cite the preprint version; to appear at the ACM International Conference on Management of Data (SIGMOD), 2027).',
    '2026, to appear in Proc.\\ ACM Int.\\ Conf.\\ Manage.\\ Data (SIGMOD), 2027.',
    1, False
))

# --- forensic section: "1)" -> "1." etc. (use regex for all 4 items) ----------
import re as _re
_forensic_pat = _re.compile(r'\\textbf\{(\d)\)')
_forensic_matches = _forensic_pat.findall(s)
print(f'forensic numbered items found: {len(_forensic_matches)} ({_forensic_matches})')
if len(_forensic_matches) != 4:
    print('VERIFY FAIL: expected 4 forensic numbered items')
    sys.exit(1)
s = _forensic_pat.sub(lambda m: '\\textbf{' + m.group(1) + '.}', s)
print('OK: forensic "\\textbf{N)" -> "\\textbf{N.}" (4 replacements)')

# --- apply -------------------------------------------------------------------
for old, new, expected, ra in pairs:
    cnt = s.count(old)
    if cnt != expected:
        print(f'VERIFY FAIL: "{old}" count={cnt} expected={expected}')
        sys.exit(1)
    if ra:
        s = s.replace(old, new)
    else:
        s = s.replace(old, new, 1)
    print(f'OK: "{old[:60]}..." -> "{new[:60]}..." ({cnt})')

# --- verify no leftover variants ---------------------------------------------
checks = [
    ('no-defense point', 0),
    ('no-defense configuration', 0),  # replaced above
    ('no-defense leak rate', 0),
    ('output-side defenses', 0),
    ('output-side defense question', 0),
    ('output-side filter defense', 0),
    ('literal-scrub coverage', 0),
    ('literal-scrub defense', 0),
    ('literal redaction', 0),  # 3 occurrences all replaced above
    ('\\textbf{1)', 0),  # handled by regex above
    ('\\textbf{2)', 0),  # handled by regex above
    ('we cite the preprint version', 0),
]
for pat, exp in checks:
    cnt = s.count(pat)
    if cnt != exp:
        print(f'VERIFY FAIL (leftover): "{pat}" count={cnt} expected={exp}')
        sys.exit(1)
    print(f'VERIFIED: "{pat}" = {cnt}')

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