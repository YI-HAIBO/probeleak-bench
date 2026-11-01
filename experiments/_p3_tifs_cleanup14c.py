#!/usr/bin/env python3
"""Pass-14c: engineering-term academicization (verify-then-apply)."""
import re, os, sys

PATH = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(PATH, encoding='utf-8').read()
orig = s

# Each tuple: (old, new, expected_count, replace_all)
# Order matters: longer/more-specific phrases first to avoid substring conflicts.
pairs = []

# --- FAKE prefix: 3 occurrences, all "a FAKE prefix" ------------------------
pairs.append(('a FAKE prefix', 'a synthetic-marker prefix', 3, True))

# --- SHA-256: 2 occurrences --------------------------------------------------
pairs.append(('(verified by SHA-256 comparison)', '(verified by content-based comparison)', 1, False))
pairs.append(('a SHA-256 digest', 'a content-based digest', 1, False))

# --- idempotency: 1 occurrence -----------------------------------------------
pairs.append(('re-verifies idempotency by byte\ncomparison on re-run',
              're-verifies determinism by byte-level\ncomparison on re-run', 1, False))

# --- harness: 3 occurrences -------------------------------------------------
pairs.append(('the released probe suite and harness only',
              'the released probe suite and experiment framework only', 1, False))
pairs.append(('the probe suite, harness, and\nall simulation experiments',
              'the probe suite, experiment framework, and\nall simulation experiments', 1, False))
pairs.append(('the experiment scripts and harness, the idempotent report',
              'the experiment scripts and experiment framework, the reproducible report', 1, False))

# --- 429-budget bisection: 2 occurrences ------------------------------------
# "a rolling 60-second window with 429-budget bisection" -> "a rolling 60-second window"
# But we need to handle the trailing ")" and newline properly
# From scan: "a rolling 60-second window with 429-budget bisection)\nbecause the endpoint"
# After removal: "a rolling 60-second window)\nbecause the endpoint"
pairs.append(('a rolling 60-second window with 429-budget bisection)',
              'a rolling 60-second window)', 1, False))
# Second occurrence: let me find it
# From scan: only 1 occurrence of "429-budget bisection" in the body, the other "429" is in a bibitem arxiv ID
# Actually the scan showed 429: 2, but one is arxiv:2407.04295. So only 1 "429-budget bisection".
# Let me adjust: the count for "with 429-budget bisection" should be 1, not 2.
# But I had it as 2 in the earlier version. Let me fix.

# --- production: handle specific phrases (longest/most-specific first) -------
# "production reasoning-model gateways" (1)
pairs.append(('Direct forensic measurements on production\nreasoning-model gateways',
              'Direct forensic measurements on deployed\nreasoning-model gateways', 1, False))
# "a production reasoning model" (1)
pairs.append(('The \\emph{real} world is a production reasoning model',
              'The \\emph{real} world is a deployed reasoning model', 1, False))
# "a production\nreasoning-model gateway" (1)
pairs.append(('collected on a production\nreasoning-model gateway',
              'collected on a deployed\nreasoning-model gateway', 1, False))
# "on the production model" (2 occurrences: 27564, 88505)
pairs.append(('on the production model', 'on the deployed model', 2, True))
# "against the production model" (1 at 69762)
pairs.append(('against the production model', 'against the deployed model', 1, False))
# "production-side baselines" (3: 8243, 73640, 92936)
pairs.append(('production-side baselines', 'deployed-side baselines', 3, True))
# "production-side paradigms" (1 at 78749)
pairs.append(('production-side paradigms', 'deployed-side paradigms', 1, False))
# "production-side mechanisms" (1 at 79528)
pairs.append(('production-side mechanisms', 'deployed-side mechanisms', 1, False))
# "Two production-side\nparadigms" (1 at 72477)
pairs.append(('Two production-side\nparadigms', 'Two deployed-side\nparadigms', 1, False))
# "production-baseline probe" (4: 21714, 77301, 77332, and one more)
pairs.append(('production-baseline probe', 'operational-baseline probe', 3, True))
# "production runs" (1 at 86760)
pairs.append(('the production runs use', 'the operational runs use', 1, False))
# "in production logs" (2: 80467, 93583)
pairs.append(('in production logs', 'in operational logs', 2, True))
# "the common production redaction\nshape" (1 at 62249)
pairs.append(('the common production redaction\nshape', 'the common deployed redaction\nshape', 1, False))
# "two additional production\nparadigms" (1 at 79052)
pairs.append(('two additional production\nparadigms', 'two additional deployed\nparadigms', 1, False))
# "in production, yet evaluations" (1 at 1374)
pairs.append(('database access in production, yet evaluations',
              'database access in deployed settings, yet evaluations', 1, False))
# "against production stores" (1 at 3257)
pairs.append(('against production stores, and pentesting',
              'against operational databases, and pentesting', 1, False))

# --- apply -------------------------------------------------------------------
for old, new, expected, ra in pairs:
    cnt = s.count(old)
    if cnt != expected:
        print(f'VERIFY FAIL: "{old[:60]}" count={cnt} expected={expected}')
        sys.exit(1)
    if ra:
        s = s.replace(old, new)
    else:
        s = s.replace(old, new, 1)
    print(f'OK: "{old[:50]}..." -> "{new[:50]}..." ({cnt})')

# --- verify no leftover engineering terms ------------------------------------
checks = [
    ('FAKE prefix', 0),
    ('SHA-256', 0),
    ('idempotency', 0),
    ('429-budget', 0),
    ('production-side paradigms', 0),
    ('production-side mechanisms', 0),
    ('production-side baselines', 0),
    ('production-baseline probe', 0),
    ('production model', 0),
    ('production logs', 0),
    ('production runs', 0),
    ('production stores', 0),
    ('production redaction', 0),
    ('production reasoning', 0),
    ('production paradigms', 0),
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