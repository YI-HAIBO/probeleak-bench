"""Pass-20a: rule 2 (hedge words) + rule 3 (real-world) + rule 1 (definitions).
verify-then-apply: each OLD must match exactly once.
"""
import os, sys

TEX = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
NL = chr(10)

EDITS = []

# --- Rule 2: "essentially" hedge words (4x) ---

# L332: "for essentially all responses" -> "for all responses"
EDITS.append((
    'the reasoning trace is non-empty for essentially all responses, so a',
    'the reasoning trace is non-empty for all responses, so a'
))

# L444: "for essentially all responses in all" -> "for all responses in all"
EDITS.append((
    'the reasoning trace is non-empty for essentially all responses in all' + NL +
    'three samples, so a zero final-channel rate cannot be an artifact of an empty',
    'the reasoning trace is non-empty for all responses in all' + NL +
    'three samples, so a zero final-channel rate cannot be an artifact of an empty'
))

# L513: "were essentially never blocked" -> "were never blocked"
EDITS.append((
    'extraction and thinking leak were essentially never blocked). The gateway and',
    'extraction and thinking leak were never blocked). The gateway and'
))

# L774: "adds essentially nothing" -> "adds nothing"
EDITS.append((
    "stronger layer's own residual: the second layer adds essentially nothing.",
    "stronger layer's own residual: the second layer adds nothing."
))

# --- Rule 3: "real-world sample" -> "measured sample" (our data) ---

# L876: "in the real-world sample" -> "in the measured sample"
EDITS.append((
    'with displacement); in the real-world sample the final channel shows no leaks',
    'with displacement); in the measured sample the final channel shows no leaks'
))

# --- Rule 1: add brief definitions at first occurrence ---

# "leak-equivalent" at L778: add parenthetical gloss
EDITS.append((
    'cost model (false-positive damage, utility loss, and latency normalized at' + NL +
    '$\\lambda$ leak-equivalents per unit), the net value of stacking is negative even',
    'cost model (false-positive damage, utility loss, and latency normalized at' + NL +
    '$\\lambda$ leak-equivalents per unit, where one leak-equivalent is one prevented' + NL +
    'credential exposure), the net value of stacking is negative even'
))

# "contextual bandit" at L940: add parenthetical gloss
EDITS.append((
    'contextual bandit updated directly from per-request rewards, and a',
    'contextual bandit (a reinforcement-learning agent that selects among defense' + NL +
    'configurations using per-request rewards) updated directly from per-request rewards, and a'
))

# "co-evolution schedule" at L949: add parenthetical gloss
EDITS.append((
    'the request stream, the co-evolution schedule, and the utility aggregation are',
    'the request stream, the co-evolution schedule (in which an adaptive attacker migrates' + NL +
    'its attack mix every five generations), and the utility aggregation are'
))

# --- verify-then-apply ---
s = open(TEX, encoding='utf-8').read()
orig = s
for i, (old, new) in enumerate(EDITS):
    cnt = s.count(old)
    if cnt != 1:
        print('EDIT %d VERIFY FAIL count=%d' % (i + 1, cnt))
        print('  OLD prefix:', repr(old[:120]))
        sys.exit(1)
    s = s.replace(old, new, 1)
    print('EDIT %d OK' % (i + 1))

if s.count('{') != s.count('}'):
    print('BRACE MISMATCH', s.count('{'), s.count('}'))
    sys.exit(1)

tmp = TEX + '.tmp'
with open(tmp, 'w', encoding='utf-8') as f:
    f.write(s)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, TEX)
print('WROTE', len(s), 'bytes (was', len(orig), ')')
print('Braces: { }', s.count('{'), s.count('}'))