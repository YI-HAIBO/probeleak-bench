#!/usr/bin/env python3
"""Pass-14d: self-deprecation reduction + caption trimming (verify-then-apply).
Caption trimming uses brace-matching to extract full caption text, then
replaces with trimmed version. This avoids CRLF line-break issues."""
import re, os, sys

PATH = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(PATH, encoding='utf-8').read()
orig = s

def apply_strict(old, new, expected=1):
    """Exact string replacement with count verification."""
    cnt = s.count(old)
    if cnt != expected:
        print(f'VERIFY FAIL: "{old[:60]}" count={cnt} expected={expected}')
        return False
    globals()['s'] = s.replace(old, new)
    print(f'OK: "{old[:50]}..." -> "{new[:50]}..." ({cnt})')
    return True

def apply_regex(rx, new, expected=1):
    """Regex replacement with count verification."""
    matches = list(re.finditer(rx, s))
    cnt = len(matches)
    if cnt != expected:
        print(f'VERIFY FAIL: regex "{rx[:60]}" count={cnt} expected={expected}')
        return False
    globals()['s'] = re.sub(rx, new, s)
    print(f'OK: regex "{rx[:50]}..." -> "{new[:50]}..." ({cnt})')
    return True

def find_caption(start_phrase):
    """Find a caption by its starting phrase, return (full_text, start_pos, end_pos)."""
    idx = s.find(start_phrase)
    if idx < 0:
        return None
    # Find \caption{ before this position
    cap_start = s.rfind('\\caption{', 0, idx)
    if cap_start < 0:
        return None
    # Find matching closing brace
    depth = 0
    i = cap_start + len('\\caption{')
    while i < len(s):
        if s[i] == '{':
            depth += 1
        elif s[i] == '}':
            if depth == 0:
                return (s[cap_start+len('\\caption{'):i], cap_start, i)
            depth -= 1
        i += 1
    return None

def replace_caption(start_phrase, new_text):
    """Find caption by start phrase and replace its content."""
    result = find_caption(start_phrase)
    if result is None:
        print(f'VERIFY FAIL: caption starting "{start_phrase}" not found')
        return False
    full_text, cap_start, cap_end = result
    old_cap = '\\caption{' + full_text + '}'
    new_cap = '\\caption{' + new_text + '}'
    cnt = s.count(old_cap)
    if cnt != 1:
        print(f'VERIFY FAIL: caption count={cnt} expected=1')
        return False
    globals()['s'] = s.replace(old_cap, new_cap)
    print(f'OK: caption "{full_text[:50]}..." -> "{new_text[:50]}..."')
    return True

# --- self-deprecation: exact-string replacements ------------------------------
if not apply_strict("Reproducibility is partially constrained by disclosure.",
                     "Reproducibility is constrained by disclosure."):
    sys.exit(1)
if not apply_strict("whose upper bound we do not claim represents the\ndeployment.",
                     "whose upper bound does not represent the\ndeployment."):
    sys.exit(1)
if not apply_strict("we did not test transfer to a different secret set.",
                     "transfer to a different secret set was not tested."):
    sys.exit(1)
if not apply_strict("occurs on real models has not been measured with\nchannel-isolated verdicts.",
                     "occurs on real models remains unmeasured with\nchannel-isolated verdicts."):
    sys.exit(1)

# --- caption trimming --------------------------------------------------------

# tab:agent (122 words -> concise)
if not replace_caption(
    "Adaptive defense agents under two world models (higher is better).",
    "Adaptive defense agents under two world models. Utility per request at $\\lambda=2$ "
    "(leak rate in parentheses); higher utility means lower leak rate. "
    "The model-driven pooling agent outperforms the static baseline in both worlds."
): sys.exit(1)

# tab:cohort (107 words -> concise)
if not replace_caption(
    "Pooled real-gateway sample by cohort and confidence intervals.",
    "Pooled real-gateway sample by cohort. Wilson 95\\% intervals: "
    "diverse CoT [10.83, 19.27], repetition CoT [96.40, 100.00], "
    "grand-pool CoT [33.47, 43.32]; grand-pool final [14.97, 22.87]. "
    "The ``Experiments'' column counts contributing campaigns; "
    "the ``$N$'' column gives effective attacks per cohort."
): sys.exit(1)

# fig:corr (89 words -> concise)
if not replace_caption(
    "Joint-residual discount versus the independence prediction.",
    "Joint-residual discount versus the independence prediction. "
    "The discount factor is plotted against $\\rho$; solid = measured, dashed = achievable "
    "bound (4.48$\\times$), dotted = errata anchor (7.63$\\times$), marked = deployment point. "
    "Validation pair $q_a=0.221$, $q_b=0.1513$; the independence prediction is the upper-right corner."
): sys.exit(1)

# tab:reach (183 words -> concise)
if not replace_caption(
    "Mechanism reach of channel-layer defenses and deployed-side baselines.",
    "Mechanism reach of channel-layer defenses and deployed-side baselines. "
    "Reach = number of the eight real CoT-only leak events the mechanism can observe "
    "or rewrite (8 of 8 = all, 0 of 8 = none); the no-defense control has no mechanism, "
    "so its reach is undefined. Union and Final-only columns give the share of events "
    "covered in each output channel."
): sys.exit(1)

# tab:cross (83 words -> concise)
if not replace_caption(
    "Cross-vendor CoT leak rates on four high-tier probes.",
    "Cross-vendor CoT leak rates on four high-tier probes. "
    "Reference row: the primary model's pooled estimate (the first and second samples, arm A, plus the third sample). "
    "The `$p$ vs. ref.' column is the two-sided Fisher exact $p$ of that model's leak count against the reference row. "
    "All three models show final-channel leak 0/24 (one-sided 95\\% upper bound 11.7\\% each). "
    "Per-model 95\\% CIs for the CoT rates are plotted in Fig.~\\ref{fig:e1cross}."
): sys.exit(1)

# fig:e4consumer right (107 words -> concise)
if not replace_caption(
    "Real end-to-end consumer exposure and measured channel visibility.",
    "Real end-to-end consumer exposure and measured channel visibility. "
    "Left: number of samples from which the downstream consumer recovered at least one honeypot key, "
    "by channel (final: 0 of 32; CoT: 11 of 13 positive samples) and after each output-side filter. "
    "Right: consumer benefit in leak-equivalents per request against channel visibility $p_{cot}$; "
    "the benefit is $p_{cot}\\cdot\\Delta E_{cot}$, so it is zero at $p_{cot}=0$. "
    "The raw CoT reader recovers secrets in 11 of 13 positive samples, while all three output-side filters "
    "drive exposure to zero (paired McNemar exact $p=0.0010$, $n=13$)."
): sys.exit(1)

# --- verify ------------------------------------------------------------------
checks = [
    ("partially constrained by disclosure", 0),
    ("we do not claim represents", 0),
    ("we did not test transfer", 0),
    ("has not been measured with", 0),
]
for pat, exp in checks:
    cnt = s.count(pat)
    if cnt != exp:
        print(f'VERIFY FAIL (leftover): "{pat}" count={cnt} expected={exp}')
        sys.exit(1)
    print(f'VERIFIED: "{pat}" = {cnt}')

# --- write back atomically ---------------------------------------------------
if s == orig:
    print("\nNO CHANGES")
    sys.exit(0)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(s)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print(f"\nWROTE {PATH} ({len(s)} bytes, delta {len(s)-len(orig)})")