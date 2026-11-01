"""Pass-19a: caption shortening (rule 6) + note stripping (rule 7 partial).
All 13 captions -> <=15 words, no formulas, no standalone notes.
verify-then-apply: each OLD must match exactly once before writing.
Double-quoted Python strings to host LaTeX apostrophes safely.
"""
import os, sys

TEX = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
NL = chr(10)

EDITS = []

# 1. fig:framework (L291-295)
EDITS.append((
    "\\caption{Measured agent stack. A user prompt passes an input-side" + NL +
    "content-safety gateway, then the reasoning model, which returns two streams:" + NL +
    "the reasoning trace and the final answer. Output-side filtering (parameterized by strictness $s$), literal scrubbing ($\\tau$), and the consumer's" + NL +
    "channel visibility $p_{cot}\\in[0,1]$ act after generation; input-side rewriting" + NL +
    "(coverage $c\\in[0,1]$) acts on the request before the model.}",
    "\\caption{Measured agent stack with input-side rewriting and output-side filtering.}"
))

# 2. tab:cot (L463-469)
EDITS.append((
    "\\caption{CoT-native blind spot on a real reasoning model, three independent" + NL +
    "samples. Counts in parentheses are leak events; rates are computed over" + NL +
    "effective attacks. Effective attack $N$ is below `requests sent' because" + NL +
    "gateway-blocked prompts, benign probes, negative controls, and failed requests" + NL +
    "are excluded; the two counts therefore differ by more than the gateway-block" + NL +
    "column. `Gateway blocks' counts sent requests rejected upstream by the" + NL +
    "content-safety layer before reaching the model.}",
    "\\caption{CoT-native blind spot on a real reasoning model, three independent samples.}"
))

# 3. tab:permode (L501-504)
EDITS.append((
    "\\caption{Per-attack-class results on the real model. $n$ is the number of" + NL +
    "scorable repeats, at 4 repeats per probe; the probe counts per class are 4, 4," + NL +
    "2, 4, 4, 5, and 6 (Prefix, Step, Tool, Reasoning, Thinking, SQL, Jailbreak)," + NL +
    "giving $n = 16, 16, 8, 16, 16, 20, 24$.}",
    "\\caption{Per-attack-class results on the real model, by attack class.}"
))

# 4. tab:cohort (L555)
EDITS.append((
    "\\caption{Pooled real-gateway sample by cohort. Wilson 95\\% intervals: diverse CoT [10.83, 19.27], repetition CoT [96.40, 100.00], grand-pool CoT [33.47, 43.32]; grand-pool final [14.97, 22.87]. The ``Experiments'' column counts contributing campaigns; the ``$N$'' column gives effective attacks per cohort.}",
    "\\caption{Pooled real-gateway sample by cohort with 95\\% intervals.}"
))

# 5. fig:simvsreal (L604-609)
EDITS.append((
    "\\caption{Per-attack-class CoT leak rates: simulation versus the real model." + NL +
    "Bars give the CoT leak rate for each attack class and are labelled with the" + NL +
    "percentage; simulated bars come from the simulated world model (no error bars," + NL +
    "being model-generated), real bars from the second sample ($N=112$ effective" + NL +
    "attacks; Wilson 95\\% intervals for these rates are in Fig.~\\ref{fig:e6ci}); both" + NL +
    "bar series cover the same five attack classes.}",
    "\\caption{Per-attack-class CoT leak rates: simulation versus the real model.}"
))

# 6. fig:e6ci (L623-626)
EDITS.append((
    "\\caption{Per-class reasoning-channel leak rates and 95\\% intervals for the second, third, and" + NL +
    "pooled (the second and third samples combined). Points show the CoT leak rate by attack class;" + NL +
    "horizontal bars show Wilson 95\\% intervals; the vertical dashed line marks the" + NL +
    "pooled rate (the second, third, and pooled are distinguished by point shape: circle, square, triangle).}",
    "\\caption{Per-class reasoning-channel leak rates with 95\\% intervals.}"
))

# 7. tab:e1cross (L648)
EDITS.append((
    "\\caption{Cross-vendor CoT leak rates on four high-tier probes. Reference row: the primary model's pooled estimate (the first and second samples, arm A, plus the third sample). The `$p$ vs. ref.' column is the two-sided Fisher exact $p$ of that model's leak count against the reference row. All three models show final-channel leak 0/24 (one-sided 95\\% upper bound 11.7\\% each). Per-model 95\\% CIs for the CoT rates are plotted in Fig.~\\ref{fig:e1cross}.}",
    "\\caption{Cross-vendor CoT leak rates on four high-tier probes.}"
))

# 8. fig:e1cross (L706-711)
EDITS.append((
    "\\caption{Cross-vendor CoT leak rates and 95\\% intervals on the second gateway" + NL +
    "(AtlasCloud). Points are per-model CoT" + NL +
    "leak rates on the four high-tier probes ($n=24$ each) and bars are 95\\%" + NL +
    "intervals. The dashed reference line is the primary model's high-tier pooled" + NL +
    "estimate (15/28, 53.6\\%) measured on the \\emph{first} gateway and is drawn for" + NL +
    "comparison only.}",
    "\\caption{Cross-vendor CoT leak rates on the second gateway.}"
))

# 9. fig:corr (L810)
EDITS.append((
    "\\caption{Joint-residual discount versus the independence prediction. The discount factor is plotted against $\\rho$; solid = measured, dashed = achievable bound (4.48$\\times$), dotted = errata anchor (7.63$\\times$), marked = deployment point. Validation pair $q_a=0.221$, $q_b=0.1513$; the independence prediction is the upper-right corner.}",
    "\\caption{Joint-residual discount versus the independence prediction.}"
))

# 10. fig:output (L911-915)
EDITS.append((
    "\\caption{Output-side filtering displaces rather than removes leakage (simulated world)." + NL +
    "The vertical axis is leak rate (\\%); CoT-effective, final-effective, and union" + NL +
    "leak rates are plotted against output-filter strictness $s$ (3{,}000 probes per" + NL +
    "point); the $\\tau$ countermeasure at $s=1$ and the" + NL +
    "irreducible union floor are marked.}",
    "\\caption{Output-side filtering displaces rather than removes leakage.}"
))

# 11. fig:e4consumer (L947)
EDITS.append((
    "\\caption{Real end-to-end consumer exposure and measured channel visibility. Left: number of samples from which the downstream consumer recovered at least one honeypot key, by channel (final: 0 of 32; CoT: 11 of 13 positive samples) and after each output-side filter. Right: consumer benefit in leak-equivalents per request against channel visibility $p_{cot}$; the benefit is $p_{cot}\\cdot\\Delta E_{cot}$, so it is zero at $p_{cot}=0$. The raw CoT reader recovers secrets in 11 of 13 positive samples, while all three output-side filters drive exposure to zero (paired McNemar exact $p=0.0010$, $n=13$).}",
    "\\caption{Real end-to-end consumer exposure by channel and filter.}"
))

# 12. tab:agent (L1001)
EDITS.append((
    "\\caption{Adaptive defense agents under two world models. Utility per request at $\\lambda=2$ (leak rate in parentheses); higher utility means lower leak rate. The model-driven pooling agent outperforms the static baseline in both worlds.}",
    "\\caption{Adaptive defense agents under two world models.}"
))

# 13. tab:reach (L1092)
EDITS.append((
    "\\caption{Mechanism reach of channel-layer defenses and deployed-side baselines. Reach = number of the eight real CoT-only leak events the mechanism can observe or rewrite (8 of 8 = all, 0 of 8 = none); the no-defense control has no mechanism, so its reach is undefined. Union and Final-only columns give the share of events covered in each output channel.}",
    "\\caption{Mechanism reach of channel-layer defenses and deployed-side baselines.}"
))

# --- verify-then-apply ---
s = open(TEX, encoding='utf-8').read()
orig = s
for i, (old, new) in enumerate(EDITS):
    cnt = s.count(old)
    if cnt != 1:
        print('EDIT %d VERIFY FAIL count=%d' % (i + 1, cnt))
        print('  OLD prefix:', repr(old[:100]))
        sys.exit(1)
    s = s.replace(old, new, 1)
    print('EDIT %d OK' % (i + 1))

# brace balance
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