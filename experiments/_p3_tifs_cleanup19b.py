"""Pass-19b: rule 7 -- merge caption notes into body text.
Insert descriptive sentences after four figures whose caption notes contained
visual-context information not already present in the surrounding prose.
verify-then-apply: each OLD must match exactly once.
"""
import os, sys

TEX = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
NL = chr(10)

EDITS = []

# 1. After fig:e1cross (L687): describe the figure's content.
EDITS.append((
    '\\end{figure*}' + NL + NL +
    '\\subsection{Model Census}',
    '\\end{figure*}' + NL + NL +
    'The figure plots per-model CoT leak rates on the four high-tier probes ' +
    '($n=24$ each) with 95\\% intervals; the dashed reference line marks the ' +
    "primary model's high-tier pooled rate (15/28, 53.6\\%) measured on the " +
    'first gateway and is drawn for comparison only.' + NL + NL +
    '\\subsection{Model Census}'
))

# 2. After fig:corr (L787): describe the legend.
EDITS.append((
    '\\end{figure}' + NL + NL +
    'The simulation treats each layer as having',
    '\\end{figure}' + NL + NL +
    'The discount factor is plotted against $\\rho$; solid = measured, dashed = ' +
    'achievable bound (4.48$\\times$), dotted = errata anchor (7.63$\\times$), and ' +
    'the deployment point is marked. Validation pair $q_a=0.221$, $q_b=0.1513$; ' +
    'the independence prediction is the upper-right corner.' + NL + NL +
    'The simulation treats each layer as having'
))

# 3. After fig:output (L887): describe the axes.
EDITS.append((
    '\\end{figure*}' + NL + NL +
    'To ground Eq.~\\eqref{eq:consumer}, a real downstream consumer was deployed',
    '\\end{figure*}' + NL + NL +
    'The vertical axis is leak rate (\\%); CoT-effective, final-effective, and ' +
    'union leak rates are plotted against output-filter strictness $s$ ' +
    '(3{,}000 probes per point), with the $\\tau$ countermeasure at $s=1$ and the ' +
    'irreducible union floor marked.' + NL + NL +
    'To ground Eq.~\\eqref{eq:consumer}, a real downstream consumer was deployed'
))

# 4. After fig:e4consumer (L920): describe the left/right panels.
EDITS.append((
    '\\end{figure*}' + NL + NL +
    '\\section{Adaptive Defense Under Weak Signal',
    '\\end{figure*}' + NL + NL +
    'The left panel shows the number of samples from which the downstream ' +
    'consumer recovered at least one honeypot key, by channel and after each ' +
    'output-side filter; the right panel plots consumer benefit in ' +
    'leak-equivalents per request against channel visibility $p_{cot}$, which is ' +
    'zero at $p_{cot}=0$.' + NL + NL +
    '\\section{Adaptive Defense Under Weak Signal'
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