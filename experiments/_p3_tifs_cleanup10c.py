#!/usr/bin/env python3
# Pass-10c: fix two remaining Pass-10 artifacts.
import io, sys, os

PATH = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
text = io.open(PATH, encoding='utf-8').read()

PAIRS = [
 # 1. Pass-10 duplicated the existing "Section~\ref{sec:e1}" reference
 (r'''M-C 12.5\%, both on the second gateway of Section~\ref{sec:e1};
Section~\ref{sec:e1}) with the original probe set.''',
  r'''M-C 12.5\%; both on the second gateway of
Section~\ref{sec:e1}, with the original probe set).'''),

 # 2. Pass-10 dropped the right-panel description from the Fig. e4consumer footnote
 (r'{\raggedright\footnotesize Left: the raw CoT reader recovers secrets in 11 of 13 positive samples, while all three output-side defenses drive exposure to zero (paired McNemar exact $p=0.0010$, $n=13$).\par}',
  r'{\raggedright\footnotesize Left: the raw CoT reader recovers secrets in 11 of 13 positive samples, while all three output-side defenses drive exposure to zero (paired McNemar exact $p=0.0010$, $n=13$). Right: consumer exposure grows linearly with channel visibility $p_{cot}$.\par}'),
]

fails = []
for i, (old, new) in enumerate(PAIRS):
    if old not in text:
        fails.append(i)
        print("FAIL pair", i, repr(old[:110]))
if fails:
    print("ABORT: %d pair(s) did not match" % len(fails))
    sys.exit(1)

for old, new in PAIRS:
    text = text.replace(old, new, 1)

tmp = PATH + '.tmp'
with io.open(tmp, 'w', encoding='utf-8', newline='') as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("OK: %d pairs applied, %d bytes" % (len(PAIRS), len(text.encode('utf-8'))))
