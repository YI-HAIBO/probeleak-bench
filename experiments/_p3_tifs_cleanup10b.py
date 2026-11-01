#!/usr/bin/env python3
# Pass-10b: repair defects introduced by Pass-10's own rewrites.
import io, sys, os

PATH = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
text = io.open(PATH, encoding='utf-8').read()

PAIRS = [
 # 1. E7/E12 paragraph: Pass-10 duplicated "12 attack modes at 3 repetitions each"
 (r'''\textbf{Anti-cherry-picking.} An earlier, broader probe expansion ran 12 attack modes at 3 repetitions each and appeared to suggest the probe set was not
selective: of 12 attack modes at 3 repetitions each, 10 produced''',
  r'''\textbf{Anti-cherry-picking.} An earlier, broader probe expansion (E7) ran 12 attack modes at 3 repetitions each and appeared to suggest the probe set was not
selective: 10 of the 12 modes produced'''),

 # 2. Reproducibility gate: Pass-10 left two near-identical clauses
 (r'''\textbf{Reproducibility failure is itself a result.} A gate asserting identical
(final, CoT, refusal) classification over repeats of the same probe
\emph{failed} in the B3 sample: the gate compares the verdict triple
(final leak, CoT leak, refusal) across repeats of the same probe, so its
unit is the probe rather than the request:''',
  r'''\textbf{Reproducibility failure is itself a result.} A gate asserting identical
(final, CoT, refusal) verdicts \emph{failed} in the B3 sample: it compares
the verdict triple across repeats of the same probe, so its unit is the probe
rather than the request:'''),

 # 3. "described above Section~\ref{sec:output})" -- stranded "of"
 (r'''described above
Section~\ref{sec:output}) has no''',
  r'''in
Section~\ref{sec:output}) has no'''),

 # 4. Clunky mid-sentence parenthetical for E
 (r'''These consumer-exposure endpoints ($E$ denotes consumer exposure), $E_{final}=0$ and $E_{cot}=0.344$
(Fig.~\ref{fig:e4consumer}), replace the modeled parameters of''',
  r'''These endpoints, $E_{final}=0$ and $E_{cot}=0.344$ ($E$ denotes consumer
exposure; Fig.~\ref{fig:e4consumer}), replace the modeled parameters of'''),
]

fails = []
for i, (old, new) in enumerate(PAIRS):
    if old not in text:
        fails.append(i)
        print("FAIL pair", i, repr(old[:100]))
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
