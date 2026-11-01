# -*- coding: utf-8 -*-
"""Pass-5 on p3_tifs.tex: undefined-number clarifications from the Turn-4 list.

Targets the remaining "undefined number" items that a first reader cannot
interpret without prior knowledge of the experiment. Each pair adds a short
inline definition or source pointer; no number is changed.
"""
import os, re

PATH = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

with open(PATH, "r", encoding="utf-8") as f:
    text = f.read()

def to_regex(s):
    parts = re.split(r"\s+", s)
    return r"\s+".join(re.escape(p) for p in parts)

PAIRS = [
# N1: "rank correlation ... flattened from 0.93 to 0.05" -> name the metric
("rewrote the per-layer marginals at $\\rho=1$ (rank correlation between layer\n"
 "strength and measured bypass flattened from 0.93 to 0.05). The original",
 "rewrote the per-layer marginals at $\\rho=1$ (the Spearman rank correlation\n"
 "between layer strength and measured bypass probability dropped from 0.93 to\n"
 "0.05, so the binding branch no longer couples the two layers). The original"),

# N2: "split-across-boundary leakage is parameterized at 0.05" -> name the parameter
("split-across-boundary leakage is parameterized at 0.05 in the calibrated model,\n"
 "where it predicts a residual of 5.8\\% for the adaptive agent).",
 "split-across-boundary leakage is parameterized at 0.05 (the probability that a\n"
 "credential appearing split across the reasoning/final boundary is recoverable\n"
 "by a consumer; a calibration parameter, not a measurement) in the calibrated\n"
 "model, where it predicts a residual of 5.8\\% for the adaptive agent)."),

# N3: expected-utility gap (0.26 / 0.576) -> name the quantity
("between configurations (0.26 in the simulated world) is much smaller than the\n"
 "per-request reward standard deviation (0.50), so per-request rewards cannot\n"
 "separate configurations online. In the real-calibrated world the gap is larger\n"
 "(0.576) but the events are much rarer (13.7\\% versus 44.1\\% no-defense leak\n"
 "rate), so observations are dominated by benign outcomes.",
 "between configurations---the expected-utility difference between the best and\n"
 "second-best arm, 0.26 in the simulated world---is much smaller than the\n"
 "per-request reward standard deviation (0.50), so per-request rewards cannot\n"
 "separate configurations online. In the real-calibrated world that gap is\n"
 "larger (0.576) but the events are much rarer (13.7\\% versus 44.1\\% no-defense\n"
 "leak rate), so observations are dominated by benign outcomes."),

# N4: "oracle regret 0.0216 and 0.0080" -> define regret
("regret 0.0216 and 0.0080 respectively; the naive bandit gains",
 "regret (the per-request utility the oracle would earn minus the agent's actual\n"
 "utility, 0.0216 and 0.0080 respectively); the naive bandit gains"),

# N5: "oracle gap at the shift generation 0.0088 versus a pre-shift median of 0.0186"
("oracle gap at the shift generation 0.0088 versus a pre-shift median of 0.0186)",
 "oracle-agent utility gap at the shift generation 0.0088 versus a pre-shift median\n"
 "of 0.0186"),

# N6: "the literature-anchored value is v~0.55" -> name the source
("normalized so that $v=1$ means the leak is eliminated, $v=0$ means no change, and\n"
 "$v<0$ means the leak worsens (the literature-anchored value is $v\\approx0.55$).",
 "normalized so that $v=1$ means the leak is eliminated, $v=0$ means no change, and\n"
 "$v<0$ means the leak worsens. The literature-anchored value $v\\approx0.55$ is\n"
 "the reduction implied by the violation-rate finding of~\\cite{rbac2026}, not an\n"
 "independent measurement; it is shown here only as a reference point."),

# N7: "observer quality (0.55--0.95)" -> define the metric
("observer quality (0.55--0.95) change the oracle gap by only 0.0018.",
 "observer quality---the true-positive rate of the deployed attack classifier at\n"
 "a fixed false-positive rate, swept from 0.55 to 0.95---changes the oracle gap\n"
 "by only 0.0018."),
]

ok = True
for i, (old, new) in enumerate(PAIRS):
    rx = to_regex(old)
    n = len(re.findall(rx, text))
    if n != 1:
        print("pair %d: regex found %d matches (need 1):" % (i + 1, n))
        print("OLD:", repr(old[:140]))
        ok = False
        continue
    text = re.sub(rx, lambda m: new, text, count=1)

if not ok:
    print("ABORTING - no file written.")
    raise SystemExit(1)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("OK: %d pairs applied, %d bytes" % (len(PAIRS), os.path.getsize(PATH)))