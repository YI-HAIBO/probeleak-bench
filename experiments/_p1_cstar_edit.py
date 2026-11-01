#!/usr/bin/env python3
"""Replace the c*-FPR Limitations paragraph with the P1a-resolved version."""
import os
import sys

P = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"
s = open(P, encoding="utf-8").read()
NL = chr(10)

OLD = NL.join([
    "equivalence-class threshold $c^{*}=0.50$ was selected on 8",
    "benign controls (a 12.5\\% false-positive rate of 1/8). A sensitivity sweep over the",
    "measured $c$ grid $\\{0, 0.25, 0.5, 0.75, 1.0\\}$ shows $c^{*}=0.50$ is the chosen value",
    "for all FPR budgets in $[0.125, 0.25]$ (the actual budget 0.15 lies inside this range),",
    "and the only alternative at a tighter budget is $c^{*}=0.25$ with TPR dropping from 0.806",
    "to 0.361. The Wilson 95\\% CI on the $c^{*}=0.50$ FPR is $[0.022, 0.471]$, so the",
    "selection rests on the point estimate rather than a conservative bound; with 8 controls",
    "the FPR is not resolved tightly enough to separate $c^{*}=0.50$ from $c^{*}=0.25$ on the",
    "upper CI alone.",
])

NEW = NL.join([
    "equivalence-class threshold $c^{*}=0.50$ was selected on 8",
    "near-miss controls---probes drawn from other attack families, a deliberately",
    "stressful set for a rewrite filter---of which 1/8 (12.5\\%) is blocked. A sensitivity",
    "sweep over the measured $c$ grid $\\{0, 0.25, 0.5, 0.75, 1.0\\}$ shows $c^{*}=0.50$ is the",
    "chosen value for all FPR budgets in $[0.125, 0.25]$ (the actual budget 0.15 lies",
    "inside this range), and the only alternative at a tighter budget is $c^{*}=0.25$ with",
    "TPR dropping from 0.806 to 0.361. On an independent set of 40 realistic benign CRM",
    "requests---the traffic the filter is deployed to serve---none is blocked at",
    "$c^{*}=0.50$ (one-sided 95\\% upper bound 0.072, below the 0.15 budget), so the",
    "selection rests on a conservative bound for benign traffic, not only on the point",
    "estimate. The near-miss set keeps its 1/8 worst-case rate (Wilson 95\\% CI",
    "$[0.022, 0.471]$), so on adversarially chosen near-miss probes the upper CI still",
    "cannot separate $c^{*}=0.50$ from $c^{*}=0.25$; that residual ambiguity is a property",
    "of the stressful control set rather than of benign traffic.",
])

if s.count(OLD) != 1:
    print("ABORT: anchor matched %d times" % s.count(OLD))
    sys.exit(1)
s = s.replace(OLD, NEW)
tmp = P + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as f:
    f.write(s)
os.replace(tmp, P)
print("c-star paragraph replaced; new size %d B" % len(s))
