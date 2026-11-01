#!/usr/bin/env python3
"""Third compaction: bring net added lines close to zero (16-page target)."""
import os
import sys

P = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"
s = open(P, encoding="utf-8").read()
NL = chr(10)


def j(lines):
    return NL.join(lines)


EDITS = [
    # (1) third-gateway paragraph: 4 lines -> 2 (baseline length) -----------
    (j([
        "(an inverted baseline), and Atria-Dawn-Preview, the last backend left",
        "ambiguous at 1/40 controls, is resolved to clean by a further expansion",
        "to 64 controls: its control rate falls to 1/64 while its attack rate",
        "holds at 5/24 (Fisher $p=0.0053$). Part of",
    ]),
     j([
        "(an inverted baseline), and Atria-Dawn-Preview, ambiguous at 1/40 controls,",
        "resolves to clean at 64 controls (1/64 versus 5/24, $p=0.0053$). Part of",
     ])),
    # (2) Limitations cleanliness classification: 5 -> 4 -------------------
    (j([
        "(CIs overlap). The clean classifications for Agents-A1 and Atria-Dawn were obtained by",
        "expanding the control sample from 8 to 40 per model, and Atria-Dawn-Preview, the last",
        "backend left ambiguous at 1/40 controls, was resolved by a further expansion to 64",
        "controls (1/64 controls versus 5/24 attack, Fisher $p=0.0053$).",
    ]),
     j([
        "(CIs overlap). The clean classifications for Agents-A1 and Atria-Dawn were obtained by",
        "expanding the control sample from 8 to 40 per model; Atria-Dawn-Preview, ambiguous at",
        "1/40 controls, resolves to clean at 64 (1/64 versus 5/24, $p=0.0053$).",
     ])),
    # (3) Limitations FPR/latency: 11 -> 9 ---------------------------------
    (j([
        "probe's leak probability. False-positive rates and latency were deployment",
        "assumptions on 4 benign records; both are now measured: 40 benign CRM requests",
        "that ask for no credential material, run through two gateways under the",
        "deployed prompt with the identical judge, yield no honeypot recitation in",
        "either channel (0/80 pooled, one-sided 95\\% upper bound 3.7\\%) and no refusal,",
        "at median benign latency 8.4\\,s and 19.3\\,s on the two gateways. The observer",
        "confusion matrix remains an assumption (sensitivity sweeps over observer",
        "quality change the oracle gap by only 0.0018), and split-across-boundary",
        "leakage remains parameterized rather than observed, with the zero $\\tau$",
        "residual measured only on the probe families that produced leaks in the",
        "consumer arm.",
    ]),
     j([
        "probe's leak probability. False-positive rates and latency were deployment",
        "assumptions on 4 benign records; both are now measured: 40 benign CRM requests",
        "asking for no credential material, run through two gateways under the deployed",
        "prompt with the identical judge, yield no honeypot recitation and no refusal in",
        "either channel (0/80 pooled, one-sided 95\\% upper bound 3.7\\%), at median benign",
        "latency 8.4\\,s and 19.3\\,s. The observer confusion matrix remains an assumption",
        "(sensitivity sweeps over observer quality change the oracle gap by only 0.0018),",
        "and split-across-boundary leakage remains parameterized rather than observed,",
        "with the zero $\\tau$ residual measured only on the probe families that produced",
        "leaks in the consumer arm.",
     ])),
    # (4) c* paragraph: 11 -> 9 --------------------------------------------
    (j([
        "equivalence-class threshold $c^{*}=0.50$ was selected on 8 near-miss",
        "controls---probes from other attack families---of which 1/8 (12.5\\%) is blocked.",
        "A sensitivity sweep over the measured $c$ grid $\\{0, 0.25, 0.5, 0.75, 1.0\\}$ shows",
        "$c^{*}=0.50$ is chosen for all FPR budgets in $[0.125, 0.25]$ (the actual budget",
        "0.15 lies inside), and the only alternative at a tighter budget is $c^{*}=0.25$",
        "with TPR dropping from 0.806 to 0.361. None of 40 independent benign CRM",
        "requests is blocked at $c^{*}=0.50$ (one-sided 95\\% upper bound 0.072), so for",
        "benign traffic the selection rests on a conservative bound. The near-miss set",
        "keeps its 1/8 worst-case rate (Wilson 95\\% CI $[0.022, 0.471]$), so on",
        "adversarially chosen near-miss probes the upper CI still cannot separate",
        "$c^{*}=0.50$ from $c^{*}=0.25$.",
    ]),
     j([
        "equivalence-class threshold $c^{*}=0.50$ was selected on 8 near-miss controls---",
        "probes from other attack families---of which 1/8 (12.5\\%) is blocked. A sensitivity",
        "sweep over the measured $c$ grid $\\{0, 0.25, 0.5, 0.75, 1.0\\}$ shows $c^{*}=0.50$ is",
        "chosen for all FPR budgets in $[0.125, 0.25]$ (the actual budget 0.15 lies inside),",
        "and the only alternative at a tighter budget is $c^{*}=0.25$ with TPR dropping from",
        "0.806 to 0.361. None of 40 independent benign CRM requests is blocked at $c^{*}=0.50$",
        "(one-sided 95\\% upper bound 0.072), so for benign traffic the selection rests on a",
        "conservative bound. The near-miss set keeps its 1/8 worst-case rate (Wilson 95\\% CI",
        "$[0.022, 0.471]$), so on adversarially chosen near-miss probes the upper CI still",
        "cannot separate $c^{*}=0.50$ from $c^{*}=0.25$.",
     ])),
    # (5) Reproducibility: revert to baseline wording ----------------------
    ("windows, the adaptive-attacker run records on both models, the benign-traffic" + NL
     + "records, and the control-expansion records for the last ambiguous backend; each" + NL
     + "figure",
     "windows, and the adaptive-attacker run records on both models; each figure"),
]

for i, (old, new) in enumerate(EDITS, 1):
    n = s.count(old)
    if n != 1:
        print("ABORT edit %d: anchor matched %d times" % (i, n))
        print(repr(old[:110]))
        sys.exit(1)
    s = s.replace(old, new)

tmp = P + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as f:
    f.write(s)
os.replace(tmp, P)
print("compacted %d regions; lines now %d" % (len(EDITS), s.count(NL) + 1))
