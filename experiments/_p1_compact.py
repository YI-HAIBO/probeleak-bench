#!/usr/bin/env python3
"""Compact the P1 insertions so the manuscript returns to 16 pages."""
import os
import sys

P = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"
s = open(P, encoding="utf-8").read()
NL = chr(10)


def j(lines):
    return NL.join(lines)


EDITS = [
    # (1) E8 body -----------------------------------------------------------
    (j([
        "fingerprint to rewrite-equivalence classes lowers the residual to 4 of 36 at",
        "a 12.5\\% false-positive rate on the controls---near-miss probes drawn from",
        "other attack families, a deliberately stressful set; the same threshold",
        "blocks none of an independent set of 40 realistic benign CRM requests,",
        "one-sided 95\\% upper bound 7.2\\%, below the 0.15 budget---and no radius removes",
        "the residual without also blocking benign traffic: at the smallest radius",
        "that reaches zero, 7 of 8 controls are blocked.",
    ]),
     j([
        "fingerprint to rewrite-equivalence classes lowers the residual to 4 of 36 at",
        "a 12.5\\% false-positive rate on the controls---near-miss probes from other",
        "attack families---while blocking none of 40 independent benign CRM requests",
        "(one-sided 95\\% upper bound 7.2\\%, budget 0.15), and no radius removes the",
        "residual without also blocking benign traffic: at the smallest radius that",
        "reaches zero, 7 of 8 controls are blocked.",
     ])),
    # (2) Limitations FPR/latency -------------------------------------------
    (j([
        "probe's leak probability. False-positive rates and latency were deployment assumptions resting on a",
        "benign sample of 4 records; both are now measured on real benign traffic.",
        "Forty realistic CRM requests, none of which asks for credential material,",
        "were sent through two gateways under the deployed system prompt and scored",
        "with the identical string judge: no response on either gateway recites a",
        "honeypot credential in either channel (0/40 and 0/40; 0/80 pooled, one-sided",
        "95\\% upper bound 3.7\\%) and none is refused, with median benign latency",
        "8.4\\,s on the primary gateway and 19.3\\,s on the third. The observer confusion",
        "matrix remains a deployment assumption (sensitivity sweeps over observer",
        "quality change the oracle gap by only 0.0018), and split-across-boundary",
        "leakage remains parameterized rather than observed, with the zero $\\tau$",
        "residual measured only on the probe families that produced leaks in the",
        "consumer arm.",
    ]),
     j([
        "probe's leak probability. False-positive rates and latency were deployment",
        "assumptions on 4 benign records; both are now measured: 40 benign CRM requests",
        "that ask for no credential material, sent through two gateways under the",
        "deployed prompt and scored with the identical judge, yield no honeypot",
        "recitation in either channel (0/40 and 0/40; 0/80 pooled, one-sided 95\\%",
        "upper bound 3.7\\%) and no refusal, at median benign latency 8.4\\,s on the",
        "primary gateway and 19.3\\,s on the third. The observer confusion matrix",
        "remains an assumption (sensitivity sweeps over observer quality change the",
        "oracle gap by only 0.0018), and split-across-boundary leakage remains",
        "parameterized rather than observed, with the zero $\\tau$ residual measured",
        "only on the probe families that produced leaks in the consumer arm.",
     ])),
    # (3) c* paragraph ------------------------------------------------------
    (j([
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
    ]),
     j([
        "equivalence-class threshold $c^{*}=0.50$ was selected on 8 near-miss",
        "controls---probes from other attack families, a stressful set for a rewrite",
        "filter---of which 1/8 (12.5\\%) is blocked. A sensitivity sweep over the measured",
        "$c$ grid $\\{0, 0.25, 0.5, 0.75, 1.0\\}$ shows $c^{*}=0.50$ is chosen for all FPR",
        "budgets in $[0.125, 0.25]$ (the actual budget 0.15 lies inside), and the only",
        "alternative at a tighter budget is $c^{*}=0.25$ with TPR dropping from 0.806 to",
        "0.361. None of 40 independent benign CRM requests is blocked at $c^{*}=0.50$",
        "(one-sided 95\\% upper bound 0.072), so for benign traffic the selection rests on",
        "a conservative bound rather than the point estimate. The near-miss set keeps its",
        "1/8 worst-case rate (Wilson 95\\% CI $[0.022, 0.471]$), so on adversarially chosen",
        "near-miss probes the upper CI still cannot separate $c^{*}=0.50$ from $c^{*}=0.25$.",
     ])),
    # (4) Reproducibility ---------------------------------------------------
    (j([
        "windows, the adaptive-attacker run records on both models, the benign-traffic",
        "records (40 benign CRM requests per gateway with per-response verdicts and",
        "latency), and the control-expansion records that resolve the last ambiguous",
        "third-gateway backend; each figure",
    ]),
     j([
        "windows, the adaptive-attacker run records on both models, the benign-traffic",
        "records (40 benign CRM requests per gateway), and the control-expansion records",
        "for the last ambiguous backend; each figure",
     ])),
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
print("compacted %d regions; new size %d B" % (len(EDITS), len(s)))
