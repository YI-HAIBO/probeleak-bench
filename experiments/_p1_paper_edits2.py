#!/usr/bin/env python3
"""P1a/P1c paper edits: E8 body c* validation, Limitations FPR/latency,
Reproducibility release enumeration. Atomic single-pass."""
import os
import sys

P = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"
s = open(P, encoding="utf-8").read()
NL = chr(10)


def j(lines):
    return NL.join(lines)


# (1) E8 body: independent benign validation of c*=0.50
OLD1 = j([
    "fingerprint to rewrite-equivalence classes lowers the residual to 4 of 36 at",
    "a 12.5\\% false-positive rate on the controls, and no radius removes the",
    "residual without also blocking benign traffic---at the smallest radius that",
    "reaches zero, 7 of 8 controls are blocked.",
])
NEW1 = j([
    "fingerprint to rewrite-equivalence classes lowers the residual to 4 of 36 at",
    "a 12.5\\% false-positive rate on the controls---near-miss probes drawn from",
    "other attack families, a deliberately stressful set; the same threshold",
    "blocks none of an independent set of 40 realistic benign CRM requests,",
    "one-sided 95\\% upper bound 7.2\\%, below the 0.15 budget---and no radius removes",
    "the residual without also blocking benign traffic: at the smallest radius",
    "that reaches zero, 7 of 8 controls are blocked.",
])

# (2) Limitations: FPR and latency now measured on real benign traffic
OLD2 = j([
    "False-positive rates, latency, and the observer",
    "confusion matrix are deployment assumptions (the benign sample comprises 4",
    "records; sensitivity sweeps over observer quality change the oracle gap by",
    "only 0.0018), and split-across-boundary leakage remains parameterized rather",
    "than observed, with the zero $\\tau$ residual measured only on the probe",
    "families that produced leaks in the consumer arm.",
])
NEW2 = j([
    "False-positive rates and latency were deployment assumptions resting on a",
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
])

# (3) Reproducibility: enumerate the new artifacts
OLD3 = "windows, and the adaptive-attacker run records on both models; each figure"
NEW3 = j([
    "windows, the adaptive-attacker run records on both models, the benign-traffic",
    "records (40 benign CRM requests per gateway with per-response verdicts and",
    "latency), and the control-expansion records that resolve the last ambiguous",
    "third-gateway backend; each figure",
])

EDITS = [(OLD1, NEW1), (OLD2, NEW2), (OLD3, NEW3)]
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
print("applied %d edits OK; new size %d B" % (len(EDITS), len(s)))
