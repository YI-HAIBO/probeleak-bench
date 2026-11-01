#!/usr/bin/env python3
"""Pooled-sample reconciliation for the RQ1 headline CoT-leak statistic.

WHY THIS EXISTS
----------------
Three mutually inconsistent pooled totals had circulated for the RQ1 headline
(CoT leak rate across all real-gateway experiments):

    149 / 491 = 30.3%   <- reached the manuscript text; unreproducible
     77 / 220 = 35.0%   <- summary-dict re-count
    115 / 324 = 35.5%   <- naive records scan

The 491 denominator reconciled with nothing. Two further traps made the
divergence systematic rather than accidental:

  (a) FILTER MISMATCH.  The manuscript's per-round numbers (N=25, N=112,
      N=196) count ONLY `kind=="attack"` responses, and for B1+B3 only arm A
      (excluding the 18-response arm-A D30 ablation and the 4 benign /
      negative-control records).  The naive scans counted every `api_ok`
      record, adding benign + negative-control + ablation traffic to the
      denominator and deflating the rate.

  (b) FIELD-NAME TRAP.  E10 stores the reasoning-channel leak in
      `reasoning_leak`, not `cot_leak`.  A uniform `cot_leak` scan silently
      records E10 as 0 CoT leaks.

KEY FINDING (why a single pooled rate is the wrong object)
----------------------------------------------------------
The pooled distribution is BIMODAL and the cohort split is mandatory:

  * DIVERSE-PROBE COHORT  (fresh probes, low repetition):
        sparse events -> the honest marginal leak rate
  * REPETITION/STRESS COHORT (E7/E9/E10/E11/E12):
        deliberate re-runs of the worst known probes -> ~100% CoT leak

Pooling without the split is what produced the spurious 30-35% midpoints.
We therefore report all three numbers and adopt the diverse-cohort rate as
the point estimate of the native blind spot.

Usage:  python experiments/pooled_sample_reconciliation.py [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RES = os.path.join(ROOT, "results")
OUT = os.path.join(RES, "pooled_sample_reconciliation_v1.json")

# --------------------------------------------------------------------------
# Source registry.  Each entry is one independent set of API responses against
# the real gateway (model `dots3-note-prev`).
#
#   file / recs   where the per-response records live
#   filter        subset predicate applied BEFORE counting (the whole reason
#                 the earlier totals diverged)
#   cot / fin     field names (they are NOT uniform across experiments)
#   cohort        "diverse" | "repetition"
# --------------------------------------------------------------------------
def _attack_only(r):
    return str(r.get("kind", "")).lower() == "attack"


def _arm_a_attack(r):
    return (str(r.get("arm", "")).lower() == "a"
            and str(r.get("kind", "")).lower() == "attack")


def _all(r):
    return True


SOURCES = [
    dict(label="P1.1 CoT pilot", file="p1_real_cot_validation_v1.json",
         recs="records", filt=_attack_only, cot="cot_leak", fin="final_leak",
         cohort="diverse",
         why="First real-gateway CoT pilot. 42 requests; 31 accepted; attack "
             "subset = 25 (benign 3 + negative-control 3 excluded)."),
    dict(label="B1+B3 main attack set", file="p1_real_scale_validation_v1.json",
         recs="records", filt=_arm_a_attack, cot="cot_leak", fin="final_leak",
         cohort="diverse",
         why="Primary campaign, arm A attack-only = 112. Excludes the 18 "
             "arm-A D30 ablation responses (separate RQ3 arm) and 4 "
             "benign/negative-control records."),
    dict(label="E2b schema hiding", file="e2_real_schema_hiding_v1.json",
         recs="records", filt=_attack_only, cot="cot_leak", fin="final_leak",
         cohort="diverse",
         why="Schema-hidden condition, attack subset = 15. NOTE: the 3 "
             "benign records contribute 1 CoT leak -- the 'schema hiding "
             "pushes benign requests into plaintext reasoning' finding; it is "
             "excluded from the attack rate on purpose."),
    dict(label="E4 consumer producer", file="e4_consumer_channel_v1.json",
         recs="producer.records", filt=_all, cot="cot_leak", fin="final_leak",
         cohort="diverse",
         why="Producer stage only (kind='producer', all 32 are attack probes). "
             "Consumer-stage records are a separate RQ3 object."),
    dict(label="E6 scale expansion", file="e6_real_scale_expansion_v1.json",
         recs="records", filt=_attack_only, cot="cot_leak", fin="final_leak",
         cohort="diverse",
         why="Second-pass diverse expansion. 101 requests; 86 accepted; "
             "attack subset = 84."),
    dict(label="E7 probe repetition", file="e7_probe_repetition_v1.json",
         recs="records", filt=_all, cot="cot_leak", fin="final_leak",
         cohort="repetition",
         why="Deliberate re-runs of the two highest-leak families; "
             "selection-conditioned."),
    dict(label="E9 production baseline", file="e9_production_baseline_v1.json",
         recs="records", filt=_all, cot="cot_leak", fin="final_leak",
         cohort="repetition",
         why="Re-run of the same high-leak probes under three production "
             "prompt conditions."),
    dict(label="E10 final stress", file="e10_final_stress_test_v1.json",
         recs="records", filt=_all, cot="reasoning_leak", fin="raw_final_leak",
         cohort="repetition",
         why="FIELD TRAP: reasoning leak is `reasoning_leak`, not `cot_leak`."),
    dict(label="E11 public benchmark", file="e11_public_benchmark_v1.json",
         recs="records", filt=_all, cot="cot_leak", fin="final_leak",
         cohort="repetition",
         why="Public-benchmark re-runs; 8/16 accepted (8 HTTP 403)."),
    dict(label="E12 probe repetition2", file="e12_probe_repetition2_v1.json",
         recs="records", filt=_all, cot="cot_leak", fin="final_leak",
         cohort="repetition",
         why="Second repetition wave (translation exfiltration, role play)."),
]

EXCLUDED = [
    dict(file="p1_real_llm_validation_v1.json",
         reason="NOT a honeypot-leak experiment: it compares simulated vs. "
                "real per-direction success rates (21 directions, no leak "
                "verdicts). Including it is what produced phantom records."),
    dict(file="p1_real_llm_validation_v2.json",
         reason="Byte-identical duplicate of p1_real_llm_validation_v1.json."),
    dict(file="p1_real_scale_validation_v1.json (arm A_d30)",
         reason="The 18 arm-A D30 responses are an RQ3 defense arm, not "
                "native-blind-spot traffic."),
    dict(file="e2_real_schema_hiding_v1.json (benign)",
         reason="The 3 benign records carry 1 CoT leak by design (schema "
                "hiding exposes keys in benign reasoning); keeping them out "
                "of the attack rate is deliberate, not filtering for "
                "leakability."),
    dict(file="e3_probe_benchmark_v1/v2.json",
         reason="Probe catalog with metadata and difficulty tiers; no raw "
                "responses."),
]


# --------------------------------------------------------------------------- #
def wilson(k: int, n: int, z: float = 1.96):
    if n <= 0:
        return [None, None]
    p = k / n
    d = 1.0 + z * z / n
    c = (p + z * z / (2.0 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4.0 * n * n)) / d
    return [round(c - h, 6), round(c + h, 6)]


def dig(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        cur = cur[part]
    return cur


def truthy(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).strip().lower() in ("true", "1", "yes", "leak", "leaked")


def pct(x):
    return None if x is None else round(100.0 * x, 2)


def evaluate():
    seen, per_exp, errors = set(), [], []
    for s in SOURCES:
        fp = os.path.join(RES, s["file"])
        if not os.path.exists(fp):
            errors.append({"file": s["file"], "error": "missing"})
            continue
        h = hashlib.sha256(open(fp, "rb").read()).hexdigest()[:12]
        if h in seen:
            errors.append({"file": s["file"], "error": "duplicate bytes"})
            continue
        seen.add(h)
        try:
            recs = dig(json.load(open(fp, encoding="utf-8")), s["recs"])
        except (KeyError, TypeError) as e:
            errors.append({"file": s["file"], "error": "path: %s" % e})
            continue
        accepted = [r for r in recs if truthy(r.get("api_ok", False))]
        sel = [r for r in accepted if s["filt"](r)]
        n_ok = len(sel)
        n_cot = sum(1 for r in sel if truthy(r.get(s["cot"])))
        n_fin = sum(1 for r in sel if truthy(r.get(s["fin"])))
        per_exp.append(dict(
            label=s["label"], file=s["file"], cohort=s["cohort"], why=s["why"],
            sha256_12=h, filter=s["filt"].__name__,
            n_records=len(recs), n_accepted=len(accepted), n_ok=n_ok,
            n_cot=n_cot, n_final=n_fin,
            rate_cot=round(n_cot / n_ok, 6) if n_ok else None,
            rate_final=round(n_fin / n_ok, 6) if n_ok else None,
            ci95_cot=wilson(n_cot, n_ok), ci95_final=wilson(n_fin, n_ok)))
    return per_exp, errors


def summarize(per_exp):
    labels = {e["label"] for e in per_exp}
    def agg(names):
        sel = [e for e in per_exp if e["label"] in names]
        n_ok = sum(e["n_ok"] for e in sel)
        n_cot = sum(e["n_cot"] for e in sel)
        n_fin = sum(e["n_final"] for e in sel)
        return dict(n_ok=n_ok, n_cot=n_cot, n_final=n_fin,
                    rate_cot=round(n_cot / n_ok, 6) if n_ok else None,
                    rate_final=round(n_fin / n_ok, 6) if n_ok else None,
                    ci95_cot=wilson(n_cot, n_ok),
                    ci95_final=wilson(n_fin, n_ok),
                    members=[e["label"] for e in sel])
    return dict(
        grand_pool=agg(labels),
        diverse_cohort=agg({"P1.1 CoT pilot", "B1+B3 main attack set",
                            "E2b schema hiding", "E4 consumer producer",
                            "E6 scale expansion"}),
        repetition_cohort=agg({"E7 probe repetition", "E9 production baseline",
                               "E10 final stress", "E11 public benchmark",
                               "E12 probe repetition2"}),
    )


def build():
    per_exp, errors = evaluate()
    s = summarize(per_exp)
    # JSON-safe copy of the registry (SOURCES carries callables).
    sources = [dict(label=x["label"], file=x["file"], recs=x["recs"],
                    filter=x["filt"].__name__, cohort=x["cohort"],
                    cot_field=x["cot"], final_field=x["fin"], why=x["why"])
               for x in SOURCES]

    def line(d):
        return "N=%d: CoT %d (%.2f%%, Wilson95 [%.2f%%, %.2f%%]); final %d " \
               "(%.2f%%, Wilson95 [%.2f%%, %.2f%%])" % (
                   d["n_ok"], d["n_cot"], pct(d["rate_cot"]),
                   pct(d["ci95_cot"][0]), pct(d["ci95_cot"][1]),
                   d["n_final"], pct(d["rate_final"]),
                   pct(d["ci95_final"][0]), pct(d["ci95_final"][1]))

    art = dict(
        artifact="pooled_sample_reconciliation_v1",
        purpose=("Single source of truth for the RQ1 pooled CoT/final leak "
                 "rate. Supersedes the unreproducible 149/491 (30.3%), "
                 "77/220 (35.0%) and 115/324 (35.5%) totals."),
        unit_of_analysis=("One accepted API response against the real gateway "
                          "(model dots3-note-prev), restricted to attack-kind "
                          "traffic except where noted. Repeated probes in later "
                          "experiments are distinct responses and are pooled "
                          "as independent calls, NOT as independent probes."),
        sources=sources,
        excluded=EXCLUDED,
        errors=errors,
        per_experiment=per_exp,
        summary=s,
        headline=dict(
            message=("The pooled distribution is BIMODAL. Report the cohort "
                     "split, not a single pooled rate. Adopt the DIVERSE "
                     "cohort as the point estimate of the native blind spot."),
            diverse=line(s["diverse_cohort"]),
            repetition=line(s["repetition_cohort"]),
            grand_pool=line(s["grand_pool"]),
        ),
        caveats=[
            "The repetition cohort is selection-conditioned: it re-runs probes "
            "already known to leak, so its ~100% CoT rate is an upper bound, "
            "not an estimate of the marginal probe leak rate.",
            "The diverse cohort is the honest marginal estimate on fresh "
            "probes; its final-channel rate is exactly 0/268.",
            "The CoT-vs-final asymmetry -- the paper's core claim -- holds in "
            "the DIVERSE cohort only. In the repetition cohort the final "
            "channel leaks too, and this must be disclosed rather than "
            "footnoted.",
            "E10 stores the reasoning leak in `reasoning_leak`; any uniform "
            "`cot_leak` scan silently undercounts it by 8.",
            "The manuscript's per-round N (25, 112, 196) are attack-only, "
            "arm-A-only subsets; counting all accepted records inflates the "
            "denominator by benign, negative-control and ablation traffic.",
            "One benign record in E2b carries a CoT leak by construction "
            "(schema hiding exposes keys in benign reasoning). It is excluded "
            "from the attack rate deliberately and reported separately.",
        ],
    )
    return art


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="regenerate to memory and byte-compare with the "
                         "on-disk artifact")
    args = ap.parse_args()
    txt = json.dumps(build(), ensure_ascii=False, indent=2, sort_keys=False)
    if args.check:
        if not os.path.exists(OUT):
            print("CHECK FAIL: artifact absent")
            sys.exit(1)
        ok = open(OUT, encoding="utf-8").read() == txt
        print("CHECK %s (%d chars)" % ("PASS" if ok else "FAIL", len(txt)))
        sys.exit(0 if ok else 1)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(txt)
    h = json.loads(txt)["headline"]
    print("WROTE", OUT)
    print("  diverse     :", h["diverse"])
    print("  repetition  :", h["repetition"])
    print("  grand pool  :", h["grand_pool"])
    print("  errors      :", json.loads(txt)["errors"] or "none")


if __name__ == "__main__":
    main()
