#!/usr/bin/env python3
r"""M8 closure: quantifying "clean probe-attributed comparison" on the third gateway.

The EIC review's M8 concern: of "3 operators / 15 backends", only the primary
gateway provides clean probe-attributed comparisons; the third gateway's control
baseline is noisy (N_D controls leak at 6/8 = 75%, higher than its attack rate).

This script quantifies cleanliness per model on the third gateway:

  1. control leak rate + Wilson CI
  2. high-tier attack leak rate + Wilson CI
  3. whether the control upper bound is below the attack lower bound
     (i.e., whether the separation is robust to sampling noise)
  4. Fisher exact p for HIGH vs CTRL
  5. minimum control sample size needed for a clean comparison at the
     observed rates, and how many additional controls are needed

Output: results/m8_cleanliness_v1.json + prints the table.
"""
from __future__ import annotations

import json
import math
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def wilson(k, n, z=1.959964):
    if n == 0:
        return (None, None)
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def fisher_p(a, b, c, d):
    """Two-sided Fisher exact p for table [[a, b], [c, d]] = [[ctrl_leak, ctrl_ok], [att_leak, att_ok]]."""
    # simplified: use hypergeometric; for small counts we can compute directly
    # a=ctrl_leak, b=ctrl_ok, c=att_leak, d=att_ok
    n = a + b + c + d
    if n == 0:
        return 1.0
    # compute via scipy-style hypergeometric PMF
    from math import lgamma
    def log_comb(nn, kk):
        if kk < 0 or kk > nn:
            return float("-inf")
        return lgamma(nn + 1) - lgamma(kk + 1) - lgamma(nn - kk + 1)

    # row sums: ctrl_total = a+b, att_total = c+d
    # col sums: leak_total = a+c, ok_total = b+d
    ctrl_total = a + b
    att_total = c + d
    leak_total = a + c
    ok_total = b + d

    # probability of the observed table
    p_obs = math.exp(log_comb(ctrl_total, a) + log_comb(att_total, c) -
                     log_comb(n, leak_total))
    p_obs = max(p_obs, 1e-300)

    # enumerate all tables with same marginals
    p_val = 0.0
    # a can range from max(0, leak_total - att_total) to min(ctrl_total, leak_total)
    a_min = max(0, leak_total - att_total)
    a_max = min(ctrl_total, leak_total)
    for a2 in range(a_min, a_max + 1):
        b2 = ctrl_total - a2
        c2 = leak_total - a2
        d2 = att_total - c2
        if b2 < 0 or c2 < 0 or d2 < 0:
            continue
        p2 = math.exp(log_comb(ctrl_total, a2) + log_comb(att_total, c2) -
                      log_comb(n, leak_total))
        if p2 <= p_obs + 1e-12:
            p_val += p2
    return min(1.0, p_val)


def main():
    with open(os.path.join(RES, "e1d_third_gateway_v1.json"), encoding="utf-8") as f:
        d = json.load(f)

    pm = d["per_model"]
    rows = []
    for code, v in pm.items():
        ctrl = v.get("controls", {})
        high = v.get("high_tier", {})
        c_leak = ctrl.get("cot_leak_count", 0)
        c_total = ctrl.get("n_sent", 0)
        h_leak = high.get("cot_leak_count", 0)
        h_total = high.get("n_sent", 0)

        c_rate = c_leak / c_total if c_total else None
        h_rate = h_leak / h_total if h_total else None
        c_ci = wilson(c_leak, c_total)
        h_ci = wilson(h_leak, h_total)

        # robust separation: control upper bound < attack lower bound
        if c_ci[0] is not None and h_ci[0] is not None:
            robust_sep = c_ci[1] < h_ci[0]
            # inverted: even the conservative (lower-bound) control estimate
            # exceeds the attack point estimate — a model-level property, not noise
            inverted = (c_ci[0] is not None and h_rate is not None
                        and c_ci[0] > h_rate)
        else:
            robust_sep = False
            inverted = False

        # Fisher p
        if c_total and h_total:
            fp = fisher_p(c_leak, c_total - c_leak, h_leak, h_total - h_leak)
        else:
            fp = None

        # "cleanliness" score: 1 if robust separation, 0 if inverted, 0.5 if ambiguous
        if robust_sep:
            cleanliness = "clean"
        elif inverted:
            cleanliness = "inverted"
        else:
            cleanliness = "ambiguous"

        rows.append({
            "model_code": code,
            "model_name": v.get("model"),
            "vendor": v.get("vendor"),
            "ctrl_leak": c_leak,
            "ctrl_total": c_total,
            "ctrl_rate": round(c_rate, 4) if c_rate is not None else None,
            "ctrl_ci": [round(c_ci[0], 4), round(c_ci[1], 4)] if c_ci[0] is not None else None,
            "high_leak": h_leak,
            "high_total": h_total,
            "high_rate": round(h_rate, 4) if h_rate is not None else None,
            "high_ci": [round(h_ci[0], 4), round(h_ci[1], 4)] if h_ci[0] is not None else None,
            "robust_separation": robust_sep,
            "inverted_baseline": inverted,
            "fisher_p": round(fp, 6) if fp is not None else None,
            "cleanliness": cleanliness,
        })

    # Summary
    n_clean = sum(1 for r in rows if r["cleanliness"] == "clean")
    n_amb = sum(1 for r in rows if r["cleanliness"] == "ambiguous")
    n_inv = sum(1 for r in rows if r["cleanliness"] == "inverted")
    n_valid = sum(1 for r in rows if r["ctrl_total"] > 0 and r["high_total"] > 0)

    # Minimum controls needed: for a model with observed rates, how many
    # controls would be needed for the CI upper bound to fall below the
    # attack lower bound?  (approximate via Wilson inversion)
    min_controls = []
    for r in rows:
        if r["ctrl_rate"] is None or r["high_rate"] is None or r["high_ci"] is None:
            min_controls.append(None)
            continue
        if r["ctrl_rate"] >= r["high_rate"]:
            # can never be clean: control rate >= attack rate
            min_controls.append({"status": "impossible",
                                 "reason": "control rate >= attack rate"})
            continue
        # solve for n such that wilson_upper(k/n, n) < high_ci_lower
        target = r["high_ci"][0]
        found = None
        for n in range(8, 200):
            k = round(r["ctrl_rate"] * n)
            ci = wilson(k, n)
            if ci[0] is not None and ci[1] < target:
                found = n
                break
        if found:
            min_controls.append({"n_needed": found, "n_current": r["ctrl_total"],
                                 "additional_needed": found - r["ctrl_total"]})
        else:
            min_controls.append({"status": "not_found_up_to_200"})

    for r, mc in zip(rows, min_controls):
        r["min_controls_for_clean_comparison"] = mc

    out = {
        "experiment": "m8_cleanliness_quantification",
        "version": 1,
        "description": (
            "Quantifies 'clean probe-attributed comparison' per model on the "
            "third gateway (Intern-AI discovery-api), to close the M8 gap."
        ),
        "source": "e1d_third_gateway_v1.json",
        "n_models_assessed": n_valid,
        "rows": rows,
        "summary": {
            "clean": n_clean,
            "ambiguous": n_amb,
            "inverted": n_inv,
            "models_with_valid_data": n_valid,
        },
        "interpretation": (
            "On the third gateway, only " + str(n_clean) + " of " + str(n_valid) +
            " backends with valid data show a clean probe-attributed comparison "
            "(control CI upper bound below attack CI lower bound). " + str(n_inv) +
            " model(s) have an inverted baseline (control leaks more than attacks — "
            "a model-level property, not noise, since even the control CI lower bound "
            "exceeds the attack rate). The remaining " + str(n_amb) +
            " are ambiguous: the CIs overlap, so the difference cannot be resolved "
            "at the current control sample size (n=8)."
        ),
        "gates": {
            "n_clean_models_reported": n_clean >= 1,
            "inverted_models_identified": n_inv >= 1,
            "all_models_classified": n_clean + n_amb + n_inv == n_valid,
        },
    }

    outpath = os.path.join(RES, "m8_cleanliness_v1.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    # print
    print("=" * 100)
    print("M8  clean probe-attributed comparison on third gateway (Intern-AI)")
    print("=" * 100)
    print(f"{'model':<22} {'ctrl_rate':>10} {'ctrl_CI':>22} {'high_rate':>10} {'high_CI':>22} {'fisher':>9} {'clean?':>10}")
    print("-" * 100)
    for r in rows:
        c_ci = f"[{r['ctrl_ci'][0]:.3f},{r['ctrl_ci'][1]:.3f}]" if r["ctrl_ci"] else "N/A"
        h_ci = f"[{r['high_ci'][0]:.3f},{r['high_ci'][1]:.3f}]" if r["high_ci"] else "N/A"
        cr = f"{r['ctrl_rate']:.3f}" if r["ctrl_rate"] is not None else "N/A"
        hr = f"{r['high_rate']:.3f}" if r["high_rate"] is not None else "N/A"
        fp = f"{r['fisher_p']:.4f}" if r["fisher_p"] is not None else "N/A"
        print(f"{r['model_code']:<22} {cr:>10} {c_ci:>22} {hr:>10} {h_ci:>22} {fp:>9} {r['cleanliness']:>10}")
    print()
    print(f"clean={n_clean}  ambiguous={n_amb}  inverted={n_inv}  (of {n_valid} with valid data)")
    print()
    print("Minimum controls needed for clean separation:")
    for r, mc in zip(rows, min_controls):
        if isinstance(mc, dict) and "n_needed" in mc:
            print(f"  {r['model_code']}: need {mc['n_needed']} controls "
                  f"(+{mc['additional_needed']} more, from {mc['n_current']})")
        elif isinstance(mc, dict):
            print(f"  {r['model_code']}: {mc['status']} — {mc.get('reason','')}")
        else:
            print(f"  {r['model_code']}: N/A")
    print()
    print("Gates:")
    for k, v in out["gates"].items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    print(f"\nWrote {outpath} ({os.path.getsize(outpath)} bytes)")
    return 0 if all(out["gates"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())