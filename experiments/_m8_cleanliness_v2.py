#!/usr/bin/env python3
r"""M8 v2: cleanliness with expanded controls.

Combines the original E1D controls (8 per model) with the M8 control
expansion (32 per model for N_A, N_B, N_C) and re-runs the cleanliness
classification.  N_D/N_E/N_F/N_G are unchanged (no expansion was run).

Output: results/m8_cleanliness_v2.json + prints the table.
"""
from __future__ import annotations

import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

ROOT = os.path.dirname(HERE)
RES = os.path.join(ROOT, "results")


def wilson(k, n, z=1.959964):
    if n == 0:
        return (None, None)
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def fisher_p(a, b, c, d):
    from math import lgamma
    def log_comb(nn, kk):
        if kk < 0 or kk > nn:
            return float("-inf")
        return lgamma(nn + 1) - lgamma(kk + 1) - lgamma(nn - kk + 1)

    n = a + b + c + d
    if n == 0:
        return 1.0
    ctrl_total = a + b
    att_total = c + d
    leak_total = a + c
    p_obs = math.exp(log_comb(ctrl_total, a) + log_comb(att_total, c) -
                     log_comb(n, leak_total))
    p_obs = max(p_obs, 1e-300)
    p_val = 0.0
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
    # Load original E1D data
    with open(os.path.join(RES, "e1d_third_gateway_v1.json"), encoding="utf-8") as f:
        e1d = json.load(f)

    # Load expansion data
    exp_path = os.path.join(RES, "m8_control_expansion_v1.json")
    with open(exp_path, encoding="utf-8") as f:
        exp = json.load(f)

    # Build expanded control counts
    exp_by_code = {}
    for r in exp.get("records", []):
        code = r.get("model_code")
        if code not in exp_by_code:
            exp_by_code[code] = {"leak": 0, "ok": 0, "total": 0}
        exp_by_code[code]["total"] += 1
        if r.get("api_ok"):
            exp_by_code[code]["ok"] += 1
            if r.get("cot_leak"):
                exp_by_code[code]["leak"] += 1

    pm = e1d["per_model"]
    rows = []
    for code, v in pm.items():
        ctrl = v.get("controls", {})
        high = v.get("high_tier", {})
        c_leak_orig = ctrl.get("cot_leak_count", 0)
        c_total_orig = ctrl.get("n_sent", 0)
        h_leak = high.get("cot_leak_count", 0)
        h_total = high.get("n_sent", 0)

        # Merge expansion controls
        ec = exp_by_code.get(code)
        c_leak = c_leak_orig
        c_total = c_total_orig
        if ec:
            c_leak += ec["leak"]
            c_total += ec["total"]

        c_rate = c_leak / c_total if c_total else None
        h_rate = h_leak / h_total if h_total else None
        c_ci = wilson(c_leak, c_total)
        h_ci = wilson(h_leak, h_total)

        if c_ci[0] is not None and h_ci[0] is not None:
            robust_sep = c_ci[1] < h_ci[0]
            inverted = (c_ci[0] is not None and h_rate is not None
                        and c_ci[0] > h_rate)
        else:
            robust_sep = False
            inverted = False

        if c_total and h_total:
            fp = fisher_p(c_leak, c_total - c_leak, h_leak, h_total - h_leak)
        else:
            fp = None

        if robust_sep:
            cleanliness = "clean"
        elif inverted:
            cleanliness = "inverted"
        else:
            cleanliness = "ambiguous"

        row = {
            "model_code": code,
            "model_name": v.get("model"),
            "ctrl_leak_orig": c_leak_orig,
            "ctrl_total_orig": c_total_orig,
            "ctrl_leak_expanded": c_leak - c_leak_orig if ec else 0,
            "ctrl_total_expanded": c_total - c_total_orig if ec else 0,
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
        }

        # Min controls needed (only for non-clean, non-inverted)
        if cleanliness == "ambiguous" and c_rate is not None and h_rate is not None and h_ci:
            if c_rate >= h_rate:
                row["min_controls_for_clean_comparison"] = {
                    "status": "impossible",
                    "reason": "control rate >= attack rate"}
            else:
                target = h_ci[0]
                found = None
                for n in range(c_total, 200):
                    k = round(c_rate * n)
                    ci = wilson(k, n)
                    if ci[0] is not None and ci[1] < target:
                        found = n
                        break
                if found:
                    row["min_controls_for_clean_comparison"] = {
                        "n_needed": found,
                        "n_current": c_total,
                        "additional_needed": max(0, found - c_total)}
                else:
                    row["min_controls_for_clean_comparison"] = {
                        "status": "not_found_up_to_200"}
        elif cleanliness == "clean":
            row["min_controls_for_clean_comparison"] = {
                "status": "already_clean",
                "n_current": c_total}
        elif cleanliness == "inverted":
            row["min_controls_for_clean_comparison"] = {
                "status": "impossible",
                "reason": "control rate >= attack rate"}

        rows.append(row)

    n_clean = sum(1 for r in rows if r["cleanliness"] == "clean")
    n_amb = sum(1 for r in rows if r["cleanliness"] == "ambiguous")
    n_inv = sum(1 for r in rows if r["cleanliness"] == "inverted")
    n_valid = sum(1 for r in rows if r["ctrl_total"] > 0 and r["high_total"] > 0)

    # Compare with v1
    v1_path = os.path.join(RES, "m8_cleanliness_v1.json")
    v1_summary = {}
    if os.path.exists(v1_path):
        with open(v1_path, encoding="utf-8") as f:
            v1 = json.load(f)
        for r in v1["rows"]:
            v1_summary[r["model_code"]] = r["cleanliness"]

    out = {
        "experiment": "m8_cleanliness_quantification_v2",
        "version": 2,
        "description": (
            "Cleanliness quantification with expanded controls: original E1D "
            "8 controls + 32 expansion controls for N_A/N_B/N_C."
        ),
        "sources": [
            "e1d_third_gateway_v1.json",
            "m8_control_expansion_v1.json",
        ],
        "n_models_assessed": n_valid,
        "rows": rows,
        "summary": {
            "clean": n_clean,
            "ambiguous": n_amb,
            "inverted": n_inv,
            "models_with_valid_data": n_valid,
        },
        "v1_comparison": {
            r["model_code"]: {
                "v1": v1_summary.get(r["model_code"], "?"),
                "v2": r["cleanliness"],
                "changed": v1_summary.get(r["model_code"]) != r["cleanliness"],
            } for r in rows
        },
        "interpretation": (
            "With expanded controls (40 per model for N_A/N_B/N_C), "
            + str(n_clean) + " of " + str(n_valid) + " backends show clean "
            "probe-attributed comparison (was 1 in v1). "
            + str(n_inv) + " remains inverted, " + str(n_amb) + " ambiguous."
        ),
        "gates": {
            "n_clean_models_increased": n_clean > 1,
            "all_models_classified": n_clean + n_amb + n_inv == n_valid,
        },
    }

    outpath = os.path.join(RES, "m8_cleanliness_v2.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    # Print
    print("=" * 110)
    print("M8 v2  clean probe-attributed comparison with expanded controls")
    print("=" * 110)
    print(f"{'model':<22} {'ctrl':>8} {'ctrl_rate':>10} {'ctrl_CI':>22} "
          f"{'high_rate':>10} {'high_CI':>22} {'fisher':>9} {'clean?':>10} {'v1->v2':>12}")
    print("-" * 110)
    for r in rows:
        c_ci = f"[{r['ctrl_ci'][0]:.3f},{r['ctrl_ci'][1]:.3f}]" if r["ctrl_ci"] else "N/A"
        h_ci = f"[{r['high_ci'][0]:.3f},{r['high_ci'][1]:.3f}]" if r["high_ci"] else "N/A"
        cr = f"{r['ctrl_rate']:.3f}" if r["ctrl_rate"] is not None else "N/A"
        hr = f"{r['high_rate']:.3f}" if r["high_rate"] is not None else "N/A"
        fp = f"{r['fisher_p']:.4f}" if r["fisher_p"] is not None else "N/A"
        v1c = v1_summary.get(r["model_code"], "?")
        changed = "CHANGED" if v1c != r["cleanliness"] else ""
        print(f"{r['model_code']:<22} {r['ctrl_leak']}/{r['ctrl_total']:>6} {cr:>10} {c_ci:>22} "
              f"{hr:>10} {h_ci:>22} {fp:>9} {r['cleanliness']:>10} {v1c}->{r['cleanliness']} {changed}")
    print()
    print(f"clean={n_clean}  ambiguous={n_amb}  inverted={n_inv}  (of {n_valid})")
    print()
    for r in rows:
        mc = r.get("min_controls_for_clean_comparison")
        if isinstance(mc, dict):
            if "n_needed" in mc:
                print(f"  {r['model_code']}: need {mc['n_needed']} (have {mc['n_current']}, "
                      f"+{mc['additional_needed']} more)")
            elif mc.get("status") == "already_clean":
                print(f"  {r['model_code']}: already clean at n={mc['n_current']}")
            else:
                print(f"  {r['model_code']}: {mc.get('status','')}")
    print()
    print("Gates:")
    for k, v in out["gates"].items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    print(f"\nWrote {outpath} ({os.path.getsize(outpath)} bytes)")
    return 0 if all(out["gates"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())