#!/usr/bin/env python3
r"""M5 closure: c*=0.50 sensitivity scan across FPR budgets.

The EIC review's M5 concern: c*=0.50 was selected on 8 benign controls with a single
12.5% observed FPR, with no sensitivity scan.  This script sweeps the c* grid already
measured in E8 (c in {0, 0.25, 0.5, 0.75, 1.0}), computes the TPR–FPR tradeoff at each
point with Wilson CIs, and tests how robust the chosen c* is to the FPR budget.

Output: results/m5_cstar_sensitivity_v1.json + prints the table.
"""
from __future__ import annotations

import json
import math
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")
EXP = os.path.join(BASE, "experiments")

# ---------------------------------------------------------------- math

def wilson(k, n, z=1.959964):
    if n == 0:
        return (0.0, 0.0)
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def safe_div(a, b):
    return a / b if b else 0.0


# ---------------------------------------------------------------- main

def main():
    with open(os.path.join(RES, "e8_real_defense_validation_v1.json"), encoding="utf-8") as f:
        e8 = json.load(f)
    conds = e8["conditions"]

    n_attack = conds["none"]["n_attack"]          # 36
    n_ctrl = 8                                      # benign controls

    # collect per-c* metrics
    rows = []
    for c in [0.0, 0.25, 0.5, 0.75, 1.0]:
        key = f"D23p_c{c:.2f}"
        v = conds[key]
        blocked = v["blocked"]
        tpr = safe_div(blocked, n_attack)
        fpr_obs = v.get("control_fpr", 0.0)
        fpr_k = int(round(fpr_obs * n_ctrl))
        fpr_ci = wilson(fpr_k, n_ctrl)
        rows.append({
            "c": c,
            "blocked": blocked,
            "bypass": n_attack - blocked,
            "tpr": round(tpr, 4),
            "fpr_obs": fpr_obs,
            "fpr_k": fpr_k,
            "fpr_ci": [round(fpr_ci[0], 4), round(fpr_ci[1], 4)],
        })

    # robustness: which c* is chosen at each FPR budget
    budgets = [0.05, 0.08, 0.10, 0.12, 0.125, 0.15, 0.18, 0.20, 0.25, 0.30]
    robustness = []
    for b in budgets:
        elig = [r["c"] for r in rows if r["fpr_obs"] <= b]
        chosen = max(elig) if elig else None
        tpr_ch = next((r["tpr"] for r in rows if r["c"] == chosen), None) if chosen is not None else None
        robustness.append({
            "fpr_budget": b,
            "eligible_c": elig,
            "chosen_c": chosen,
            "tpr_at_chosen": tpr_ch,
        })

    # also: what if we used the *upper* Wilson bound instead of point estimate?
    robustness_upper = []
    for b in budgets:
        elig = [r["c"] for r in rows if r["fpr_ci"][1] <= b]
        chosen = max(elig) if elig else None
        tpr_ch = next((r["tpr"] for r in rows if r["c"] == chosen), None) if chosen is not None else None
        robustness_upper.append({
            "fpr_budget": b,
            "eligible_c": elig,
            "chosen_c": chosen,
            "tpr_at_chosen": tpr_ch,
        })

    out = {
        "experiment": "m5_cstar_sensitivity",
        "version": 1,
        "description": (
            "Sensitivity of the D23' c*=0.50 selection to the FPR budget, "
            "computed from the E8 measured c* grid (36 attacks, 8 benign controls)."
        ),
        "source": "e8_real_defense_validation_v1.json",
        "n_attack": n_attack,
        "n_ctrl": n_ctrl,
        "c_star_used": e8.get("c_star"),
        "fpr_budget_used": e8.get("fpr_budget"),
        "rows": rows,
        "robustness_by_budget": robustness,
        "robustness_by_budget_upper_wilson": robustness_upper,
        "gates": {
            "c_star_chosen_at_actual_budget_0.15": next(
                r["chosen_c"] for r in robustness if r["fpr_budget"] == 0.15
            ) == 0.5,
            "c_star_robust_pm0.025_around_actual": all(
                r["chosen_c"] == 0.5 for r in robustness
                if 0.125 <= r["fpr_budget"] <= 0.25
            ),
            "upper_wilson_no_cstar_eligible_at_budget_0.15_disclosure": next(
                r["chosen_c"] for r in robustness_upper if r["fpr_budget"] == 0.15
            ) is None,
        },
    }

    outpath = os.path.join(RES, "m5_cstar_sensitivity_v1.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    # print table
    print("=" * 72)
    print("M5  c* sensitivity sweep (36 attacks, 8 benign controls)")
    print("=" * 72)
    print(f"{'c*':>7} {'TPR':>7} {'FPR obs':>9} {'FPR Wilson 95%':>20} {'blocked':>8}")
    for r in rows:
        ci = f"[{r['fpr_ci'][0]:.3f}, {r['fpr_ci'][1]:.3f}]"
        print(f"{r['c']:>7.2f} {r['tpr']:>7.3f} {r['fpr_obs']:>9.3f} {ci:>20} {r['blocked']:>8}")
    print()
    print("Chosen c* by FPR budget (point-estimate FPR):")
    for r in robustness:
        marker = " <--" if r["chosen_c"] == 0.5 else ""
        print(f"  budget={r['fpr_budget']:.3f}  chosen c*={r['chosen_c']}  "
              f"TPR={r['tpr_at_chosen']}{marker}")
    print()
    print("Chosen c* by FPR budget (upper Wilson bound):")
    for r in robustness_upper:
        marker = " <--" if r["chosen_c"] == 0.5 else ""
        print(f"  budget={r['fpr_budget']:.3f}  chosen c*={r['chosen_c']}  "
              f"TPR={r['tpr_at_chosen']}{marker}")
    print()
    print("Gates:")
    for k, v in out["gates"].items():
        label = "PASS" if v else ("FAIL" if k.startswith("c_star_") else "DISCLOSURE")
        print(f"  {k}: {label}")
    print(f"\nWrote {outpath} ({os.path.getsize(outpath)} bytes)")
    # exit 0: the two substantive gates pass; the third is a disclosed limitation
    return 0 if out["gates"]["c_star_chosen_at_actual_budget_0.15"] and out["gates"]["c_star_robust_pm0.025_around_actual"] else 1


if __name__ == "__main__":
    sys.exit(main())