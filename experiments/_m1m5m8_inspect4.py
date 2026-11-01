#!/usr/bin/env python3
"""Extract full per-c* condition detail for M5 sensitivity analysis."""
import json, os, math

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


def wilson(k, n, z=1.959964):
    """Wilson score interval for k/n."""
    if n == 0:
        return (0.0, 0.0)
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


e8 = load("e8_real_defense_validation_v1.json")
conds = e8["conditions"]

print("=== D23' per-c* sweep (36 attacks, 8 benign controls) ===")
print(f"{'c*':>8} {'blocked':>8} {'bypass':>8} {'TPR':>7} {'ctrl_fpr':>9} {'fpr_Wilson':>16}")
for c in [0.0, 0.25, 0.5, 0.75, 1.0]:
    key = f"D23p_c{c:.2f}".replace("0.00", "0.00")
    # fix key naming
    if c == 0.0:
        key = "D23p_c0.00"
    elif c == 0.25:
        key = "D23p_c0.25"
    elif c == 0.5:
        key = "D23p_c0.50"
    elif c == 0.75:
        key = "D23p_c0.75"
    else:
        key = "D23p_c1.00"
    v = conds[key]
    n_att = v["n_attack"]
    blk = v["blocked"]
    bypass = n_att - blk
    tpr = blk / n_att if n_att else 0
    fpr = v.get("control_fpr", None)
    ci = wilson(int(fpr * 8), 8) if fpr is not None else (None, None)
    ci_str = f"[{ci[0]:.3f},{ci[1]:.3f}]" if fpr is not None else "N/A"
    print(f"{c:>8.2f} {blk:>8} {bypass:>8} {tpr:>7.3f} {str(fpr):>9} {ci_str:>16}")

# Also show D23 (exact) and D30 and stack for reference
print()
print("=== Reference conditions ===")
for k in ["none", "D23", "D30_s1.00", "stack"]:
    v = conds[k]
    print(f"  {k}: blocked={v['blocked']}/{v['n_attack']} bypass_rate={v.get('bypass_rate')} "
          f"control_fpr={v.get('control_fpr')} wilson95={v.get('wilson95')}")

# Now: what if we used a different FPR budget?
print()
print("=== c* selection under different FPR budgets ===")
# reconstruct FPR at each c* from conditions
fpr_by_c = {}
for c in [0.0, 0.25, 0.5, 0.75, 1.0]:
    key = {"D23p_c0.00": 0.0, "D23p_c0.25": 0.25, "D23p_c0.50": 0.5,
           "D23p_c0.75": 0.75, "D23p_c1.00": 1.0}[key] if False else None
    # just hardcode from the loop above
    pass

# Re-extract properly
fpr_map = {}
tpr_map = {}
for c in [0.0, 0.25, 0.5, 0.75, 1.0]:
    key = f"D23p_c{c:.2f}"
    v = conds[key]
    fpr_map[c] = v.get("control_fpr")
    tpr_map[c] = v["blocked"] / v["n_attack"]

for budget in [0.10, 0.125, 0.15, 0.20, 0.25]:
    eligible = [c for c in [0.0, 0.25, 0.5, 0.75, 1.0]
                if fpr_map.get(c) is not None and fpr_map[c] <= budget]
    chosen = max(eligible) if eligible else None
    tpr_chosen = tpr_map.get(chosen, None) if chosen is not None else None
    print(f"  FPR budget {budget:.2f}: eligible c*={eligible}, chosen={chosen}, "
          f"TPR at chosen={tpr_chosen:.3f}" if chosen is not None else f"  FPR budget {budget:.2f}: none eligible")