#!/usr/bin/env python3
"""Extract per-c* FPR/TPR from E8 conditions, and per-mode joint rates from P52."""
import json, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


e8 = load("e8_real_defense_validation_v1.json")
conds = e8["conditions"]

print("=== E8 conditions (per-c* D23') ===")
for k in sorted(conds.keys()):
    v = conds[k]
    if isinstance(v, dict):
        keys = list(v.keys())
        print(f"  {k}: keys={keys[:12]}")
        # print key metrics
        for metric in ["fpr", "fpr_rate", "benign_blocked", "benign_total",
                       "attack_leak", "attack_total", "tpr", "tpr_rate",
                       "residual_leak", "residual", "leak_count", "total",
                       "blocked", "blocked_count", "pass_rate", "leak_rate"]:
            if metric in v:
                print(f"      {metric} = {v[metric]}")
    else:
        print(f"  {k}: {repr(v)[:120]}")

# Also look at records for per-trace detail
print()
recs = e8.get("records", [])
print(f"E8 records: {len(recs)}")
if recs:
    print("  sample record keys:", list(recs[0].keys()))
    print("  sample:", json.dumps(recs[0], ensure_ascii=False)[:400])
    # count benign vs attack
    benign = [r for r in recs if r.get("kind") == "control" or r.get("type") == "benign"]
    attack = [r for r in recs if r.get("kind") == "attack" or r.get("type") == "attack"]
    print(f"  benign records: {len(benign)}, attack records: {len(attack)}")
    if benign:
        print("  benign sample:", json.dumps(benign[0], ensure_ascii=False)[:300])
    if attack:
        print("  attack sample:", json.dumps(attack[0], ensure_ascii=False)[:300])