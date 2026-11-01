#!/usr/bin/env python3
"""Dig into E1D per_model control baselines and gates for M8."""
import json, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


d = load("e1d_third_gateway_v1.json")

print("=== per_model ===")
pm = d.get("per_model", {})
for model, v in pm.items():
    print(f"\n  {model}:")
    if isinstance(v, dict):
        for kk, vv in v.items():
            if isinstance(vv, (dict, list)):
                print(f"    {kk}: {type(vv).__name__} len={len(vv)}")
                print(f"      {json.dumps(vv, ensure_ascii=False)[:400]}")
            else:
                print(f"    {kk}: {repr(vv)[:200]}")

print("\n=== gates ===")
print(json.dumps(d.get("gates"), ensure_ascii=False, indent=1)[:2000])

print("\n=== records summary ===")
recs = d.get("records", [])
print(f"total records: {len(recs)}")
if recs:
    # count by model and kind
    from collections import Counter
    model_kinds = Counter((r.get("model"), r.get("kind")) for r in recs)
    for (m, k), c in sorted(model_kinds.items()):
        print(f"  {m} / {k}: {c}")
    # show a control record
    ctrl = [r for r in recs if r.get("kind") == "control"]
    if ctrl:
        print(f"\n  control sample: {json.dumps(ctrl[0], ensure_ascii=False)[:400]}")
    # show a high-leak record
    high = [r for r in recs if r.get("kind") == "high"]
    if high:
        print(f"\n  high sample: {json.dumps(high[0], ensure_ascii=False)[:400]}")