#!/usr/bin/env python3
"""Inspect E1D third-gateway data for M8 control-baseline analysis."""
import json, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


d = load("e1d_third_gateway_v1.json")
print("top keys:", list(d.keys())[:30])
print()

# Look for control / baseline data
for k in ["conditions", "per_backend", "results", "control_baseline",
          "probe_attributed", "gate_analysis", "by_backend", "backends"]:
    if k in d:
        v = d[k]
        if isinstance(v, dict):
            print(f"{k}: dict keys={list(v.keys())[:15]}")
        elif isinstance(v, list):
            print(f"{k}: list len={len(v)}")
            if v:
                print("  sample:", json.dumps(v[0], ensure_ascii=False)[:300])
        else:
            print(f"{k}: {repr(v)[:200]}")
        print()

# Look for any key containing 'control' or 'baseline'
for k in d:
    if 'control' in k.lower() or 'baseline' in k.lower() or 'fpr' in k.lower():
        v = d[k]
        if isinstance(v, (dict, list)):
            print(f"{k}: {type(v).__name__} len={len(v) if hasattr(v,'__len__') else '?'}")
            print("  ", json.dumps(v, ensure_ascii=False)[:500])
        else:
            print(f"{k}: {repr(v)[:200]}")
        print()