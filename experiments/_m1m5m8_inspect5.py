#!/usr/bin/env python3
"""Inspect P52 grid / per-record data for M1 stratification analysis."""
import json, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


p52 = load("phase52_d23prime_d30_two_layer_stack_v1.json")
r = p52["results"]

print("=== P52 grid ===")
grid = r.get("grid")
if isinstance(grid, dict):
    print("  keys:", list(grid.keys())[:20])
    for k, v in list(grid.items())[:3]:
        print(f"  {k}: {json.dumps(v, ensure_ascii=False)[:300]}")
elif isinstance(grid, list):
    print(f"  list len={len(grid)}")
    for g in grid[:3]:
        print(f"  {json.dumps(g, ensure_ascii=False)[:300]}")

print()
print("=== P52 intensity_sensitivity_deployed ===")
isd = r.get("intensity_sensitivity_deployed")
print(json.dumps(isd, ensure_ascii=False, indent=1)[:2000])

print()
print("=== P52 cost_benefit ===")
print(json.dumps(r.get("cost_benefit"), ensure_ascii=False, indent=1)[:1500])

print()
print("=== P52 per_attack_mode_heterogeneity (full) ===")
ph = r.get("per_attack_mode_heterogeneity")
for mode, v in ph.items():
    print(f"  {mode}:")
    for kk, vv in v.items():
        print(f"    {kk} = {vv}")