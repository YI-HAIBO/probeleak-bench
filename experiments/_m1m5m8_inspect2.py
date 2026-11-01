#!/usr/bin/env python3
"""Dig into c_sweep / correlation / per_record structures for M1/M5 analysis."""
import json, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


# ---- M5: c_sweep in E8 ----
e8 = load("e8_real_defense_validation_v1.json")
print("=" * 70)
print("E8 c_sweep:")
cs = e8.get("c_sweep")
print(json.dumps(cs, ensure_ascii=False, indent=1)[:3000])
print()
print("E8 c_star:", e8.get("c_star"), "| c_star_unconstrained:", e8.get("c_star_unconstrained"))
print("E8 fpr_budget:", e8.get("fpr_budget"))
print("E8 conditions keys:", list(e8.get("conditions", {}).keys())[:15])

# ---- M1: E7 correlation detail ----
e7 = load("e7_defense_correlation_v1.json")
print()
print("=" * 70)
print("E7 correlation:")
print(json.dumps(e7.get("correlation"), ensure_ascii=False, indent=1)[:2000])
print()
print("E7 per_probe keys:", list(e7.get("per_probe", {}).keys())[:10] if isinstance(e7.get("per_probe"), dict) else "list")
pp = e7.get("per_probe")
if isinstance(pp, dict):
    for k, v in list(pp.items())[:3]:
        print("  ", k, "->", json.dumps(v, ensure_ascii=False)[:300])
print()
print("E7 per_record sample:")
pr = e7.get("per_record")
if isinstance(pr, list):
    for r in pr[:3]:
        print("  ", json.dumps(r, ensure_ascii=False)[:300])
elif isinstance(pr, dict):
    for k, v in list(pr.items())[:3]:
        print("  ", k, "->", json.dumps(v, ensure_ascii=False)[:300])

# ---- phase52 rho calibration ----
p52 = load("phase52_d23prime_d30_two_layer_stack_v1.json")
print()
print("=" * 70)
print("P52 rho_calibration:")
print(json.dumps(p52["results"].get("rho_calibration"), ensure_ascii=False, indent=1)[:2000])
print()
print("P52 deployed_summary:")
print(json.dumps(p52["results"].get("deployed_summary"), ensure_ascii=False, indent=1)[:1500])
print()
print("P52 per_attack_mode_heterogeneity:")
print(json.dumps(p52["results"].get("per_attack_mode_heterogeneity"), ensure_ascii=False, indent=1)[:2000])