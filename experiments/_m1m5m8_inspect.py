#!/usr/bin/env python3
"""Inspect E8 / E7 / phase52 data structures for M1/M5/M8 gap-closing experiments."""
import json, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


for name in ["e8_real_defense_validation_v1.json", "e7_defense_correlation_v1.json",
             "phase52_d23prime_d30_two_layer_stack_v1.json",
             "e10_coevo_vs_adaptive_defense_v1.json"]:
    d = load(name)
    print("=" * 70)
    print(name, "| top-level keys:", list(d.keys())[:25])
    # dig one level for dict values
    for k, v in list(d.items())[:6]:
        if isinstance(v, dict):
            print("  ", k, "-> dict keys:", list(v.keys())[:12])
        elif isinstance(v, list):
            print("  ", k, "-> list len:", len(v),
                  "| sample:", json.dumps(v[0], ensure_ascii=False)[:200] if v else "empty")
        else:
            print("  ", k, "->", repr(v)[:120])
    print()