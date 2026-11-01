#!/usr/bin/env python3
"""Check third gateway quota status and model availability for M8 follow-up."""
import json, os, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


d = load("e1d_third_gateway_v1.json")
print("endpoint:", d.get("endpoint"))
print("seed:", d.get("seed"))
print("models:", d.get("models"))
print()

# Which models are usable (had any successful responses)?
print("=== Model status ===")
for code, v in d["per_model"].items():
    c = v.get("controls", {})
    h = v.get("high_tier", {})
    c_ok = c.get("n_ok", 0)
    h_ok = h.get("n_ok", 0)
    c_fail = c.get("n_api_failed", 0)
    h_fail = h.get("n_api_failed", 0)
    status = "BLOCKED" if (c_ok == 0 and h_ok == 0) else "usable"
    print(f"  {code} ({v.get('model')}): ctrl {c_ok}/{c.get('n_sent',8)} "
          f"(fail={c_fail}) | high {h_ok}/{h.get('n_sent',24)} (fail={h_fail}) "
          f"| vendor={v.get('vendor')} | {status}")

print()
print("=== Ambiguous models needing more controls ===")
# From M8 analysis: N_A needs +20, N_B needs +21, N_C needs +30
print("  N_A (Agents-A1): needs 28 controls total (+20 more)")
print("  N_B (Atria-Dawn): needs 29 controls total (+21 more)")
print("  N_C (Atria-Dawn-Preview): needs 38 controls total (+30 more)")
print("  N_F (intern-s2): already clean, 0 more needed")
print()
print("Total additional control probes needed: 71")
print("At ~2.5s per probe (observed latency median ~25-70s per request,")
print("but controls are simple prompts): estimated ~3-5 min wall time.")
print()
print("=== Quota risk ===")
print("  Original E1D used 224 requests. Quota locked at ~250 requests.")
print("  Adding 71 control probes = ~295 total, likely to hit quota lock.")
print("  Mitigation: split across two windows, or target only N_A/N_B/N_C")
print("  (the three ambiguous models with usable data).")