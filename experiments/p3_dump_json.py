"""Dump top-level structure of JSONs needed for the P3 paper."""
import json, os

R = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")

FILES = [
    "phase47_multi_defense_cascade_v1.json",
    "phase49_cot_exfiltration_v1.json",
    "phase50_defense_iteration_d23_prime_v1.json",
    "phase51_cot_firewall_ablation_v1.json",
    "phase52_d23prime_d30_two_layer_stack_v1.json",
    "phase53_displacement_countermeasure_v1.json",
    "phase54_self_evolving_defense_v1.json",
    "phase55_real_calibrated_defense_v1.json",
    "p1_real_cot_validation_v1.json",
    "p1_real_scale_validation_v1.json",
    "b2_cross_model_v1.json",
    "phase48_cross_vendor_transfer_v1.json",
]


def walk(o, prefix="", depth=0, out=None):
    if out is None:
        out = []
    if depth > 2:
        return out
    if isinstance(o, dict):
        for k, v in o.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                out.append(f"{p}  [{type(v).__name__} len={len(v)}]")
                walk(v, p, depth + 1, out)
            else:
                s = repr(v)
                if len(s) > 60:
                    s = s[:57] + "..."
                out.append(f"{p} = {s}")
    elif isinstance(o, list):
        out.append(f"{prefix}  [list len={len(o)}]")
        if o and isinstance(o[0], (dict, list)):
            walk(o[0], prefix + "[0]", depth + 1, out)
        elif o:
            s = repr(o[0])
            if len(s) > 60:
                s = s[:57] + "..."
            out.append(f"{prefix}[0] = {s}")
    return out


for fn in FILES:
    path = os.path.join(R, fn)
    if not os.path.exists(path):
        print(f"### {fn}: MISSING")
        continue
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    print("=" * 70)
    print("###", fn)
    for line in walk(data):
        print("  ", line)
