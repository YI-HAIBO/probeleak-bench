"""Pull remaining leaf values for the P3 paper."""
import json, os

R = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def load(fn):
    with open(os.path.join(R, fn), encoding="utf-8") as f:
        return json.load(f)


p52 = load("phase52_d23prime_d30_two_layer_stack_v1.json")
p53 = load("phase53_displacement_countermeasure_v1.json")
p54 = load("phase54_self_evolving_defense_v1.json")
p55 = load("phase55_real_calibrated_defense_v1.json")

print("== P52 cost_benefit.lambda_2 ==")
print(json.dumps(p52["results"]["cost_benefit"]["lambda_2"], ensure_ascii=False, indent=1))
print("== P52 rho_max_deployed.lambda_2 ==")
print(json.dumps(p52["results"]["rho_max_deployed"]["lambda_2"], ensure_ascii=False, indent=1))
print("== P52 self_checks.product_and_min_law ==")
print(json.dumps(p52["results"]["self_checks"]["product_and_min_law"], ensure_ascii=False, indent=1))
print("== P52 phase47_replay_all_rho ==")
print(json.dumps(p52["results"]["phase47_replay_all_rho"], ensure_ascii=False, indent=1))

print("== P53 grid[1.0] full ==")
print(json.dumps(p53["results"]["grid"]["1.0"], ensure_ascii=False, indent=1))
print("== P53 tau1_detail ==")
print(json.dumps(p53["results"]["self_checks"]["tau1_detail"], ensure_ascii=False, indent=1))
print("== P53 baseline_comparison ==")
print(json.dumps(p53["results"]["baseline_comparison"], ensure_ascii=False, indent=1))

print("== P54 drift_analysis (subset) ==")
da = p54["results"]["drift_analysis"]
for k in ["e0_util_pre_shift", "e0_util_at_shift", "e0_util_post_5", "e0_recover_gen",
          "e0_gap_vs_oracle_pre_median", "e0_gap_vs_oracle_at_shift", "e0_final_policy_match",
          "naive_bandit_util_at_shift", "naive_bandit_util_post_5"]:
    print(" ", k, "=", da.get(k))

print("== P55 drift arms (main vs drift) ==")
for arm in ["random", "static_best", "bandit_naive", "defense_agent_e0", "oracle"]:
    m = p55["results"]["main_arms"][arm]
    d = p55["results"]["drift_stress_arms"][arm]
    print(f"  {arm}: main util={m['utility_per_request']:.4f} leak={m['leak_rate']:.4f} | "
          f"drift util={d['utility_per_request']:.4f} leak={d['leak_rate']:.4f}")
print("== P55 arm2/arm1 mode detail for tl in arm2 ==")
print(json.dumps(p55["real_evidence"]["arm2_per_mode"]["thinking_leak"], ensure_ascii=False))
print(json.dumps(p55["real_evidence"]["arm2_per_mode"]["prefix_extraction"], ensure_ascii=False))
print("== P55 r0_sim_vs_real ==")
print(json.dumps(p55["results"]["r0_sim_vs_real"], ensure_ascii=False, indent=1))
print("== P55 snr real full ==")
print(json.dumps(p55["results"]["snr"]["real_calibrated"], ensure_ascii=False, indent=1))
print("== P55 oracle leak keys source (oracle leak 0.0068) ==")
o = p55["results"]["main_arms"]["oracle"]
for k in o:
    if "leak" in k or "policy" in k or "oracle" in k:
        print("  ", k, "=", o[k])
