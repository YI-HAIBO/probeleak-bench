"""Extract exact metric values needed for the P3 paper into a provenance table."""
import json, os

R = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def load(fn):
    with open(os.path.join(R, fn), encoding="utf-8") as f:
        return json.load(f)


p47 = load("phase47_multi_defense_cascade_v1.json")
p48 = load("phase48_cross_vendor_transfer_v1.json")
p49 = load("phase49_cot_exfiltration_v1.json")
p50 = load("phase50_defense_iteration_d23_prime_v1.json")
p51 = load("phase51_cot_firewall_ablation_v1.json")
p52 = load("phase52_d23prime_d30_two_layer_stack_v1.json")
p53 = load("phase53_displacement_countermeasure_v1.json")
p54 = load("phase54_self_evolving_defense_v1.json")
p55 = load("phase55_real_calibrated_defense_v1.json")
p11 = load("p1_real_cot_validation_v1.json")
b1 = load("p1_real_scale_validation_v1.json")
b2 = load("b2_cross_model_v1.json")

out = []


def rec(section, key, value, path):
    out.append((section, key, value, path))


# ---- Phase 47 (errata subject) ----
r47 = p47["results"]
rec("P47", "independence_gap (errata subject)", r47["independence_gap"], "results.independence_gap")
rec("P47", "independent_rate_rho0", r47["independent_rate_rho0"], "results.independent_rate_rho0")
rec("P47", "correlated_rate_rho1", r47["correlated_rate_rho1"], "results.correlated_rate_rho1")
for rho in ["0.0", "0.6", "1.0"]:
    cell = r47["per_rho"][rho]
    keys = [k for k in cell if "rate" in k or "penetration" in k]
    for k in keys:
        rec("P47", f"per_rho[{rho}].{k}", cell[k], f"results.per_rho.{rho}.{k}")

# ---- Phase 48 ----
r48 = p48["results"]
for v, d in r48["per_target_vendor"].items():
    rec("P48", f"transfer {v}", d.get("success_rate") or d.get("target_success_rate"),
        f"results.per_target_vendor.{v}")
rec("P48", "best_strategy", r48["best_transfer_strategy"]["strategy"], "results.best_transfer_strategy")
rec("P48", "best_strategy_rate", r48["best_transfer_strategy"]["success_rate"], "results.best_transfer_strategy.success_rate")

# ---- Phase 49 ----
r49 = p49["results"]
for k in ["overall_cot_leak_rate", "overall_final_leak_rate", "cot_vs_final_ratio",
          "extended_vs_fast_multiplier", "avg_cot_steps"]:
    rec("P49", k, r49[k], f"results.{k}")
for m, d in r49["per_attack_mode"].items():
    rec("P49", f"per_attack_mode[{m}]", d, f"results.per_attack_mode.{m}")

# ---- Phase 50 ----
r50 = p50["results"]
rec("P50", "arm_a_bypass (D23 base)", r50["arm_a_baseline"]["bypass_rate"], "results.arm_a_baseline.bypass_rate")
rec("P50", "residual_bypass_at_c_star", r50["residual_bypass_at_c_star"], "results.residual_bypass_at_c_star")
rec("P50", "iteration_gain_pp", r50["iteration_gain_pp"], "results.iteration_gain_pp")
rec("P50", "arm_c_bypass (closed loop)", r50["closed_loop_bypass"], "results.closed_loop_bypass")
rec("P50", "arm_c_fp", r50["arm_c_closed_loop"]["false_positive_rate"], "results.arm_c_closed_loop.false_positive_rate")

# ---- Phase 51 ----
r51 = p51["results"]
for s in ["0.0", "1.0"]:
    cell = r51["arm_b_static_sweep"][s]
    for k in sorted(cell.keys()):
        if "rate" in k and k.endswith("rate"):
            rec("P51", f"static_sweep[{s}].{k}", cell[k], f"results.arm_b_static_sweep.{s}.{k}")
rec("P51", "sweep_baseline_cot", r51["sweep_baseline"]["cot_leak_rate"], "results.sweep_baseline.cot_leak_rate")
rec("P51", "sweep_baseline_final", r51["sweep_baseline"]["final_leak_rate"], "results.sweep_baseline.final_leak_rate")
rec("P51", "optimal_s_lambda2", r51["optimal_strictness_by_lambda"]["lambda_2"], "results.optimal_strictness_by_lambda.lambda_2")
rec("P51", "worst_combo_base", r51["worst_combo_ablation"]["baseline_cot_leak_rate"], "results.worst_combo_ablation.baseline_cot_leak_rate")
rec("P51", "worst_combo_s1", r51["worst_combo_ablation"]["cot_leak_rate_at_s_1.0"], "results.worst_combo_ablation.cot_leak_rate_at_s_1.0")
nbs = r51["net_benefit_sign_analysis"]
rec("P51", "net_positive_points", f"{nbs['positive_count']}/{nbs['grid_points']}", "results.net_benefit_sign_analysis")

# ---- Phase 52 ----
r52 = p52["results"]
rc = r52["rho_calibration"]
for k in ["clean_rate_at_rho0", "clean_rate_at_rho1", "clean_gap_at_rho1", "phase47_anchor_gap",
          "rate_overshoot_ratio", "gap_overshoot_ratio", "rho_saturated", "rho_hat_used_for_deployment"]:
    rec("P52", k, rc[k], f"results.rho_calibration.{k}")
ds = r52["deployed_summary"]
for k in ["q_a", "q_b", "joint_at_rho0", "product_pred", "joint_at_rho_eff", "min_pred", "discount_factor_at_rho_eff"]:
    rec("P52", f"deployed.{k}", ds[k], f"results.deployed_summary.{k}")
for lam in ["lambda_1", "lambda_2", "lambda_5"]:
    cell = r52["cost_benefit"][lam]
    rec("P52", f"cost_benefit.{lam}", cell, f"results.cost_benefit.{lam}")
    rm = r52["rho_max_deployed"][lam]
    rec("P52", f"rho_max.{lam}", rm.get("net_at_rho_max"), f"results.rho_max_deployed.{lam}.net_at_rho_max")
for chk, d in r52["self_checks"].items():
    if isinstance(d, dict) and "passed" in d:
        rec("P52", f"self_check.{chk}", d["passed"], f"results.self_checks.{chk}.passed")

# ---- Phase 53 ----
r53 = p53["results"]
rec("P53", "base_union_rate", r53["base_union_rate"], "results.base_union_rate")
for s in ["0.0", "1.0"]:
    cell = r53["grid"][s]
    rec("P53", f"grid[{s}]", cell, f"results.grid.{s}")
for s in ["0.0", "1.0"]:
    cell = r53["cot_metric_vs_union"][s]
    rec("P53", f"cot_vs_union[{s}]", cell, f"results.cot_metric_vs_union.{s}")
rec("P53", "self_checks.all_passed", r53["self_checks"]["all_three_passed"], "results.self_checks.all_three_passed")
cb53 = r53["cost_benefit"]
for s in ["0.0", "0.6", "1.0"]:
    rec("P53", f"cost_benefit[{s}]", cb53[s], f"results.cost_benefit.{s}")
rec("P53", "anchors", r53["anchors"], "results.anchors")

# ---- Phase 54 ----
r54 = p54["results"]
for arm, d in r54["arms"].items():
    rec("P54", f"arm.{arm}.util", d["utility_per_request"], f"results.arms.{arm}.utility_per_request")
    rec("P54", f"arm.{arm}.leak", d.get("leak_rate"), f"results.arms.{arm}.leak_rate")
    rec("P54", f"arm.{arm}.fp", d.get("fp_rate"), f"results.arms.{arm}.fp_rate")
rec("P54", "coevo.util", r54["coevo_arm"]["utility_per_request"], "results.coevo_arm.utility_per_request")
rec("P54", "coevo.leak", r54["coevo_arm"]["leak_rate"], "results.coevo_arm.leak_rate")
rec("P54", "model_fidelity_mae", r54["model_fidelity"]["mean_abs_error"], "results.model_fidelity.mean_abs_error")
for lam, d in r54["lambda_sweep"].items():
    rec("P54", f"lambda_sweep[{lam}]", d, f"results.lambda_sweep.{lam}")
for g, d in p54["gates"].items():
    rec("P54", f"gate.{g}.passed", d["passed"], f"gates.{g}.passed")

# ---- Phase 55 ----
r55 = p55["results"]
for arm, d in r55["main_arms"].items():
    rec("P55", f"main.{arm}.util", d["utility_per_request"], f"results.main_arms.{arm}.utility_per_request")
    rec("P55", f"main.{arm}.leak", d.get("leak_rate"), f"results.main_arms.{arm}.leak_rate")
rec("P55", "agent_gain_vs_static", r55["agent_gain_vs_static"], "results.agent_gain_vs_static")
rec("P55", "naive_gain_vs_static", r55["naive_gain_vs_static"], "results.naive_gain_vs_static")
for pc, d in r55["pcot_sweep"].items():
    rec("P55", f"pcot[{pc}]", d, f"results.pcot_sweep.{pc}")
for k, d in r55["tau_sweep"].items():
    rec("P55", f"tau[{k}]", d, f"results.tau_sweep.{k}")
for k, d in r55["pobs_sweep"].items():
    rec("P55", f"pobs[{k}]", d, f"results.pobs_sweep.{k}")
for k, d in r55["lambda_sweep"].items():
    rec("P55", f"lambda[{k}]", d, f"results.lambda_sweep.{k}")
rec("P55", "coevo.util", r55["coevo_arm"]["utility_per_request"], "results.coevo_arm.utility_per_request")
rec("P55", "coevo.leak", r55["coevo_arm"]["leak_rate"], "results.coevo_arm.leak_rate")
rec("P55", "snr.real", r55["snr"]["real_calibrated"], "results.snr.real_calibrated")
rec("P55", "snr.sim", r55["snr"]["sim_phase54"], "results.snr.sim_phase54")
for g, d in p55["gates"].items():
    rec("P55", f"gate.{g}.passed", d["passed"], f"gates.{g}.passed")

# ---- P1.1 ----
s11 = p11["summary"]
for k in ["n_attack_probes", "cot_leak_rate", "final_leak_rate", "union_leak_rate", "refusal_rate",
          "cot_vs_final_ratio", "n_gateway_blocked", "n_tpm_or_network_fail"]:
    rec("P1.1", k, s11[k], f"summary.{k}")
for g, d in p11["gates"].items():
    rec("P1.1", f"gate.{g}.pass", d["pass"], f"gates.{g}.pass")

# ---- B1+B3 ----
a1 = b1["summary_arm1"]
for k in ["n_attack_effective", "cot_leak_rate", "final_leak_rate", "union_leak_rate", "refusal_rate",
          "cot_leak_count", "final_leak_count", "all_leaks_cot_only", "n_gateway_blocked"]:
    rec("B1", k, a1[k], f"summary_arm1.{k}")
for m, d in a1["per_attack_mode"].items():
    rec("B1", f"per_mode[{m}]", d, f"summary_arm1.per_attack_mode.{m}")
a2 = b1["summary_arm2"]
for k in ["n_attack_effective", "cot_leak_rate", "final_leak_rate", "refusal_rate", "cot_leak_count"]:
    rec("B3", k, a2[k], f"summary_arm2.{k}")
for m, d in a2["per_attack_mode"].items():
    rec("B3", f"arm2_per_mode[{m}]", d, f"summary_arm2.per_attack_mode.{m}")
for k, d in b1["arm_b_posthoc"].items():
    if isinstance(d, dict):
        rec("B1", f"posthoc.{k}", d, f"arm_b_posthoc.{k}")
for g, d in b1["gates"].items():
    rec("B1", f"gate.{g}.pass", d["pass"], f"gates.{g}.pass")
rec("B1", "n_records", len(b1["records"]), "records (len)")

# ---- B2 ----
rec("B2", "verdict", b2["verdict"], "verdict")
rec("B2", "models_listing_status", b2["models_listing"]["status"], "models_listing.status")
rec("B2", "parsed_ids", b2["models_listing"]["parsed_ids"], "models_listing.parsed_ids")
rec("B2", "n_probe_results", len(b2["probe_results"]), "probe_results (len)")

# write
lines = ["# P3 Paper Metric Provenance Table", "",
         "| Source | Key | Value | JSON path |", "|---|---|---|---|"]
for s, k, v, p in out:
    sv = repr(v)
    if len(sv) > 180:
        sv = sv[:177] + "..."
    lines.append(f"| {s} | {k} | {sv} | {p} |")
dst = os.path.join(R, "p3_metrics_provenance.md")
with open(dst, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print(f"wrote {dst} with {len(out)} entries")
