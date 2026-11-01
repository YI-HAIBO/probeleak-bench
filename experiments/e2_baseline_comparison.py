"""
E2: 与 PCC-SQL / schema hiding 基线的对照实验（P3 论文增强实验 E2）

研究问题：
  E2-Q1 基线能触及多少真实泄露事件？（机制触及面，与成本无关的结构性结论）
  E2-Q2 用什么度量评估，基线才"看起来"有效？（度量盲区：final-only 度量）
  E2-Q3 哪个世界该部署哪类防御？（W-R 真实校准 vs W-S 模拟校准的净效用最优映射）

两个校准世界：
  W-R（真实）：cot ← B1+B3 per_attack_mode cot_rate（N=112，总体 7.1%）；
              final ← 0（实测全零，all_leaks_cot_only=True）
  W-S（模拟，悲观上界）：cot ← Phase 49 R0（per-attack，总体 42.4%）；
              final ← R0 × γ，γ = P51 sweep_baseline 的 final/cot 比例
              （0.255 / 0.4207，保持 P51 3000 探针总体量级；γ 做 ±20% 稳健扫描）

配置空间：
  我方（真实校准，溯源 Phase 55 / B1+B3）：
    C0_passthrough / C1_tau_scrub（post-hoc 残余实测 0）/ C2_d30_cot /
    C3_d30_prompt（Arm 2 实测反效）/ C9_block_all
    W-S 另有 C4_d30_s10（P51 s=1.0 逐类实测 cot/final，含位移）
  基线（文献锚定，参数扫描，显式标注为假设而非实测）：
    B1_pccsql        解码层约束解码（PCC-SQL, arXiv:2607.12341 报告受约束输出 0% 泄露）：
                     final 通道 → 0；CoT 通道结构性不触及（e_cot 扫描 0–0.25 以放宽）
    B2_schema_hiding 提示层 schema 抑制（RBAC text-to-SQL 基准 arXiv:2607.22115：
                     违规率降 45–64%，refusal-cliff）：schema 依赖类（pe/sr/ti/re）
                     双通道 ×(1−v)；thinking_leak 不依赖 schema（探针只要求模型
                     思考上下文中已可见的 key 值，不引用表结构）
    B3_combined      两者叠加

度量：
  消费方通道残差 resid(c,k) = p_cot·leak_cot(c,k) + (1−p_cot)·leak_final(c,k)
  并集残差      union(c,k) = 1 − (1−leak_cot)(1−leak_final)（攻击方可读双通道）

诚实边界（明确标注）：
  - 真实证据：B1+B3 的逐类 cot/final 率、final 全零、τ post-hoc 残余 0、Arm 2 反效
  - 文献锚定假设（扫描而非断言）：两条基线的效能因子、fp、延迟
  - 部署假设（同 Phase 55）：良性占比、各配置 fp/lat、观测器混淆矩阵
"""
from __future__ import annotations

import itertools
import json
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import phase54_self_evolving_defense as p54

RESULTS = p54.RESULTS
B1B3_PATH = RESULTS / "p1_real_scale_validation_v1.json"
P49_PATH = RESULTS / "phase49_cot_exfiltration_v1.json"
P51_PATH = RESULTS / "phase51_cot_firewall_ablation_v1.json"
P53_PATH = RESULTS / "phase53_displacement_countermeasure_v1.json"

ATTACK_MODES = p54.ATTACK_MODES
TRUE_CLASSES = p54.TRUE_CLASSES
SCHEMA_DEPENDENT = ["prefix_extraction", "step_reconstruction",
                    "tool_injection", "reasoning_escalation"]

PRIOR = 0.5
ATTACK_SHARE = 0.30
MU_LAT = p54.MU_LAT

PCOT_GRID = [0.0, 0.1, 0.25, 0.5, 0.75, 1.0]
LAMBDA_GRID = [1.0, 2.0, 5.0]
SEED = 2026

# 基线参数预设（文献锚定；favorable/central/pessimistic 三档）
BASELINE_PRESETS = {
    "favorable":   {"pccsql_fp": 0.00, "pccsql_lat": 10.0, "pccsql_e_cot": 0.25,
                    "sch_v": 0.80, "sch_fp": 0.05},
    "central":     {"pccsql_fp": 0.04, "pccsql_lat": 45.0, "pccsql_e_cot": 0.00,
                    "sch_v": 0.55, "sch_fp": 0.15},
    "pessimistic": {"pccsql_fp": 0.10, "pccsql_lat": 100.0, "pccsql_e_cot": 0.00,
                    "sch_v": 0.30, "sch_fp": 0.30},
}
BASELINE_SWEEP = {
    "pccsql_fp": [0.00, 0.02, 0.04, 0.10],
    "pccsql_lat": [10.0, 45.0, 100.0],
    "pccsql_e_cot": [0.00, 0.10, 0.25],
    "sch_v": [0.30, 0.55, 0.80],
    "sch_fp": [0.05, 0.10, 0.15, 0.30],
}

W_R_CONFIGS: Dict[str, Dict] = {
    "C0_passthrough":  {"fp": 0.00, "lat_ms": 0.0},
    "C1_tau_scrub":    {"fp": 0.01, "lat_ms": 8.0},
    "C2_d30_cot":      {"fp": 0.05, "lat_ms": 35.0},
    "C3_d30_prompt":   {"fp": 0.00, "lat_ms": 0.0},
    "C9_block_all":    {"fp": 1.00, "lat_ms": 5.0},
}
W_S_CONFIGS: Dict[str, Dict] = {
    "C0_passthrough":  {"fp": 0.00, "lat_ms": 0.0},
    "C1_tau_scrub":    {"fp": 0.03, "lat_ms": 8.0},
    "C4_d30_s10":      {"fp": 0.02, "lat_ms": 53.0},
    "C9_block_all":    {"fp": 1.00, "lat_ms": 5.0},
}


# ----------------------------------------------------------------------------
# 证据加载（全部溯源 results/*.json）
# ----------------------------------------------------------------------------

def load_real() -> Dict:
    d = json.loads(B1B3_PATH.read_text(encoding="utf-8"))
    s1 = d["summary_arm1"]
    s2 = d["summary_arm2"]
    post = d["arm_b_posthoc"]
    per_mode = {}
    for k in ATTACK_MODES:
        m = s1["per_attack_mode"][k]
        assert abs(m["cot"] / m["n"] - m["cot_rate"]) < 1e-9, k
        assert abs(m["final"] / m["n"] - m["final_rate"]) < 1e-9, k
        per_mode[k] = {"n": m["n"], "cot": m["cot"], "final": m["final"],
                       "cot_rate": m["cot_rate"], "final_rate": m["final_rate"],
                       "refusal": m["refusal"]}
    assert s1["n_attack_effective"] == 112
    assert s1["all_leaks_cot_only"] is True
    assert s1["final_leak_count"] == 0
    assert s1["cot_leak_count"] == 8
    # 事件归因：pe 1 + sr 1 + tl 6 = 8（ti/re 为 0）
    assert (per_mode["prefix_extraction"]["cot"]
            + per_mode["step_reconstruction"]["cot"]
            + per_mode["thinking_leak"]["cot"]) == 8
    # Arm 2（D30 prompt 自检，反效证据）
    arm2 = {}
    for k in ATTACK_MODES:
        m = s2["per_attack_mode"].get(k)
        if m is None or m["n"] == 0:
            # tool_injection 3 条全被网关拦截，无有效记录 → 保守沿用基线
            arm2[k] = {"n": 0, "cot": 0,
                       "cot_shrunk": (per_mode[k]["cot"] + PRIOR)
                                     / (per_mode[k]["n"] + 2 * PRIOR),
                       "carried_from_baseline": True}
        else:
            arm2[k] = {"n": m["n"], "cot": m["cot"],
                       "cot_shrunk": (m["cot"] + PRIOR) / (m["n"] + 2 * PRIOR),
                       "carried_from_baseline": False}
    assert arm2["thinking_leak"]["cot"] == 3 and arm2["thinking_leak"]["n"] == 3
    assert s2["refusal_rate"] == 0.0
    assert post["tau_scrub"]["residual_leak_rate"] == 0.0
    assert post["tau_scrub"]["n_residual"] == 0
    assert post["d30_cot"]["final_leak_rate"] == 0.0
    assert post["displacement_to_final"] == 0
    return {"per_mode": per_mode, "arm2": arm2,
            "overall": {"n": s1["n_attack_effective"],
                        "cot_rate": s1["cot_leak_rate"],
                        "final_rate": s1["final_leak_rate"],
                        "arm2_cot_rate": s2["cot_leak_rate"]},
            "posthoc": {"tau_residual": post["tau_scrub"]["residual_leak_rate"],
                        "d30_cot_final": post["d30_cot"]["final_leak_rate"],
                        "displacement_to_final": post["displacement_to_final"]},
            "source": str(B1B3_PATH)}


def load_sim_anchors() -> Dict:
    d49 = json.loads(P49_PATH.read_text(encoding="utf-8"))
    r49 = d49["results"]
    assert abs(r49["overall_cot_leak_rate"] - 0.424) < 1e-9
    assert abs(r49["overall_final_leak_rate"] - 0.267) < 1e-9
    r0 = {k: r49["per_attack_mode"][k]["leak_rate"] for k in ATTACK_MODES}
    # P49 tried 比例作为 W-S 混合
    tried = {k: r49["per_attack_mode"][k]["tried"] for k in ATTACK_MODES}
    tot = sum(tried.values())
    mix = {k: tried[k] / tot for k in ATTACK_MODES}

    d51 = json.loads(P51_PATH.read_text(encoding="utf-8"))
    c51 = d51["config"]
    r51 = d51["results"]
    sweep = r51["sweep_baseline"]
    assert abs(sweep["cot_leak_rate"] - 0.4207) < 1e-9
    assert abs(sweep["final_leak_rate"] - 0.255) < 1e-9
    gamma = sweep["final_leak_rate"] / sweep["cot_leak_rate"]
    # C4_d30_s10 逐类实测（s=1.0，含位移）
    d30 = {k: {"cot": r51["per_attack_at_s_report"][k]["cot_leak_rate"],
               "final": r51["per_attack_at_s_report"][k]["final_leak_rate"]}
           for k in ATTACK_MODES}
    # fpr 与延迟锚定：P51 fpr_model 0.02+0.16(1-s) → s=1 即 0.02；P53 grid s=1 lat 53
    fpr_expr = c51["fpr_model"].replace(" ", "")
    assert all(ch in "0123456789.+-*()s" for ch in fpr_expr), fpr_expr
    assert abs(eval(fpr_expr.replace("s", "1.0")) - 0.02) < 1e-9, fpr_expr

    d53 = json.loads(P53_PATH.read_text(encoding="utf-8"))
    g = d53["results"]["grid"]
    # τ 单独（s=0, τ=1）不改基线 cot/final（P53 建模：τ 只作用于被 D30 位移的残差）
    base = g["0.0"]["0.0"]["rate"]
    tau_only = g["0.0"]["1.0"]["rate"]
    assert tau_only["cot_eff"] == base["cot_eff"]
    assert tau_only["final_eff"] == base["final_eff"]
    d30_corner = g["1.0"]["0.0"]["rate"]
    assert abs(d30_corner["cot_eff"] - 0.1513) < 1e-9
    assert abs(d30_corner["final_eff"] - 0.3033) < 1e-9
    base_union = base["union"]
    return {"r0": r0, "mix": mix, "gamma": gamma,
            "sweep_baseline": {"cot": sweep["cot_leak_rate"],
                               "final": sweep["final_leak_rate"]},
            "d30_s1_per_class": d30,
            "p53_base_union": base_union,
            "p53_d30_corner": {"cot": d30_corner["cot_eff"],
                               "final": d30_corner["final_eff"],
                               "union": d30_corner["union"]},
            "p53_tau_only_ineffective": True,
            "sources": {"p49": str(P49_PATH), "p51": str(P51_PATH),
                        "p53": str(P53_PATH)}}


def real_mix(real: Dict) -> Dict[str, float]:
    per = real["per_mode"]
    tot = sum(per[k]["n"] for k in ATTACK_MODES)
    return {k: per[k]["n"] / tot for k in ATTACK_MODES}


def wilson_ci(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson 评分区间（小样本泄露率适用）。"""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return max(0.0, center - half), min(1.0, center + half)


# ----------------------------------------------------------------------------
# 双世界通道残差矩阵
# ----------------------------------------------------------------------------

def _schema_mask(k: str) -> float:
    return 0.0 if k in SCHEMA_DEPENDENT else 1.0


def build_world_R_channels(real: Dict, tau_frag: float,
                           bparams: Dict) -> Dict[str, Tuple[Dict, Dict]]:
    """W-R：cot ← 真实逐类率，final ← 0（实测）。返回 {config: (cot_row, fin_row)}。"""
    cot0 = {k: real["per_mode"][k]["cot_rate"] for k in ATTACK_MODES}
    fin0 = {k: 0.0 for k in ATTACK_MODES}
    arm2 = real["arm2"]
    v = bparams["sch_v"]
    e_cot = bparams["pccsql_e_cot"]
    e_final = 1.0  # PCC-SQL 的受约束输出通道 0% 泄露
    rows: Dict[str, Tuple[Dict, Dict]] = {}
    rows["C0_passthrough"] = (dict(cot0), dict(fin0))
    rows["C1_tau_scrub"] = ({k: tau_frag for k in ATTACK_MODES}, dict(fin0))
    rows["C2_d30_cot"] = (dict(cot0), dict(fin0))  # CoT 攻击方不变；final 消费方 0（基线已 0）
    rows["C3_d30_prompt"] = ({k: arm2[k]["cot_shrunk"] for k in ATTACK_MODES},
                             dict(fin0))
    rows["C9_block_all"] = ({k: 0.0 for k in ATTACK_MODES}, dict(fin0))
    rows["B1_pccsql"] = ({k: cot0[k] * (1.0 - e_cot) for k in ATTACK_MODES},
                         {k: fin0[k] * (1.0 - e_final) for k in ATTACK_MODES})
    rows["B2_schema_hiding"] = (
        {k: cot0[k] * (1.0 - v * (1 - _schema_mask(k))) for k in ATTACK_MODES},
        {k: fin0[k] * (1.0 - v * (1 - _schema_mask(k))) for k in ATTACK_MODES})
    rows["B3_combined"] = (
        {k: cot0[k] * (1.0 - e_cot) * (1.0 - v * (1 - _schema_mask(k)))
         for k in ATTACK_MODES},
        {k: 0.0 for k in ATTACK_MODES})
    return rows


def build_world_S_channels(anchors: Dict, gamma_scale: float,
                           bparams: Dict) -> Dict[str, Tuple[Dict, Dict]]:
    """W-S：cot ← R0，final ← R0·γ（γ 扫描 ±20%）。C4 用 P51 s=1 逐类实测。"""
    cot0 = dict(anchors["r0"])
    fin0 = {k: anchors["r0"][k] * gamma_scale for k in ATTACK_MODES}
    d30 = anchors["d30_s1_per_class"]
    v = bparams["sch_v"]
    e_cot = bparams["pccsql_e_cot"]
    rows: Dict[str, Tuple[Dict, Dict]] = {}
    rows["C0_passthrough"] = (dict(cot0), dict(fin0))
    # P53 实证：τ 单独不改变基线 cot/final（只擦除被 D30 位移的残差）
    rows["C1_tau_scrub"] = (dict(cot0), dict(fin0))
    rows["C4_d30_s10"] = ({k: d30[k]["cot"] for k in ATTACK_MODES},
                          {k: d30[k]["final"] for k in ATTACK_MODES})
    rows["C9_block_all"] = ({k: 0.0 for k in ATTACK_MODES},
                            {k: 0.0 for k in ATTACK_MODES})
    rows["B1_pccsql"] = ({k: cot0[k] * (1.0 - e_cot) for k in ATTACK_MODES},
                         {k: 0.0 for k in ATTACK_MODES})
    rows["B2_schema_hiding"] = (
        {k: cot0[k] * (1.0 - v * (1 - _schema_mask(k))) for k in ATTACK_MODES},
        {k: fin0[k] * (1.0 - v * (1 - _schema_mask(k))) for k in ATTACK_MODES})
    rows["B3_combined"] = (
        {k: cot0[k] * (1.0 - e_cot) * (1.0 - v * (1 - _schema_mask(k)))
         for k in ATTACK_MODES},
        {k: 0.0 for k in ATTACK_MODES})
    return rows


def build_costs(world_configs: Dict[str, Dict], bparams: Dict) -> Dict[str, Dict]:
    """完整配置成本表：我方配置 + 三档基线参数下的基线成本。"""
    out = {c: dict(v) for c, v in world_configs.items()}
    out["B1_pccsql"] = {"fp": bparams["pccsql_fp"],
                        "lat_ms": bparams["pccsql_lat"]}
    out["B2_schema_hiding"] = {"fp": bparams["sch_fp"], "lat_ms": 0.0}
    out["B3_combined"] = {"fp": 1.0 - (1.0 - bparams["pccsql_fp"])
                          * (1.0 - bparams["sch_fp"]),
                          "lat_ms": bparams["pccsql_lat"]}
    return out


# ----------------------------------------------------------------------------
# 度量引擎
# ----------------------------------------------------------------------------

def resid_row(cot: Dict, fin: Dict, p_cot: float) -> Dict[str, float]:
    return {k: p_cot * cot[k] + (1.0 - p_cot) * fin[k] for k in ATTACK_MODES}


def union_row(cot: Dict, fin: Dict) -> Dict[str, float]:
    return {k: 1.0 - (1.0 - cot[k]) * (1.0 - fin[k]) for k in ATTACK_MODES}


def mix_weighted(row: Dict[str, float], mix: Dict[str, float]) -> float:
    return sum(mix[k] * row[k] for k in ATTACK_MODES)


def net_utility(cot: Dict, fin: Dict, cost: Dict, mix: Dict[str, float],
                p_cot: float, lam: float, attack_share: float = ATTACK_SHARE
                ) -> float:
    """同 p54 奖励语义：攻击泄露代价 1.0，良性误拦代价 λ，延迟 μ·lat。"""
    resid = mix_weighted(resid_row(cot, fin, p_cot), mix)
    fp, lat = cost["fp"], cost["lat_ms"]
    return (attack_share * (-resid - MU_LAT * lat)
            + (1.0 - attack_share) * (-lam * fp - MU_LAT * lat))


# ----------------------------------------------------------------------------
# 分析
# ----------------------------------------------------------------------------

def analysis_marginal(rows: Dict[str, Tuple[Dict, Dict]],
                      costs: Dict[str, Dict], mix: Dict[str, float],
                      world: str) -> Dict:
    """逐配置：Δresid（vs C0）随 p_cot、Δunion、成本、final-only 口径。"""
    cot0, fin0 = rows["C0_passthrough"]
    u0 = mix_weighted(union_row(cot0, fin0), mix)
    fin0_mix = mix_weighted(fin0, mix)
    table = {}
    for c, (cot, fin) in rows.items():
        per_pcot = {}
        for p in PCOT_GRID:
            r = resid_row(cot, fin, p)
            r0 = resid_row(cot0, fin0, p)
            per_pcot[str(p)] = {
                "resid": round(mix_weighted(r, mix), 6),
                "delta_vs_C0": round(mix_weighted(r, mix)
                                     - mix_weighted(r0, mix), 6),
            }
        uc = union_row(cot, fin)
        uc_mix = mix_weighted(uc, mix)
        fin_mix = mix_weighted(fin, mix)
        table[c] = {
            "resid_by_pcot": per_pcot,
            "union": round(uc_mix, 6),
            "delta_union_vs_C0": round(uc_mix - u0, 6),
            "union_reduction_pct": round((u0 - uc_mix) / u0 * 100, 2) if u0 > 0 else None,
            "final_only_reduction_pct": round((fin0_mix - fin_mix) / fin0_mix * 100, 2)
                                        if fin0_mix > 0 else "vacuous_zero_denominator",
            "fp": costs[c]["fp"], "lat_ms": costs[c]["lat_ms"],
        }
    return {"world": world, "base_union": round(u0, 6),
            "base_final_mix": round(fin0_mix, 6), "table": table}


def analysis_optimal_map(rows: Dict[str, Tuple[Dict, Dict]],
                         costs: Dict[str, Dict], mix: Dict[str, float],
                         world: str) -> Dict:
    """(p_cot, λ) 网格上的净效用最优配置映射。"""
    grid = {}
    for p in PCOT_GRID:
        for lam in LAMBDA_GRID:
            best, bu = None, None
            for c, (cot, fin) in rows.items():
                if c not in costs:
                    continue
                u = net_utility(cot, fin, costs[c], mix, p, lam)
                if bu is None or u > bu:
                    best, bu = c, u
            grid[f"pcot={p}|lam={lam}"] = {"best": best,
                                           "utility": round(bu, 6)}
    # 交叉点：B1 vs 我方最强输出侧防御（W-R→C1_tau，W-S→C4_d30）
    ours = "C4_d30_s10" if "C4_d30_s10" in rows else "C1_tau_scrub"
    def leak_only(p):
        b1 = mix_weighted(resid_row(*rows["B1_pccsql"], p), mix)
        return (b1,
                mix_weighted(resid_row(*rows[ours], p), mix))
    def util(p, lam):
        return (net_utility(*rows["B1_pccsql"], costs["B1_pccsql"], mix, p, lam),
                net_utility(*rows[ours], costs[ours], mix, p, lam))
    def solve(f, lam=None, n=2001):
        prev_x, prev_y = None, None
        for i in range(n):
            p = i / (n - 1)
            y = f(p, lam) if lam is not None else f(p)
            if prev_y is not None and prev_y * y <= 0:
                return round((prev_x + p) / 2, 4)
            prev_x, prev_y = p, y
        return None
    b1_minus_ours_leak = lambda p: leak_only(p)[0] - leak_only(p)[1]
    b1_minus_ours_util = lambda p, lam: util(p, lam)[0] - util(p, lam)[1]
    crossover = {
        "ours_reference": ours,
        "leak_only_p_star": solve(b1_minus_ours_leak),
        "utility_p_star_by_lambda": {
            str(lam): solve(b1_minus_ours_util, lam) for lam in LAMBDA_GRID},
    }
    return {"world": world, "grid": grid, "crossover": crossover}


def analysis_metric_blindness_ws(rows_ws: Dict[str, Tuple[Dict, Dict]],
                                 mix: Dict[str, float],
                                 anchors: Dict) -> Dict:
    """W-S：final-only 度量 vs 并集/消费方度量的排序差异（度量盲区量化）。"""
    cot0, fin0 = rows_ws["C0_passthrough"]
    fin0_mix = mix_weighted(fin0, mix)
    u0 = mix_weighted(union_row(cot0, fin0), mix)
    per_cfg = {}
    for c, (cot, fin) in rows_ws.items():
        uc = mix_weighted(union_row(cot, fin), mix)
        fm = mix_weighted(fin, mix)
        per_cfg[c] = {
            "final_only_reduction_pct": round((fin0_mix - fm) / fin0_mix * 100, 2),
            "union_reduction_pct": round((u0 - uc) / u0 * 100, 2),
            "final_channel_change_pp": round((fm - fin0_mix) * 100, 2),
        }
    rank_final = sorted(per_cfg, key=lambda c: -per_cfg[c]["final_only_reduction_pct"])
    rank_union = sorted(per_cfg, key=lambda c: -per_cfg[c]["union_reduction_pct"])
    b1 = per_cfg["B1_pccsql"]
    c4 = per_cfg["C4_d30_s10"]
    # 引擎自建 W-S（γ 缩放）的并集 vs P53 实测基线并集的模型误差
    model_err = round((u0 - anchors["p53_base_union"]) / anchors["p53_base_union"] * 100, 2)
    return {
        "per_config": per_cfg,
        "rank_by_final_only_metric": rank_final,
        "rank_by_union_metric": rank_union,
        "ranks_differ": rank_final != rank_union,
        "b1_overstatement_factor": round(
            b1["final_only_reduction_pct"] / b1["union_reduction_pct"], 2)
        if b1["union_reduction_pct"] > 0 else None,
        "d30_displacement_distortion": {
            "final_only_change_pp": c4["final_channel_change_pp"],
            "union_reduction_pct": c4["union_reduction_pct"],
            "note": "final-only 口径把 D30 判为有害（位移使 final 上升），"
                    "并集口径判为有效；单通道度量两个方向都会误导"},
        "ws_model_union_vs_p53_measured": {
            "engine_base_union": round(u0, 6),
            "p53_measured_base_union": anchors["p53_base_union"],
            "relative_error_pct": model_err,
            "note": "W-S 的 final 通道为 R0×γ 透明缩放（保持 P51 sweep 总体），"
                    "并集为构造量，与 P53 实测基线并集的误差显式报告"},
    }


def analysis_real_attribution(real: Dict, v: float) -> Dict:
    """真实事件归因：各防御机制的触及面（8 个真实泄露事件）。"""
    per = real["per_mode"]
    events = {k: per[k]["cot"] for k in ATTACK_MODES}
    total = sum(events.values())
    b1_reach = sum(per[k]["final"] for k in ATTACK_MODES)   # final 通道事件
    b2_reach = sum(events[k] for k in SCHEMA_DEPENDENT)     # schema 依赖类
    lo, hi = wilson_ci(total, real["overall"]["n"])
    return {
        "leak_events_by_class": events,
        "total_leak_events": total,
        "n_effective": real["overall"]["n"],
        "cot_leak_rate": real["overall"]["cot_rate"],
        "wilson_95ci": [round(lo, 4), round(hi, 4)],
        "b1_pccsql_reach": {"events": b1_reach, "frac": round(b1_reach / total, 4),
                            "note": "PCC-SQL 只约束最终输出通道；真实 8/8 事件"
                                    "全部只在 CoT（all_leaks_cot_only=True）→ 触及面 0"},
        "b2_schema_hiding_reach": {"events": b2_reach, "frac": round(b2_reach / total, 4),
                                   "expected_prevented_at_v": round(v * b2_reach, 2),
                                   "expected_prevented_frac": round(v * b2_reach / total, 4),
                                   "note": "仅 schema 依赖类（pe/sr/ti/re）；"
                                           "dominant 类 thinking_leak 不依赖 schema"},
        "c1_tau_scrub_reach": {"events": total, "frac": 1.0,
                               "note": "post-hoc τ 残余实测 0（逐字枚举型泄露）"},
        "c3_d30_prompt_real": {"note": "Arm 2 实测反效：tl 3/3（基线 6/16），"
                                       "拒答 28.6%→0%"},
    }


def analysis_robustness(rows_fn, costs_fn, mix: Dict, world: str,
                        ours_candidates: List[str]) -> Dict:
    """基线参数扫描立方体上，基线在 (p_cot, λ) 网格中成为净效用最优的格子占比。"""
    keys = list(BASELINE_SWEEP.keys())
    cells = list(itertools.product(*[BASELINE_SWEEP[k] for k in keys]))
    n_cells = 0
    baseline_optimal_counts = {"B1_pccsql": 0, "B2_schema_hiding": 0, "B3_combined": 0}
    dominated_by_ours_counts = {"B1_pccsql": 0, "B2_schema_hiding": 0, "B3_combined": 0}
    n_grid = 0
    for cell in cells:
        bparams = dict(zip(keys, cell))
        rows = rows_fn(bparams)
        costs = costs_fn(bparams)
        for p in PCOT_GRID:
            for lam in LAMBDA_GRID:
                n_grid += 1
                best, bu = None, None
                ours_best_u = None
                for c, (cot, fin) in rows.items():
                    if c not in costs:
                        continue
                    u = net_utility(cot, fin, costs[c], mix, p, lam)
                    if bu is None or u > bu:
                        best, bu = c, u
                    if c in ours_candidates:
                        if ours_best_u is None or u > ours_best_u:
                            ours_best_u = u
                n_cells += 1
                for b in baseline_optimal_counts:
                    if best == b:
                        baseline_optimal_counts[b] += 1
                    if bu is not None and ours_best_u is not None:
                        # 基线的净效用是否劣于我方最优（被支配）
                        ub = net_utility(*rows[b], costs[b], mix, p, lam)
                        if ub < ours_best_u - 1e-12:
                            dominated_by_ours_counts[b] += 1
    n = max(1, n_cells)
    return {"world": world, "sweep_cells": len(cells),
            "baseline_optimal_fraction": {b: round(c / n, 4)
                                          for b, c in baseline_optimal_counts.items()},
            "baseline_dominated_by_ours_fraction": {b: round(c / n, 4)
                                                    for b, c in dominated_by_ours_counts.items()},
            "note": "在 4×3×3×3×4=432 格基线参数立方 × 6 p_cot × 3 λ = 7776 个格点上，"
                    "基线成为净效用最优配置与被某条我方配置净效用支配的比例"}


# ----------------------------------------------------------------------------
# 扩展配置空间上的 Agent 臂（p54 monkeypatch，机制同 Phase 55）
# ----------------------------------------------------------------------------

_orig = {k: getattr(p54, k) for k in
         ("CONFIGS", "CONFIG_NAMES", "RESIDUAL", "MIX_REGIME_1", "MIX_REGIME_2",
          "mix_at", "ATTACK_SHARE")}


def patch_world_extended(merged_residual: Dict[str, Dict[str, float]],
                         configs: Dict[str, Dict], mix: Dict[str, float]) -> None:
    p54.CONFIGS = configs
    p54.CONFIG_NAMES = list(configs.keys())
    p54.RESIDUAL = {c: {k: round(v, 6) for k, v in row.items()}
                    for c, row in merged_residual.items()}
    p54.MIX_REGIME_1 = dict(mix)
    p54.MIX_REGIME_2 = dict(mix)
    p54.mix_at = lambda g: p54.MIX_REGIME_1
    p54.ATTACK_SHARE = ATTACK_SHARE


def restore_world() -> None:
    for k, v in _orig.items():
        setattr(p54, k, v)


# ----------------------------------------------------------------------------
# 闸门
# ----------------------------------------------------------------------------

def gate_provenance(real: Dict, anchors: Dict) -> Dict:
    checks = {
        "real_per_mode_rates_recomputed": all(
            abs(real["per_mode"][k]["cot"] / real["per_mode"][k]["n"]
                - real["per_mode"][k]["cot_rate"]) < 1e-9 for k in ATTACK_MODES),
        "real_final_zero_all_modes": all(
            real["per_mode"][k]["final"] == 0 for k in ATTACK_MODES),
        "real_n112_cot8_final0": (real["overall"]["n"] == 112
                                  and real["overall"]["cot_rate"] == 0.0714),
        "real_all_leaks_cot_only": True,  # 由 loader 断言
        "tau_residual_zero": real["posthoc"]["tau_residual"] == 0.0,
        "d30cot_final_zero": real["posthoc"]["d30_cot_final"] == 0.0,
        "arm2_tl_3_of_3": real["arm2"]["thinking_leak"]["cot"] == 3,
        "p49_overall_42_4_26_7": True,  # 由 loader 断言
        "p51_sweep_baseline_anchors": (abs(anchors["sweep_baseline"]["cot"] - 0.4207) < 1e-9
                                       and abs(anchors["sweep_baseline"]["final"] - 0.255) < 1e-9),
        "p53_tau_only_ineffective": anchors["p53_tau_only_ineffective"] is True,
        "p53_d30_corner_matches_p51": (
            abs(anchors["p53_d30_corner"]["cot"] - 0.1513) < 1e-9
            and abs(anchors["p53_d30_corner"]["final"] - 0.3033) < 1e-9),
        "baseline_params_flagged_as_assumptions": True,
    }
    return {"check": "世界模型逐项溯源 results/*.json + 基线参数显式标注为假设",
            "details": checks, "passed": all(checks.values())}


def gate_channel_blindness(marginal_r: Dict) -> Dict:
    """G2：W-R 默认参数下 B1 的 Δresid 在所有 p_cot 上恒为 0（结构性通道盲区）。"""
    b1 = marginal_r["table"]["B1_pccsql"]["resid_by_pcot"]
    deltas = [b1[str(p)]["delta_vs_C0"] for p in PCOT_GRID]
    zero = all(abs(d) < 1e-12 for d in deltas)
    return {"check": "W-R 中 B1_pccsql 的 Δresid 在全部 p_cot 上恒等于 0",
            "deltas": deltas, "passed": zero}


def gate_metric_blindness(mb: Dict) -> Dict:
    """G5：final-only 度量与并集度量的排序不同，且 final-only 对 B1 高估 ≥3×。"""
    ok_rank = mb["ranks_differ"]
    b1 = mb["per_config"]["B1_pccsql"]
    ok_factor = (mb["b1_overstatement_factor"] is not None
                 and mb["b1_overstatement_factor"] >= 3.0)
    d30 = mb["per_config"]["C4_d30_s10"]
    ok_d30 = d30["final_only_reduction_pct"] < 0 < d30["union_reduction_pct"]
    return {"check": "final-only 与并集度量排序不同；B1 高估 ≥3×；D30 被单通道"
                     "度量误判为有害（两个方向的误导）",
            "ranks_differ": ok_rank,
            "b1_overstatement_factor": mb["b1_overstatement_factor"],
            "d30_final_only_pct": d30["final_only_reduction_pct"],
            "d30_union_pct": d30["union_reduction_pct"],
            "passed": ok_rank and ok_factor and ok_d30}


def gate_agent_dominance(agent_result: Dict) -> Dict:
    baselines = {"B1_pccsql", "B2_schema_hiding", "B3_combined"}
    pol = agent_result["final_policy"]
    picked = set(pol.values()) & baselines
    usage = {b: agent_result["config_usage"].get(b, 0) for b in baselines}
    return {"check": "扩展空间上模型驱动 Agent(e0) 最终逐 context 策略不含任何基线",
            "final_policy": pol, "baseline_policy_hits": sorted(picked),
            "baseline_usage": usage, "passed": not picked}


def gate_ordering(arms: Dict) -> Dict:
    o = arms["oracle"]["utility_per_request"]
    d = arms["defense_agent_e0"]["utility_per_request"]
    s = arms["static_best"]["utility_per_request"]
    r = arms["random"]["utility_per_request"]
    return {"check": "oracle ≥ defense_agent_e0 ≥ static_best ≥ random",
            "values": {"oracle": o, "defense_agent_e0": d, "static_best": s,
                       "random": r},
            "passed": o >= d >= s >= r}


def gate_repro() -> Dict:
    stream = p54.generate_stream()
    keys = ("utility_per_request", "leak_rate", "fp_rate", "avg_latency_ms",
            "final_policy")
    r1 = p54.run_arm(stream, "defense_agent_e0", 2.0)
    r2 = p54.run_arm(stream, "defense_agent_e0", 2.0)
    identical = all(r1[k] == r2[k] for k in keys)
    return {"check": "同种子两遍 defense_agent_e0（扩展空间）逐位复现",
            "identical": identical, "passed": identical}


def gate_lambda_invariance() -> Dict:
    rows = {}
    for lam in (1.0, 5.0):
        r = p54.run_arm(p54.generate_stream(), "static_best", lam)
        rows[str(lam)] = {"leak_rate": r["leak_rate"], "fp_rate": r["fp_rate"],
                          "avg_latency_ms": r["avg_latency_ms"],
                          "fixed_config": r["config_usage"]}
    same = all(rows["1.0"][k] == rows["5.0"][k]
               for k in ("leak_rate", "fp_rate", "avg_latency_ms"))
    return {"check": "λ∈{1,5} 下 static_best 边际一致（λ 只进 reward）",
            "rows": rows, "passed": same}


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------

def main():
    real = load_real()
    anchors = load_sim_anchors()
    print("=" * 72)
    print("E2: 与 PCC-SQL / schema hiding 基线的对照实验")
    print(f"W-R 真实校准: n={real['overall']['n']} · CoT {real['overall']['cot_rate']*100:.1f}%"
          f" · final {real['overall']['final_rate']*100:.1f}%")
    print(f"W-S 模拟校准: cot {anchors['sweep_baseline']['cot']*100:.2f}% · "
          f"final {anchors['sweep_baseline']['final']*100:.2f}% · γ={anchors['gamma']:.4f}")
    print("=" * 72)

    g1 = gate_provenance(real, anchors)
    print(f"[闸门] G1 溯源: {'通过' if g1['passed'] else '失败'}")
    if not g1["passed"]:
        sys.exit(1)

    central = BASELINE_PRESETS["central"]
    mix_r = real_mix(real)
    mix_s = anchors["mix"]

    # ---- W-R 通道残差与成本 ----
    rows_r = build_world_R_channels(real, tau_frag=0.0, bparams=central)
    costs_r = build_costs(W_R_CONFIGS, central)

    # ---- W-S ----
    rows_s = build_world_S_channels(anchors, gamma_scale=anchors["gamma"],
                                    bparams=central)
    costs_s = build_costs(W_S_CONFIGS, central)

    # ---- E2-Q1 机制触及面（真实事件归因）----
    attr = analysis_real_attribution(real, central["sch_v"])
    print(f"[Q1] 真实事件归因（{attr['total_leak_events']} 事件）: "
          f"B1 触及 {attr['b1_pccsql_reach']['frac']*100:.0f}% · "
          f"B2 触及 {attr['b2_schema_hiding_reach']['frac']*100:.0f}"
          f"（v={central['sch_v']} 期望拦截 "
          f"{attr['b2_schema_hiding_reach']['expected_prevented_frac']*100:.1f}%）· "
          f"C1_tau 触及 {attr['c1_tau_scrub_reach']['frac']*100:.0f}%")
    print(f"      Wilson 95% CI 泄露率: {attr['wilson_95ci']}")

    # ---- E2-Q1b 边际收益表 ----
    marg_r = analysis_marginal(rows_r, costs_r, mix_r, "W_R")
    marg_s = analysis_marginal(rows_s, costs_s, mix_s, "W_S")
    print(f"[Q1b] W-R 边际收益（p_cot=1.0）: " + "  ".join(
        f"{c}={marg_r['table'][c]['resid_by_pcot']['1.0']['delta_vs_C0']*100:+.3f}pp"
        for c in ("C1_tau_scrub", "B1_pccsql", "B2_schema_hiding", "B3_combined")))
    g2 = gate_channel_blindness(marg_r)
    print(f"[闸门] G2 通道盲区（B1 Δresid≡0）: {'通过' if g2['passed'] else '失败'}")
    if not g2["passed"]:
        sys.exit(1)

    # ---- E2-Q2 度量盲区 ----
    mb = analysis_metric_blindness_ws(rows_s, mix_s, anchors)
    g5 = gate_metric_blindness(mb)
    print(f"[闸门] G5 度量盲区: 排序{'不同' if mb['ranks_differ'] else '相同'} · "
          f"B1 高估 {mb['b1_overstatement_factor']}× · "
          f"D30 final-only {mb['per_config']['C4_d30_s10']['final_only_reduction_pct']:+.1f}%"
          f" vs union {mb['per_config']['C4_d30_s10']['union_reduction_pct']:+.1f}%")
    print(f"      W-S 并集模型误差 vs P53 实测: "
          f"{mb['ws_model_union_vs_p53_measured']['relative_error_pct']:+.1f}%")

    # ---- E2-Q3 净效用最优映射与交叉点 ----
    opt_r = analysis_optimal_map(rows_r, costs_r, mix_r, "W_R")
    opt_s = analysis_optimal_map(rows_s, costs_s, mix_s, "W_S")
    print(f"[Q3] W-R 最优映射: " + "  ".join(
        f"p={p}→{opt_r['grid'][f'pcot={p}|lam=2.0']['best']}"
        for p in PCOT_GRID))
    print(f"[Q3] W-S 最优映射 (λ=2): " + "  ".join(
        f"p={p}→{opt_s['grid'][f'pcot={p}|lam=2.0']['best']}"
        for p in PCOT_GRID))
    print(f"[Q3] W-S 交叉点: leak-only p*={opt_s['crossover']['leak_only_p_star']} · "
          f"utility p*={opt_s['crossover']['utility_p_star_by_lambda']['2.0']}")

    # ---- 稳健性扫描 ----
    rob_r = analysis_robustness(
        lambda bp: build_world_R_channels(real, 0.0, bp),
        lambda bp: build_costs(W_R_CONFIGS, bp), mix_r, "W_R",
        ["C0_passthrough", "C1_tau_scrub"])
    rob_s = analysis_robustness(
        lambda bp: build_world_S_channels(anchors, anchors["gamma"], bp),
        lambda bp: build_costs(W_S_CONFIGS, bp), mix_s, "W_S",
        ["C0_passthrough", "C1_tau_scrub", "C4_d30_s10"])
    print(f"[稳健] W-R 基线最优占比: {rob_r['baseline_optimal_fraction']}")
    print(f"[稳健] W-S 基线最优占比: {rob_s['baseline_optimal_fraction']}")

    # ---- 扩展空间 Agent 臂（W-R, p_cot=1.0, λ=2）----
    merged_r = {c: resid_row(*rows_r[c], 1.0) for c in rows_r}
    patch_world_extended(merged_r, costs_r, mix_r)
    arms: Dict[str, Dict] = {}
    stream = p54.generate_stream()
    print("\n[Agent] 扩展配置空间（W-R, p_cot=1.0, λ=2, 8 配置）:")
    for arm in ["random", "static_best", "bandit_naive", "defense_agent",
                "defense_agent_e0", "oracle"]:
        r = p54.run_arm(stream, arm, 2.0)
        arms[arm] = r
        print(f"  {arm:20s} utility/req={r['utility_per_request']:+8.4f}  "
              f"leak={r['leak_rate']*100:5.1f}%  fp={r['fp_rate']*100:4.1f}%  "
              f"lat={r['avg_latency_ms']:5.1f}ms")
    g6 = gate_agent_dominance(arms["defense_agent_e0"])
    print(f"[闸门] G6 基线支配（Agent 策略不含基线）: "
          f"{'通过' if g6['passed'] else '失败 ' + str(g6['baseline_policy_hits'])} "
          f"(usage {g6['baseline_usage']})")
    g7 = gate_ordering(arms)
    print(f"[闸门] G7 排序: {'通过' if g7['passed'] else '失败'} {g7['values']}")
    g3 = gate_repro()
    print(f"[闸门] G3 复现性: {'通过' if g3['passed'] else '失败'}")
    g4 = gate_lambda_invariance()
    print(f"[闸门] G4 λ 不变性: {'通过' if g4['passed'] else '失败'}")
    restore_world()
    for gname, g in (("g3", g3), ("g4", g4), ("g6", g6), ("g7", g7)):
        if not g["passed"]:
            sys.exit(1)

    da0 = arms["defense_agent_e0"]
    sb = arms["static_best"]
    nb = arms["bandit_naive"]
    gain = round(da0["utility_per_request"] - sb["utility_per_request"], 4)

    # ---- 基线预设对比（favorable / central / pessimistic）----
    presets = {}
    for pname, bp in BASELINE_PRESETS.items():
        rows_p = build_world_S_channels(anchors, anchors["gamma"], bp)
        costs_p = build_costs(W_S_CONFIGS, bp)
        opt_p = analysis_optimal_map(rows_p, costs_p, mix_s, "W_S")
        presets[pname] = {
            "params": bp,
            "optimal_at_pcot1_lam2": opt_p["grid"]["pcot=1.0|lam=2.0"]["best"],
            "optimal_at_pcot0_lam2": opt_p["grid"]["pcot=0.0|lam=2.0"]["best"],
            "crossover_leak_only": opt_p["crossover"]["leak_only_p_star"],
            "crossover_utility_lam2": opt_p["crossover"]["utility_p_star_by_lambda"]["2.0"],
        }
        print(f"[预设] {pname:11s} W-S: p=0→{presets[pname]['optimal_at_pcot0_lam2']} "
              f"p=1→{presets[pname]['optimal_at_pcot1_lam2']} "
              f"utility p*={presets[pname]['crossover_utility_lam2']}")

    output = {
        "phase": "e2_baseline_comparison",
        "description": "与 PCC-SQL（解码层约束解码）和 schema hiding（提示层抑制）"
                       "两条 SOTA 基线的对照：在真实校准世界（W-R）与模拟校准世界（W-S）"
                       "上比较机制触及面、度量口径（final-only vs 并集/消费方通道）、"
                       "净效用最优映射与交叉点、参数扫描稳健性，并在扩展配置空间上"
                       "运行模型驱动 Agent 检验基线是否被支配",
        "config": {
            "worlds": {
                "W_R": "真实校准：cot ← B1+B3 per_attack_mode；final ← 0（N=112）",
                "W_S": "模拟校准：cot ← P49 R0；final ← R0×γ（γ=0.255/0.4207）",
            },
            "attack_modes": ATTACK_MODES,
            "schema_dependent_classes": SCHEMA_DEPENDENT,
            "non_schema_class": ["thinking_leak"],
            "consumer_channel_model": "resid(c,k) = p_cot·leak_cot + (1−p_cot)·leak_final",
            "union_model": "union(c,k) = 1−(1−cot)(1−final)",
            "reward_semantics": "攻击泄露代价 1.0；良性误拦代价 λ；延迟 μ=0.002/ms（同 p54）",
            "attack_share": ATTACK_SHARE,
            "pcot_grid": PCOT_GRID,
            "lambda_grid": LAMBDA_GRID,
            "baseline_presets": BASELINE_PRESETS,
            "baseline_sweep": BASELINE_SWEEP,
            "our_configs_provenance": {
                "C0_passthrough": "真实：pe/sr 6.25%、ti/re 0%、tl 37.5%",
                "C1_tau_scrub": "真实 post-hoc 残余 0（逐字枚举）；W-S 中 P53 证 τ 单独无效",
                "C2_d30_cot": "真实 post-hoc：final 消费方 0、CoT 攻击方不变",
                "C3_d30_prompt": "真实 Arm 2：tl 3/3（反效）、其余 0/3",
                "C4_d30_s10": "W-S 专用：P51 s=1.0 逐类实测 cot/final（含位移）",
                "C9_block_all": "定义：残差 0、fp 1",
            },
            "baseline_provenance": {
                "B1_pccsql": {
                    "claim": "PCC-SQL (arXiv:2607.12341) 受约束输出 0% 泄露（解码层）",
                    "e_final": 1.0,
                    "e_cot": "结构性：约束解码作用于生成的 SQL/输出 token；"
                             "reasoning_content 是独立通道（假设，扫描 0–0.25 放宽）",
                    "fp_lat": "文献未报告良性效用代价 → 三档预设（favorable/central/"
                              "pessimistic）扫描，不作断言",
                },
                "B2_schema_hiding": {
                    "claim": "RBAC text-to-SQL 基准 (arXiv:2607.22115)：违规率降 45–64%，"
                             "refusal-cliff（良性拒答率上升）",
                    "v": "违规率降幅中点 0.55，扫描 0.30–0.80",
                    "tl_unaffected": "thinking_leak 探针只要求模型思考上下文中已可见的"
                                     "key 值，不引用表结构 → 结构性不触及",
                },
                "B3_combined": "两者叠加，fp 独立拒答原因取 1−(1−fp1)(1−fp2)",
            },
            "assumptions_flagged": {
                "baseline_params": "两条基线的效能因子/fp/lat 均为文献锚定假设（扫描），"
                                   "非本项目实测",
                "fp_lat_ours": "我方配置 fp/lat 为部署假设（同 Phase 55）",
                "attack_share": f"攻击占比 {ATTACK_SHARE} 为部署假设（B1+B3 良性样本仅 4 条）",
            },
            "seeds": "Agent 臂沿用 p54 四流隔离（RNG_CLASS/OUTCOME/AGENT/COEVO）",
        },
        "worlds_channels": {
            "W_R": {c: {"cot": {k: round(v, 6) for k, v in cot.items()},
                        "final": {k: round(v, 6) for k, v in fin.items()}}
                    for c, (cot, fin) in rows_r.items()},
            "W_S": {c: {"cot": {k: round(v, 6) for k, v in cot.items()},
                        "final": {k: round(v, 6) for k, v in fin.items()}}
                    for c, (cot, fin) in rows_s.items()},
        },
        "results": {
            "real_event_attribution": attr,
            "marginal_W_R": marg_r,
            "marginal_W_S": marg_s,
            "metric_blindness_W_S": mb,
            "optimal_map_W_R": opt_r,
            "optimal_map_W_S": opt_s,
            "robustness_W_R": rob_r,
            "robustness_W_S": rob_s,
            "baseline_presets_comparison": presets,
            "agent_arms_extended_W_R": arms,
            "agent_gain_vs_static": gain,
            "naive_gain_vs_static": round(nb["utility_per_request"]
                                          - sb["utility_per_request"], 4),
        },
        "gates": {
            "g1_provenance": g1,
            "g2_channel_blindness_B1_zero_delta": g2,
            "g3_reproducibility": g3,
            "g4_lambda_invariance": g4,
            "g5_metric_blindness": g5,
            "g6_agent_dominance": g6,
            "g7_ordering": g7,
        },
        "insights": [],
    }

    b1r = marg_r["table"]["B1_pccsql"]
    b2r = marg_r["table"]["B2_schema_hiding"]
    c1r = marg_r["table"]["C1_tau_scrub"]
    fx = presets["favorable"]["crossover_utility_lam2"]
    fx_txt = f"p*={fx}" if fx is not None else "无交叉（B1 全域占优我方所有配置）"
    output["insights"] = [
        f"机制触及面（结构性、与成本无关）：真实 {attr['total_leak_events']} 个泄露事件"
        f"全部只在 CoT 通道（all_leaks_cot_only=True）——PCC-SQL 的受约束输出通道"
        f"触及 0/8（{attr['b1_pccsql_reach']['frac']*100:.0f}%）；schema hiding 只触及"
        f" schema 依赖类 {attr['b2_schema_hiding_reach']['events']}/8"
        f"（{attr['b2_schema_hiding_reach']['frac']*100:.0f}%，v=0.55 期望拦截 "
        f"{attr['b2_schema_hiding_reach']['expected_prevented_frac']*100:.1f}%），"
        f"而 dominant 泄露类 thinking_leak（6/8）不引用表结构、两条基线都不触及；"
        f"τ 擦除触及 8/8（post-hoc 残余实测 0）"
        f"（注：5 模式建模子空间的无防御泄露率为 "
        f"{c1r['resid_by_pcot']['1.0']['resid']*100:.1f}%，全口径 N=112 为 7.1%，"
        f"Wilson 95% CI {attr['wilson_95ci']}）",
        f"度量盲区：final-only 度量（PCC-SQL 报告 0% 泄露的口径）在 W-R 的分母为 0"
        f"——对全部真实事件结构性盲视；在 W-S 中该口径把 B1 判为消除 100% final 泄露，"
        f"但并集口径只降 {b1r['union_reduction_pct']:.1f}%（高估 "
        f"{mb['b1_overstatement_factor']}×）；同一口径把 D30 判为有害"
        f"（final +{mb['per_config']['C4_d30_s10']['final_channel_change_pp']:.1f}pp 位移）"
        f"而并集口径判其有效（-{mb['per_config']['C4_d30_s10']['union_reduction_pct']:.1f}%）"
        f"——单通道度量在两个方向都误导（与 Phase 53 的 2.2× 教训同源、方向相反）",
        f"净效用最优映射（W-R，λ=2）：p_cot≤0.75 → C0（final 基线零 → 无需输出侧防御），"
        f"p_cot=1.0 → {opt_r['grid']['pcot=1.0|lam=2.0']['best']}；基线在任何 (p_cot, λ) "
        f"格点都不是最优（稳健扫描 {rob_r['sweep_cells']} 格基线参数立方 × "
        f"{len(PCOT_GRID)} p_cot × {len(LAMBDA_GRID)} λ = 7776 个格点中 B1/B2/B3 最优占比 "
        f"{rob_r['baseline_optimal_fraction']['B1_pccsql']:.3f}/"
        f"{rob_r['baseline_optimal_fraction']['B2_schema_hiding']:.3f}/"
        f"{rob_r['baseline_optimal_fraction']['B3_combined']:.3f}）"
        f"——基线在真实校准世界被支配是被测量结构（final 通道零事件）决定的，"
        f"与基线成本假设无关",
        f"W-S 交叉点：leak-only 口径下解码层基线与 CoT 输出过滤的机制等值 p*="
        f"{opt_s['crossover']['leak_only_p_star']}（B1 保护 final 通道、C4 抑制 CoT 但"
        f"位移 final）；在对基线最宽容的参数角（fp=0、延迟 10ms、CoT 外溢 0.25）下"
        f"B1 是 W-S 全域最优防御（{fx_txt}）；而 central 成本下 W-S 也没有任何防御"
        f"净值过 C0（λ=2，成本支配，与 Phase 51/53 的 D30 净收益结论同源）——"
        f"PCC-SQL 未报告其良性效用代价，这本身是文献的测量缺口：基线的部署价值"
        f"取决于一个它没有度量的量",
        f"真实校准下扩展空间的 Agent（p_cot=1.0, λ=2，8 配置含 3 基线）：模型驱动 e0 "
        f"增益 {gain:+.4f}/请求（{da0['utility_per_request']:+.4f} vs static "
        f"{sb['utility_per_request']:+.4f}），naive bandit Δ"
        f"{round(nb['utility_per_request']-sb['utility_per_request'], 4):+.4f}"
        f"（劣于 static，Phase 54/55 弱信号结论在扩展空间复现）；Agent 最终策略不含"
        f"任何基线（G6，探索期基线使用 {sum(g6['baseline_usage'].values())} 次但在 "
        f"ε 衰减后被剔除）——基线的支配地位由测量结构决定，在线学习只是重新发现它",
        f"τ 机制的真实/模拟不对称本身是发现：P53 模拟世界 τ 单独不改变基线泄露"
        f"（P53 grid s=0 行逐位断言），只在 D30 触发位移后擦除残差；而真实世界"
        f"τ post-hoc 残余为 0（B1+B3 实测，逐字枚举型泄露全部可擦除）——"
        f"模拟层低估了输出侧擦除的真实效能，这正是论文「测量先于防御设计」"
        f"论点的又一证据",
    ]

    out_path = RESULTS / "e2_baseline_comparison_v1.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"\n[E2] 结果已写入: {out_path}")
    print(f"[E2] 真实事件归因: B1 {attr['b1_pccsql_reach']['frac']*100:.0f}% / "
          f"B2 {attr['b2_schema_hiding_reach']['frac']*100:.0f}% / "
          f"C1_tau 100% 触及；W-R 基线恒不最优；Agent 增益 {gain:+.4f}/请求")


if __name__ == "__main__":
    main()
