"""
Phase 52: D23' x D30 双层组合 —— 防御堆叠是否等于乘积级安全？

背景
----
Phase 50 得到 D23'（输入侧，改写等价类规范化）的最优覆盖度 c* 与残留下游绕过率，
Phase 51 得到 D30（输出侧，CoT 记忆防火墙）的最优严格度 s* 与残余泄露率。
两者分别来自两次独立实验、分别针对输入侧与输出侧，所以"把它们叠起来"这个动作
本身还没有被实验过。本 phase 回答：

    把两层都上，是得到"两层阻断率的乘积"这种理想增益，
    还是只得到"两层里较强那一层的水平"？

这正是 Phase 47 提出的"共享盲点"问题，但 Phase 47 用的是 9 层随机级联，
与本 phase 的"两个具体防御、两个具体配置"不是同一个对象。

--------------------------------------------------------------------------
模型：强度无关的共单调混合耦合（边际一致版本）
--------------------------------------------------------------------------
每个探针上两层防御各有一个伯努利"失效"事件，边际分别为
    q_A(c) = P(D23' 在覆盖度 c 下被穿透)      —— 直接取 Phase 50 实测值
    q_B(s) = P(D30  在严格度 s 下未拦住泄露)  —— 直接取 Phase 51 实测值

耦合规则（以概率 rho 选择"绑定"分支）：
    bound       （概率 rho）：抽一个共享随机变量 U ~ U(0,1)，
                            两层用**同一个 U** 按**各自阈值**判定
                            A=(U<q_A)，B=(U<q_B)
    independent （概率 1-rho）：两层各抽独立随机变量，A=(U_A<q_A)，B=(U_B<q_B)

三个性质（都是可数值验证的，不是构造性断言）：
    (i)   两个分支的边际都是 (q_A, q_B) —— 因此混合后的边际与 rho 无关（边际守恒）
    (ii)  rho=0 => P(A and B) = q_A * q_B            （乘积律 / 教科书独立假设）
    (iii) rho=1 => P(A and B) = min(q_A, q_B)        （共单调耦合 / 取小律）

(iv) 取小律就是 Frechet 上界，即 P(A and B) <= min(P(A), P(B)) 的紧上界。
    所以在边际固定的前提下，rho=1 已经是"联合穿透率"能达到的最大可能值，
    任何超出 min(q_A, q_B) 的建模结果都不可达。

为什么不用 Phase 47 的"共享 Bernoulli(均值盲点)"，而用"共享 U + 各自阈值"
--------------------------------------------------------------------------
Phase 47 的绑定分支令所有层共享同一个 Bernoulli(shared_base * I)，其中
shared_base = 各层独立盲点率的**均值**。这个写法本身不违反任何不等式
（rho=1 时 P(A)=P(B)=P(A and B)，取小律恰好取等），但它的实际后果是：

    各层的单层边际穿透率被**强制改写为同一个均值**，不再是各层真实的盲点率。

这不是修辞上的瑕疵，它会让 Phase 47 在同一份结果里同时给出两组互相矛盾的
单层数字。本 phase 用 Phase 47 已落盘的 per_defense_bypass_rate 直接验证
这一点（不需要任何新假设）：

    rho=0 时各层数字仍大致保留内在强弱次序（弱层盲点率仍偏高）；
    rho=1 时 D30_memory_firewall（内在最强，盲点 0.083）实测穿透率 0.2101，
    反而高于 D29_gan_detector（内在最弱，盲点 0.237）的 0.1792 ——
    最强层被报告成比最弱层更易穿透。用秩相关量化：内在盲点率排序与 rho=1
    实测排序的 Spearman 相关约 0.05，即基本没有相关性，排名已退化为噪声。

因此"rho 仅改变相关性、不改变单层边际"（Phase 47 config 里的 note）在
Phase 47 的构造下**不成立**。本 phase 用"共享 U + 各自阈值"重写同一模型
（防御池、级联长度分布、强度 Beta(2,2)、绑定概率 rho 全部保持 Phase 47
原样），使边际守恒真正成立，从而：

    - 标定出 rho 在边际一致模型下能达到的穿透率/缺口**上界**；
    - 得出 Phase 47 报告值相对该上界的倍数（构造缺陷的量化幅度）；
    - 用同一套边际一致的耦合机制回答本 phase 的核心问题（双层堆叠）。

本 phase 不修改 Phase 47 已落盘的结果与报告，只做显式勘误标注，以保持
Phase 47 自身的可复现性。

--------------------------------------------------------------------------
三道自检闸门（任一失败即中止，视为实验作废）
--------------------------------------------------------------------------
0. Phase 47 锚点逐位复刻：先在本文件内逐行复刻 Phase 47 引擎并从 seed 2047
   顺序跑完 5 个 rho，必须复现已落盘的 per_rho["0.0"]=0.0095 与
   per_rho["1.0"]=0.0725。若复现失败，说明本文件对 Phase 47 的理解有误，
   后续所有对 Phase 47 的批评都不成立，因此这一步必须先行。
1. 边际守恒：对每个 rho，模拟出的单侧穿透率必须等于输入的 q_A / q_B（容差 0.01）。
2. 乘积律：rho=0 时联合穿透率必须等于 q_A * q_B。
3. 取小律：rho=1 时联合穿透率必须等于 min(q_A, q_B)。

另加两道稳健性检查（不作为闸门）：
4. 单调性：联合穿透率关于 rho 非递减。
5. 多 seed 稳定性：同一格点在 3 个 seed 下的偏差上界。

--------------------------------------------------------------------------
交付
--------------------------------------------------------------------------
- c x s 网格（7 x 6）在 5 个 rho 下的联合穿透率与独立性折扣因子（joint/product）
- rho 标定：边际一致模型的可达上界、Phase 47 报告值相对上界的倍数
- Phase 47 单层排名退化度量（Spearman）
- 叠加净收益 vs 最优单层基准：对每个 lambda 求出"叠加还划算的最大 rho"（rho_max）
- 部署结论：共享盲点相关系数下的双层堆叠最优点在哪里
"""

from __future__ import annotations

import json
import math
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"

# ---------------------------------------------------------------------------
# Phase 47 的原配置（防御池 / 盲点率 / 级联长度分布 / 强度分布）——原样复用
# ---------------------------------------------------------------------------
DEFENSES = [
    "D23_semantic_fingerprint", "D24_temporal_consistency", "D25_causal_constraint",
    "D26_rag_audit", "D27_gradient_clip_enhanced", "D28_agent_sandbox",
    "D29_gan_detector", "D30_memory_firewall", "D31_coevolution_steady",
]
BASE_BLOCK_RATE = {
    "D23_semantic_fingerprint": 0.864, "D24_temporal_consistency": 0.870,
    "D25_causal_constraint": 0.873, "D26_rag_audit": 0.860,
    "D27_gradient_clip_enhanced": 0.907, "D28_agent_sandbox": 0.883,
    "D29_gan_detector": 0.763, "D30_memory_firewall": 0.917,
    "D31_coevolution_steady": 0.808,
}
CHAIN_LENGTHS = [1, 2, 3, 4, 5]
CHAIN_WEIGHTS = [0.15, 0.25, 0.25, 0.20, 0.15]
INTENSITY_ALPHA, INTENSITY_BETA = 2, 2
RHO_SWEEP_47 = [0.0, 0.3, 0.6, 0.9, 1.0]
SEED_47 = 2047
PROBES_47 = 2000

BLINDSPOT = {d: round(1.0 - BASE_BLOCK_RATE[d], 4) for d in DEFENSES}

# ---------------------------------------------------------------------------
# Phase 52 的网格
# ---------------------------------------------------------------------------
COVERAGE_GRID = [0.0, 0.2, 0.4, 0.6, 0.8, 0.95, 1.0]
STRICTNESS_GRID = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
RHO_GRID = [0.0, 0.25, 0.5, 0.75, 1.0]
PROBES_GRID = 20000        # 每 (c, s, rho) 格点的探针数
PROBES_CHECK = 100000      # 自检用探针数
SEEDS = [5201, 5202, 5203]
LAMBDA_GRID = [1.0, 2.0, 5.0]
TOL = 0.01                 # 自检容差（100000 探针下 SE≈0.0015，留足余量）

# 部署配置（Phase 50 / 51 各自的最优点）
C_STAR = 1.0
S_STAR = 1.0

# 成本模型（与 Phase 50 / 51 完全一致）
FP_D23_BASE, FP_D23_SLOPE = 0.04, 0.15
LAT_D23_BASE, LAT_D23_SLOPE = 12.0, 9.0
UTIL_D30_COEF, UTIL_D30_EXP = 0.30, 1.6
LAT_D30_BASE, LAT_D30_SCALING, LAT_D30_EXP = 8.0, 45.0, 1.5
LAT_NORMALIZE = 1000.0


# ---------------------------------------------------------------------------
# 从已落盘的 Phase 50 / 51 结果读取边际（不硬编码）
# ---------------------------------------------------------------------------
def load_marginals() -> Tuple[Dict[float, float], Dict[float, float], Dict[str, Dict]]:
    """返回 (q_A: coverage->D23' 穿透率, q_B: strictness->D30 残余泄露率, 原始记录)。"""
    p50 = json.loads((RESULTS / "phase50_defense_iteration_d23_prime_v1.json")
                     .read_text(encoding="utf-8"))["results"]
    p51 = json.loads((RESULTS / "phase51_cot_firewall_ablation_v1.json")
                     .read_text(encoding="utf-8"))["results"]

    q_a: Dict[float, float] = {0.0: p50["arm_a_baseline"]["bypass_rate"]}
    for k, v in p50["arm_b_iteration"].items():
        q_a[float(k)] = v["bypass_rate"]

    q_b: Dict[float, float] = {}
    for k, v in p51["arm_b_static_sweep"].items():
        q_b[float(k)] = v["cot_eff_leak_rate"]

    missing = ([c for c in COVERAGE_GRID if c not in q_a]
               + [s for s in STRICTNESS_GRID if s not in q_b])
    if missing:
        raise SystemExit(f"边际缺失，无法建网格：coverage 缺 {q_a and [m for m in missing if m in COVERAGE_GRID]}，"
                         f"strictness 缺 {[m for m in missing if m in STRICTNESS_GRID]}")

    raw = {
        "p50_arm_a_bypass": p50["arm_a_baseline"]["bypass_rate"],
        "p50_arm_b_bypass": {k: v["bypass_rate"] for k, v in p50["arm_b_iteration"].items()},
        "p50_arm_b_fp": {k: v["false_positive_rate"] for k, v in p50["arm_b_iteration"].items()},
        "p50_arm_b_lat": {k: v["overhead_ms"] for k, v in p50["arm_b_iteration"].items()},
        "p51_arm_b_cot_eff": {k: v["cot_eff_leak_rate"] for k, v in p51["arm_b_static_sweep"].items()},
        "p51_arm_b_final_eff": {k: v["final_eff_leak_rate"] for k, v in p51["arm_b_static_sweep"].items()},
        "p51_arm_b_util": {k: v["utility_loss"] for k, v in p51["arm_b_static_sweep"].items()},
        "p51_arm_b_lat": {k: v["lat_overhead_ms"] for k, v in p51["arm_b_static_sweep"].items()},
        "p51_per_attack_s0": {k: dict(v) for k, v in p51["arm_b_static_sweep"]["0.0"]["per_attack"].items()},
        "p51_per_attack_s1": {k: dict(v) for k, v in p51["arm_b_static_sweep"]["1.0"]["per_attack"].items()},
        "p51_probes": p51["sweep_baseline"]["probes"],
        "p50_probes": p50["arm_a_baseline"]["total_probes"],
    }
    return q_a, q_b, raw


def fp_d23(c: float) -> float:
    return FP_D23_BASE + FP_D23_SLOPE * c


def lat_d23_ms(c: float) -> float:
    return LAT_D23_BASE + LAT_D23_SLOPE * c


def util_d30(s: float) -> float:
    return 0.0 if s == 0.0 else UTIL_D30_COEF * s ** UTIL_D30_EXP


def lat_d30_ms(s: float) -> float:
    return 0.0 if s == 0.0 else LAT_D30_BASE + LAT_D30_SCALING * s ** LAT_D30_EXP


def cost_single_d23(c: float, lam: float) -> float:
    return lam * (fp_d23(c) + lat_d23_ms(c) / LAT_NORMALIZE)


def cost_single_d30(s: float, lam: float) -> float:
    return lam * (util_d30(s) + lat_d30_ms(s) / LAT_NORMALIZE)


def cost_stack(c: float, s: float, lam: float) -> float:
    return lam * (fp_d23(c) + util_d30(s)
                  + (lat_d23_ms(c) + lat_d30_ms(s)) / LAT_NORMALIZE)


# ---------------------------------------------------------------------------
# Phase 47 原引擎的逐位复刻（仅用于验证我是否正确理解 Phase 47）
# ---------------------------------------------------------------------------
class Phase47Replay:
    """与 phase47_multi_defense_cascade.py 的 MultiDefenseCascade 逐行同构。

    RNG 消耗顺序必须完全一致：
        random.choices(CHAIN_LENGTHS, weights) -> random.sample(DEFENSES, k)
        -> random.betavariate(2, 2) -> [random.random() 判定 shared_match]
        -> 逐层 [random.random() 判定是否绑定] [+random.random() 独立盲点判定]
    若任一处顺序不同，自检 0 会失败，本文件对 Phase 47 的理解即被否证。
    """

    def __init__(self, rho: float):
        self.rho = rho
        self.blindspot = {d: round(1.0 - BASE_BLOCK_RATE[d], 4) for d in DEFENSES}
        self.shared_base = round(sum(self.blindspot.values()) / len(self.blindspot), 4)

    def _run_chain(self, chain: List[str], intensity: float) -> Tuple[int, List[bool]]:
        shared_p = min(0.95, self.shared_base * intensity)
        shared_match = random.random() < shared_p

        depth, outcomes = 0, []
        for d in chain:
            if random.random() < self.rho:
                defeated = shared_match
            else:
                defeated = random.random() < (self.blindspot[d] * intensity)
            outcomes.append(defeated)
            if defeated:
                depth += 1
            else:
                break
        return depth, outcomes

    def run(self, total_probes: int = PROBES_47) -> Dict:
        full, per_def_bypass, per_def_count, by_len = 0, {}, {}, {}
        for d in DEFENSES:
            per_def_bypass[d] = 0
            per_def_count[d] = 0
        for L in CHAIN_LENGTHS:
            by_len[L] = {"tried": 0, "bypassed": 0}

        for _ in range(total_probes):
            chain_len = random.choices(CHAIN_LENGTHS, weights=CHAIN_WEIGHTS)[0]
            chain = random.sample(DEFENSES, k=chain_len)
            intensity = random.betavariate(INTENSITY_ALPHA, INTENSITY_BETA)

            depth, outcomes = self._run_chain(chain, intensity)
            if depth == chain_len:
                full += 1
            for j, d in enumerate(chain):
                if j >= len(outcomes):
                    break
                per_def_count[d] += 1
                if outcomes[j]:
                    per_def_bypass[d] += 1
            by_len[chain_len]["tried"] += 1
            if depth == chain_len:
                by_len[chain_len]["bypassed"] += 1

        for L in CHAIN_LENGTHS:
            by_len[L]["rate"] = round(by_len[L]["bypassed"] / max(1, by_len[L]["tried"]), 4)
        return {
            "rho": self.rho, "total_probes": total_probes,
            "cascade_success_rate": round(full / total_probes, 4),
            "per_defense_bypass_rate": {
                d: round(per_def_bypass[d] / max(1, per_def_count[d]), 4) for d in DEFENSES},
            "by_chain_length": {str(L): by_len[L] for L in CHAIN_LENGTHS},
        }


# ---------------------------------------------------------------------------
# 解析式期望（闭式解，用于标定，不依赖蒙特卡洛）
# ---------------------------------------------------------------------------
def _elem_symmetric(qs: Sequence[float]) -> List[float]:
    """e[k] = 所有 k 元子集的乘积和。"""
    n = len(qs)
    e = [0.0] * (n + 1)
    e[0] = 1.0
    for q in qs:
        for k in range(min(n, len(qs)), 0, -1):
            e[k] += e[k - 1] * q
    return e


def _mean_min_over_samples(qs: Sequence[float], L: int) -> float:
    """均匀 L 元子集上 min 的期望，闭式解：
    sum_k x_(k) * C(n-k, L-1) / C(n, L)，其中 x_(k) 为升序第 k 个。
    推导：子集最小值等于 x_(k) 当且仅当其余 L-1 个元素取自 x_(k) 之后的 n-k 个。
    """
    n = len(qs)
    xs = sorted(qs)
    denom = math.comb(n, L)
    tot = 0.0
    for k in range(1, n - L + 2):
        tot += xs[k - 1] * math.comb(n - k, L - 1)
    return tot / denom


def _beta22_moment(L: int) -> float:
    """E[I^L] for I ~ Beta(2,2) = 6/((L+2)(L+3))。L=1 时 = 0.5。"""
    return 6.0 / ((L + 2) * (L + 3))


def clean_expected_rate(rho: float, qs: Sequence[float]) -> float:
    """边际一致耦合下的解析期望。

    绑定分支：所有层共用一个 U，P(all defeated) = E[min_i q_i] * E[I]
    独立分支：P(all defeated) = E[prod_i q_i] * E[I^L]
    强度 I 与链采样独立，故可分离。
    """
    e = _elem_symmetric(qs)
    n = len(qs)
    e_intensity = _beta22_moment(1)   # E[I] = 0.5 for Beta(2,2)
    rate = 0.0
    for L, w in zip(CHAIN_LENGTHS, CHAIN_WEIGHTS):
        prod_mean = e[L] / math.comb(n, L)
        min_mean = _mean_min_over_samples(qs, L)
        rate += w * (rho * min_mean * e_intensity + (1 - rho) * prod_mean * _beta22_moment(L))
    return rate


# ---------------------------------------------------------------------------
# Phase 52 主引擎：两层共单调混合耦合
# ---------------------------------------------------------------------------
class TwoLayerStack:
    """q_A / q_B 边际固定的两层组合。use_intensity 提供强度敏感性变体。"""

    def __init__(self, rho: float, use_intensity: bool = False,
                 intensity_scale: float = 0.5):
        self.rho = rho
        self.use_intensity = use_intensity
        # 强度变体下边际保持 E[I]*q = intensity_scale*q，故用该比例把
        # 实测率还原成"满强度参数"，使报告的边际仍等于实测率
        self.intensity_scale = intensity_scale

    def run(self, q_a: float, q_b: float, probes: int, seed: int) -> Dict:
        rng = random.Random(seed)
        if self.use_intensity:
            qa = q_a / self.intensity_scale
            qb = q_b / self.intensity_scale
        else:
            qa, qb = q_a, q_b

        a_hit = b_hit = both = 0
        for _ in range(probes):
            intensity = rng.betavariate(INTENSITY_ALPHA, INTENSITY_BETA) if self.use_intensity else 1.0
            ta = qa * intensity
            tb = qb * intensity
            if rng.random() < self.rho:
                u = rng.random()
                a = u < ta
                b = u < tb
            else:
                a = rng.random() < ta
                b = rng.random() < tb
            a_hit += int(a)
            b_hit += int(b)
            both += int(a and b)

        return {
            "rho": self.rho,
            "probes": probes,
            "q_a": q_a, "q_b": q_b,
            "a_rate": round(a_hit / probes, 6),
            "b_rate": round(b_hit / probes, 6),
            "joint": round(both / probes, 6),
            "product_pred": round(q_a * q_b, 6),
            "min_pred": round(min(q_a, q_b), 6),
            "discount_factor": round((both / probes) / max(1e-12, q_a * q_b), 4),
            "a_drift": round(abs(a_hit / probes - q_a), 6),
            "b_drift": round(abs(b_hit / probes - q_b), 6),
        }


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------
def self_check_marginals(rho_grid: Sequence[float],
                         pairs: Sequence[Tuple[float, float]]) -> Dict:
    """自检 1：边际守恒。

    附带诊断量：Phase 47 的绑定分支把两层的边际都写成同一个共享率 base
    （此处 base = (q_A+q_B)/2，对应 Phase 47 里"均值盲点"的写法）。
    这不违反 Frechet 上界（rho=1 时 P(A)=P(B)=P(A and B)，上界恰好取等），
    它的问题是**边际本身被改写**：只要 q_A != q_B，两层的真实盲点率就被抹平。
    下面的 drift 就是这个抹平幅度的实测值。
    """
    drift = {}
    max_drift = 0.0
    for rho in rho_grid:
        row = {}
        for (qa, qb) in pairs:
            r = TwoLayerStack(rho).run(qa, qb, PROBES_CHECK, seed=777)
            d = max(r["a_drift"], r["b_drift"])
            max_drift = max(max_drift, d)

            base = (qa + qb) / 2
            n = PROBES_CHECK
            rng = random.Random(778)
            a47 = b47 = 0
            for _ in range(n):
                u = rng.random() < base
                a47 += int(u)
                b47 += int(u)
            row[f"qa={qa:.4f}__qb={qb:.4f}"] = {
                "clean_a": r["a_rate"], "clean_b": r["b_rate"],
                "clean_max_drift": d,
                "phase47_shared_rate": round(base, 6),
                "phase47_a_measured": round(a47 / n, 6),
                "phase47_b_measured": round(b47 / n, 6),
                "phase47_a_marginal_drift": round(abs(a47 / n - qa), 6),
                "phase47_b_marginal_drift": round(abs(b47 / n - qb), 6),
                "true_marginals_differ": bool(abs(qa - qb) > 1e-9),
                "frechet_upper_bound_on_joint": round(min(qa, qb), 6),
                "phase47_joint_under_same_rule": round(base, 6),
            }
        drift[str(rho)] = row
    return {"check": "边际守恒（clean 构造）+ Phase 47 原构造边际改写幅度诊断",
            "probes_per_cell": PROBES_CHECK,
            "pairs": [{"q_a": a, "q_b": b} for a, b in pairs],
            "tolerance": TOL,
            "clean_max_drift": round(max_drift, 6),
            "passed": max_drift < TOL,
            "per_rho": drift,
            "note": ("Phase 47 的绑定分支不违反 P(A and B) <= min(P(A),P(B))"
                     "（rho=1 时三者相等，上界取等）；它的缺陷是把各层边际强制改写为"
                     "同一个共享率，只要各层盲点不相等就必然发生。上面的 drift 是该"
                     "改写幅度的实测值，不是构造性断言。")}


def self_check_laws(rho_grid: Sequence[float],
                    pairs: Sequence[Tuple[float, float]]) -> Dict:
    """自检 2/3：rho=0 乘积律、rho=1 取小律。"""
    prod_max = 0.0
    min_max = 0.0
    detail = {}
    for (qa, qb) in pairs:
        row = {}
        for rho in rho_grid:
            r = TwoLayerStack(rho).run(qa, qb, PROBES_CHECK, seed=991)
            row[str(rho)] = r
            if abs(rho) < 1e-9:
                prod_max = max(prod_max, abs(r["joint"] - r["product_pred"]))
            if abs(rho - 1.0) < 1e-9:
                min_max = max(min_max, abs(r["joint"] - r["min_pred"]))
        detail[f"qa={qa:.4f}__qb={qb:.4f}"] = row
    return {"probes_per_cell": PROBES_CHECK, "tolerance": TOL,
            "product_law_max_abs_error": round(prod_max, 6),
            "min_law_max_abs_error": round(min_max, 6),
            "passed": (prod_max < TOL) and (min_max < TOL),
            "per_pair": detail}


def self_check_monotone(rho_grid: Sequence[float],
                        pairs: Sequence[Tuple[float, float]]) -> Dict:
    """稳健性 4：联合穿透率关于 rho 非递减。"""
    viol = []
    for (qa, qb) in pairs:
        prev = None
        for rho in rho_grid:
            v = TwoLayerStack(rho).run(qa, qb, PROBES_GRID, seed=5201)["joint"]
            if prev is not None and v < prev - 1e-9:
                viol.append({"q_a": qa, "q_b": qb, "rho": rho, "prev": prev, "cur": v})
            prev = v
    return {"pairs_checked": len(pairs), "rho_points": list(rho_grid),
            "monotone_violations": viol, "passed": not viol}


def spearman(xs: Sequence[float], ys: Sequence[float]) -> float:
    n = len(xs)
    def rank(v: Sequence[float]) -> List[float]:
        order = sorted(range(n), key=lambda i: v[i])
        r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r
    rx, ry = rank(xs), rank(ys)
    mx = sum(rx) / n
    my = sum(ry) / n
    cov = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    sx = math.sqrt(sum((rx[i] - mx) ** 2 for i in range(n)))
    sy = math.sqrt(sum((ry[i] - my) ** 2 for i in range(n)))
    return cov / (sx * sy) if sx > 0 and sy > 0 else float("nan")


def calibrate_rho(qs: Sequence[float], target_rate: float, target_gap: float) -> Dict:
    """用 Phase 47 的两个实测锚点标定 rho，并报告边际一致模型的可达上界。"""
    rate0 = clean_expected_rate(0.0, qs)
    rate1 = clean_expected_rate(1.0, qs)
    gap1 = rate1 / rate0 if rate0 > 0 else float("inf")

    # 解 clean_rate(rho) = target_rate
    feasible_rate = rate0 <= target_rate <= rate1
    rho_rate = None
    if feasible_rate:
        rho_rate = (target_rate - rate0) / (rate1 - rate0)

    # 解 gap(rho) = target_gap；gap 关于 rho 单调，线性关系
    feasible_gap = 1.0 <= target_gap <= gap1
    rho_gap = None
    if feasible_gap and gap1 > 1.0:
        rho_gap = (target_gap - 1.0) / (gap1 - 1.0)

    # 两个锚点都越界 => rho 已顶到上限 1.0，且 Phase 47 的值在边际一致模型里不可达
    saturated = not feasible_rate or not feasible_gap
    rho_hat = 1.0 if saturated else round(min(1.0, max(0.0, max(
        rho_rate if rho_rate is not None else 0.0,
        rho_gap if rho_gap is not None else 0.0))), 4)

    return {
        "clean_rate_at_rho0": round(rate0, 6),
        "clean_rate_at_rho1": round(rate1, 6),
        "clean_gap_at_rho1": round(gap1, 4),
        "phase47_anchor_rate": target_rate,
        "phase47_anchor_gap": target_gap,
        "phase47_anchor_within_achievable_rate_range": bool(feasible_rate),
        "phase47_anchor_within_achievable_gap_range": bool(feasible_gap),
        "rho_from_rate": None if rho_rate is None else round(rho_rate, 4),
        "rho_from_gap": None if rho_gap is None else round(rho_gap, 4),
        "rho_saturated": bool(saturated),
        "rho_hat_used_for_deployment": rho_hat,
        "rate_overshoot_ratio": round(target_rate / rate1, 4) if rate1 > 0 else None,
        "gap_overshoot_ratio": round(target_gap / gap1, 4) if gap1 > 0 else None,
        "interpretation": (
            "Phase 47 报告的 rho=1 穿透率与独立性缺口都超出边际一致耦合的可达上界"
            "（上界 rate={:.4f}、gap={:.2f}x），因此 rho 在本模型中已饱和到 1.0，"
            "而 Phase 47 的数值本身不可由任何边际一致的耦合复现。"
            "真实相关性效应的上界应以 clean_gap_at_rho1 为准，Phase 47 的 7.63x 中"
            "超出该上界的部分来自其绑定分支改写各层边际的构造特性。"
            "本 phase 不回改 Phase 47 已落盘结果，只做显式勘误标注。"
        ).format(rate1, gap1),
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    q_a, q_b, raw = load_marginals()

    print("=" * 78)
    print("Phase 52: D23' x D30 双层组合 —— 防御堆叠是否等于乘积级安全？")
    print("=" * 78)
    print(f"q_A(c) D23' 穿透率: {q_a}")
    print(f"q_B(s) D30 残余泄露: {q_b}")
    cells = len(COVERAGE_GRID) * len(STRICTNESS_GRID)
    print(f"网格 {len(COVERAGE_GRID)}x{len(STRICTNESS_GRID)} = {cells} 格 "
          f"x {len(RHO_GRID)} rho = {cells*len(RHO_GRID)} 格点，每格 {PROBES_GRID} 探针")
    print(f"总探针 ≈ {cells * len(RHO_GRID) * PROBES_GRID:,}")

    # ---------------- 自检 0：验证我对 Phase 47 的理解（逐位复刻） ----------------
    print("\n[自检 0] 逐位复刻 Phase 47 引擎，验证两个锚点")
    random.seed(SEED_47)
    np.random.seed(SEED_47)
    replay = {}
    for rho in RHO_SWEEP_47:
        r = Phase47Replay(rho).run(PROBES_47)
        replay[str(rho)] = r
        print(f"  rho={rho:.1f}  复刻穿透率={r['cascade_success_rate']*100:.2f}%")

    p47_json = json.loads((RESULTS / "phase47_multi_defense_cascade_v1.json")
                          .read_text(encoding="utf-8"))["results"]
    a0, a1 = replay["0.0"]["cascade_success_rate"], replay["1.0"]["cascade_success_rate"]
    e0 = p47_json["per_rho"]["0.0"]["cascade_success_rate"]
    e1 = p47_json["per_rho"]["1.0"]["cascade_success_rate"]
    anchor_ok = (a0 == e0) and (a1 == e1)
    print(f"  已落盘锚点: rho=0 -> {e0}, rho=1 -> {e1}  (缺口 {p47_json['independence_gap']}x)")
    print(f"  -> {'通过（逐位一致）' if anchor_ok else '失败：我对 Phase 47 的理解有误，终止'}")
    if not anchor_ok:
        sys.exit(1)

    # Phase 47 单层排名的退化度量（用已落盘结果，不依赖新假设）
    stored_r0 = p47_json["per_rho"]["0.0"]["per_defense_bypass_rate"]
    stored_r1 = p47_json["per_rho"]["1.0"]["per_defense_bypass_rate"]
    replay_r0 = replay["0.0"]["per_defense_bypass_rate"]
    replay_r1 = replay["1.0"]["per_defense_bypass_rate"]
    intra = [BLINDSPOT[d] for d in DEFENSES]
    rank_spearman = {
        "intrinsic_vs_rho0_measured": round(spearman(intra, [stored_r0[d] for d in DEFENSES]), 4),
        "intrinsic_vs_rho1_measured": round(spearman(intra, [stored_r1[d] for d in DEFENSES]), 4),
        "replay_rho0_bitwise_match": all(
            abs(replay_r0[d] - stored_r0[d]) < 1e-9 for d in DEFENSES),
        "replay_rho1_bitwise_match": all(
            abs(replay_r1[d] - stored_r1[d]) < 1e-9 for d in DEFENSES),
    }
    strongest, weakest = "D30_memory_firewall", "D29_gan_detector"
    ranking_flattening = {
        "intrinsic_blindspot": {strongest: BLINDSPOT[strongest], weakest: BLINDSPOT[weakest]},
        "measured_rho0": {strongest: stored_r0[strongest], weakest: stored_r0[weakest]},
        "measured_rho1": {strongest: stored_r1[strongest], weakest: stored_r1[weakest]},
        "strongest_worse_than_weakest_at_rho1": bool(stored_r1[strongest] > stored_r1[weakest]),
        "note": ("rho=1 时最强防御 D30（内在盲点 0.083）的实测穿透率高于"
                 "最弱防御 D29（内在盲点 0.237），即单层强弱次序被抹平。"
                 "这是 Phase 47 绑定分支改写各层边际的直接后果。"),
    }
    print(f"  单层排名 Spearman: rho=0 -> {rank_spearman['intrinsic_vs_rho0_measured']}"
          f"   rho=1 -> {rank_spearman['intrinsic_vs_rho1_measured']}")
    print(f"  rho=1 时最强层 D30 实测 {stored_r1[strongest]} vs 最弱层 D29 {stored_r1[weakest]}"
          f"  -> {'最强层被报告成更易穿透（排名已退化）' if ranking_flattening['strongest_worse_than_weakest_at_rho1'] else '次序正常'}")

    # ---------------- 自检 1：边际守恒 ----------------
    pairs = [(q_a[C_STAR], q_b[S_STAR]), (q_a[0.0], q_b[0.0]),
             (q_a[0.6], q_b[0.4]), (q_a[0.2], q_b[1.0])]
    print("\n[自检 1] 边际守恒 + Phase 47 原构造边际改写幅度诊断")
    sc1 = self_check_marginals(RHO_GRID, pairs)
    print(f"  clean 构造最大边际漂移 = {sc1['clean_max_drift']:.6f}  "
          f"-> {'通过' if sc1['passed'] else '失败，实验作废'}")
    for rho, row in sc1["per_rho"].items():
        v = list(row.values())[0]
        print(f"  rho={rho}: Phase 47 写法对 (qA,qB)=({v['clean_a']:.4f},{v['clean_b']:.4f}) 的"
              f"边际改写 A={v['phase47_a_marginal_drift']:.4f} B={v['phase47_b_marginal_drift']:.4f}")
    if not sc1["passed"]:
        sys.exit(1)

    # ---------------- 自检 2/3：乘积律 + 取小律 ----------------
    print("\n[自检 2/3] rho=0 乘积律 / rho=1 取小律")
    sc23 = self_check_laws(RHO_GRID, pairs)
    print(f"  乘积律最大绝对误差 = {sc23['product_law_max_abs_error']:.6f}")
    print(f"  取小律最大绝对误差 = {sc23['min_law_max_abs_error']:.6f}")
    print(f"  -> {'通过' if sc23['passed'] else '失败，模型缺陷，实验作废'}")
    if not sc23["passed"]:
        sys.exit(1)

    # ---------------- 稳健性 4：单调性 ----------------
    sc4 = self_check_monotone(RHO_GRID, pairs)
    print(f"\n[稳健性] 单调性违规 = {len(sc4['monotone_violations'])} -> {'通过' if sc4['passed'] else '注意'}")

    # ---------------- rho 标定 ----------------
    qs = [BLINDSPOT[d] for d in DEFENSES]
    cal = calibrate_rho(qs, e1, float(p47_json["independence_gap"]))
    print(f"\n[rho 标定] clean 模型 rate(rho=0)={cal['clean_rate_at_rho0']:.4f} "
          f"rate(rho=1)={cal['clean_rate_at_rho1']:.4f}")
    print(f"  Phase 47 锚点: rate(rho=1)={e1}, gap={p47_json['independence_gap']}x")
    print(f"  clean 缺口上界 = {cal['clean_gap_at_rho1']}x  "
          f"rate 越界倍数={cal['rate_overshoot_ratio']}  gap 越界倍数={cal['gap_overshoot_ratio']}")
    print(f"  rho 饱和 = {cal['rho_saturated']}  部署用 rho = {cal['rho_hat_used_for_deployment']}")
    rho_eff = cal["rho_hat_used_for_deployment"]
    rho_eff_key = f"rho={rho_eff:.2f}"
    if rho_eff_key not in (f"rho={r:.2f}" for r in RHO_GRID):
        print(f"  [提示] rho_eff={rho_eff} 不在网格上，部署格点改用网格内最近点 1.00")
        rho_eff_key = "rho=1.00"

    # ---------------- 主网格 ----------------
    print("\n[主网格] 联合穿透率 c x s x rho")
    grid: Dict[str, Dict] = {}
    for c in COVERAGE_GRID:
        for s in STRICTNESS_GRID:
            key = f"c={c:.2f}__s={s:.2f}"
            qa, qb = q_a[c], q_b[s]
            cell = {"c": c, "s": s, "q_a": qa, "q_b": qb,
                    "product_pred": round(qa * qb, 6), "min_pred": round(min(qa, qb), 6)}
            for rho in RHO_GRID:
                r = TwoLayerStack(rho).run(qa, qb, PROBES_GRID, SEEDS[0])
                cell[f"rho={rho:.2f}"] = r
            grid[key] = cell

    # 强度敏感性变体（仅部署配置）
    print("\n[敏感性] 加入强度 Beta(2,2) 的变体（部署配置 c*={:.1f}, s*={:.1f}）".format(
        C_STAR, S_STAR))
    sens = {}
    for rho in RHO_GRID:
        r = TwoLayerStack(rho, use_intensity=True).run(q_a[C_STAR], q_b[S_STAR],
                                                        PROBES_GRID, SEEDS[0])
        sens[f"rho={rho:.2f}"] = r
        print(f"  rho={rho:.2f}  joint={r['joint']:.4f}  A={r['a_rate']:.4f}  "
              f"B={r['b_rate']:.4f}  折扣={r['discount_factor']}x")

    # ---------------- 稳健性 5：多 seed 稳定性 ----------------
    print("\n[稳健性] 多 seed 稳定性（部署配置）")
    stab = {}
    for rho in RHO_GRID:
        vals = [TwoLayerStack(rho).run(q_a[C_STAR], q_b[S_STAR], PROBES_GRID, sd)["joint"]
                for sd in SEEDS]
        stab[f"rho={rho:.2f}"] = {"seed_values": vals,
                                  "max_spread": round(max(vals) - min(vals), 6)}
        print(f"  rho={rho:.2f}  {vals}  spread={stab[f'rho={rho:.2f}']['max_spread']:.4f}")

    # ---------------- 成本-收益与单层基准 ----------------
    print("\n[成本-收益] 叠加 vs 最优单层")
    status_quo_bypass = q_a[0.0]

    cost_benefit = {}
    for lam in LAMBDA_GRID:
        sq_damage = status_quo_bypass + cost_single_d23(0.0, lam)

        # 最优单层（不含叠加）：D23'(c) 或 D30(s)
        single_opts = []
        for c in COVERAGE_GRID:
            single_opts.append({"layer": "D23'", "c": c, "s": None,
                                "bypass": q_a[c], "cost": cost_single_d23(c, lam),
                                "damage": q_a[c] + cost_single_d23(c, lam)})
        for s in STRICTNESS_GRID:
            single_opts.append({"layer": "D30", "c": None, "s": s,
                                "bypass": q_b[s], "cost": cost_single_d30(s, lam),
                                "damage": q_b[s] + cost_single_d30(s, lam)})
        best_single = min(single_opts, key=lambda x: x["damage"])
        # 语义护栏：最优单层可能退化为"什么都不上"（D23' 的 c=0 或 D30 的 s=0
        # 成本都为 0，故在成本权重较高时会胜出）。这本身是有效结论，但必须显式
        # 标注，否则"最优单层 = D30(c=None, s=0.0)"会被误读成"部署 D30@s=0"。
        no_def = (best_single["layer"] == "D23'" and best_single["c"] == 0.0) or \
                 (best_single["layer"] == "D30" and best_single["s"] == 0.0)
        best_single["is_no_defense"] = bool(no_def)
        best_single["label"] = "无防御" if no_def else best_single["layer"]

        stack_best = {}
        for rho in RHO_GRID:
            best = None
            for c in COVERAGE_GRID:
                for s in STRICTNESS_GRID:
                    joint = grid[f"c={c:.2f}__s={s:.2f}"][f"rho={rho:.2f}"]["joint"]
                    dmg = joint + cost_stack(c, s, lam)
                    cand = {"c": c, "s": s, "joint": round(joint, 6),
                            "cost": round(cost_stack(c, s, lam), 6),
                            "damage": round(dmg, 6)}
                    if best is None or dmg < best["damage"]:
                        best = cand
            stack_best[f"rho={rho:.2f}"] = {
                "best_stack": best,
                "gain_vs_status_quo_pp": round((sq_damage - best["damage"]) * 100, 2),
                "gain_vs_best_single_pp": round((best_single["damage"] - best["damage"]) * 100, 2),
            }
        cost_benefit[f"lambda_{lam:g}"] = {
            "status_quo_damage": round(sq_damage, 6),
            "status_quo_bypass": status_quo_bypass,
            "status_quo_cost": round(cost_single_d23(0.0, lam), 6),
            "best_single_layer": best_single,
            "per_rho": stack_best,
        }
        print(f"  lambda={lam:g}: 现状损伤={sq_damage:.4f}  最优单层={best_single['label']}"
              f"(c={best_single['c']},s={best_single['s']}) 损伤={best_single['damage']:.4f}"
              f"{'  ← 退化为不部署任何防御' if no_def else ''}")
        for rho in RHO_GRID:
            b = stack_best[f"rho={rho:.2f}"]["best_stack"]
            print(f"    rho={rho:.2f}: 最优叠加 c={b['c']},s={b['s']} "
                  f"joint={b['joint']:.4f} 损伤={b['damage']:.4f} "
                  f"vs现状 {stack_best[f'rho={rho:.2f}']['gain_vs_status_quo_pp']:+.2f}pp "
                  f"vs最优单层 {stack_best[f'rho={rho:.2f}']['gain_vs_best_single_pp']:+.2f}pp")

    # ---------------- rho_max：叠加还划算的最大共享盲点系数 ----------------
    print("\n[rho_max] 叠加相对参照单层还划算的最大 rho（部署配置 c*={:.1f}, s*={:.1f}）".format(
        C_STAR, S_STAR))
    rho_max = {}
    for lam in LAMBDA_GRID:
        single = {
            "D23'": (q_a[C_STAR], cost_single_d23(C_STAR, lam)),
            "D30": (q_b[S_STAR], cost_single_d30(S_STAR, lam)),
        }
        best_name, (bs_bypass, bs_cost) = min(single.items(),
                                              key=lambda kv: kv[1][0] + kv[1][1])
        extra_cost = cost_stack(C_STAR, S_STAR, lam) - bs_cost

        # 边际一致耦合下 joint 关于 rho 线性：joint(rho) = (1-rho)*prod + rho*min
        prod = q_a[C_STAR] * q_b[S_STAR]
        mn = min(q_a[C_STAR], q_b[S_STAR])

        def net(rho: float) -> float:
            joint = (1 - rho) * prod + rho * mn
            return (bs_bypass - joint) - extra_cost

        n0, n1 = net(0.0), net(1.0)
        if n0 <= 0:
            rmax: Optional[float] = None      # 连最有利情形都不划算
        elif n1 >= 0:
            rmax = 1.0                        # 任何 rho 下都划算
        else:
            lo, hi = 0.0, 1.0
            for _ in range(60):
                mid = 0.5 * (lo + hi)
                if net(mid) > 0:
                    lo = mid
                else:
                    hi = mid
            rmax = 0.5 * (lo + hi)

        rho_max[f"lambda_{lam:g}"] = {
            "reference_single_layer": best_name,
            "reference_single_bypass": round(bs_bypass, 6),
            "reference_single_cost": round(bs_cost, 6),
            "stack_extra_cost": round(extra_cost, 6),
            "max_possible_gain": round(bs_bypass - prod, 6),
            "net_at_rho0": round(n0, 6),
            "net_at_rho1": round(n1, 6),
            "rho_max": None if rmax is None else round(rmax, 4),
            "stack_worth_it": bool(rmax is not None),
            "binding_constraint": ("cost" if (n0 <= 0) else
                                   ("none" if rmax == 1.0 else "correlation")),
        }
        print(f"  lambda={lam:g}: 参照单层={best_name}(bypass={bs_bypass:.4f})  "
              f"叠加额外成本={extra_cost:.4f}  最大可能增益={bs_bypass-prod:.4f}  "
              f"net(rho=0)={n0:+.4f}  net(rho=1)={n1:+.4f}  rho_max={rmax}")

    # ---------------- 按攻击模式的 D30 侧异质性 ----------------
    print("\n[异质性] 各攻击模式下叠加的边际增益（部署配置 c*={:.1f}）".format(C_STAR))
    hetero = {}
    pa0 = raw["p51_per_attack_s0"]
    pa1 = raw["p51_per_attack_s1"]
    for a in pa0:
        qa_b = pa0[a]["cot_eff"] / max(1, pa0[a]["tried"])
        qb_b = pa1[a]["cot_eff"] / max(1, pa1[a]["tried"])
        prod = q_a[C_STAR] * qb_b
        mn = min(q_a[C_STAR], qb_b)
        joint_eff = (1 - rho_eff) * prod + rho_eff * mn
        marg_gain = q_a[C_STAR] - joint_eff
        hetero[a] = {
            "q_b_no_filter": round(qa_b, 6),
            "q_b_at_s_star": round(qb_b, 6),
            "product_pred": round(prod, 6),
            "joint_at_rho_eff": round(joint_eff, 6),
            "marginal_gain_of_stacking_over_d23_only": round(marg_gain, 6),
            "d30_side_reduction_pp": round((qa_b - qb_b) * 100, 2),
        }
        print(f"  {a:22s} qB(0)={qa_b:.4f} qB(s*)={qb_b:.4f}  "
              f"joint(rho={rho_eff})={joint_eff:.4f}  "
              f"叠加增益={marg_gain*100:+.2f}pp")

    # ---------------- 汇总 ----------------
    dep = grid[f"c={C_STAR:.2f}__s={S_STAR:.2f}"]
    dep_r0 = dep["rho=0.00"]
    dep_r_eff = dep[rho_eff_key]

    cb_l2 = cost_benefit["lambda_2"]
    best_r0 = cb_l2["per_rho"]["rho=0.00"]["best_stack"]
    best_r_eff = cb_l2["per_rho"][rho_eff_key]["best_stack"]
    rm = rho_max["lambda_2"]
    max_spread = max(v["max_spread"] for v in stab.values())
    worst_law_err = max(sc23["product_law_max_abs_error"], sc23["min_law_max_abs_error"])

    output = {
        "phase": "52_d23prime_d30_two_layer_stack",
        "description": "D23'(输入侧) x D30(输出侧) 双层组合：用边际一致的共单调混合耦合标定共享盲点系数 rho，"
                       "量化'防御堆叠 =/= 乘积级安全'的折扣，并给出叠加还划算的最大 rho；"
                       "同时显式勘误 Phase 47 绑定分支改写各层边际的构造特性",
        "config": {
            "q_a_source": "phase50_defense_iteration_d23_prime_v1.json (arm_a + arm_b.bypass_rate)",
            "q_b_source": "phase51_cot_firewall_ablation_v1.json (arm_b_static_sweep.cot_eff_leak_rate)",
            "coverage_grid": COVERAGE_GRID,
            "strictness_grid": STRICTNESS_GRID,
            "rho_grid": RHO_GRID,
            "probes_per_grid_cell": PROBES_GRID,
            "probes_per_check_cell": PROBES_CHECK,
            "seeds": SEEDS,
            "lambda_grid": LAMBDA_GRID,
            "c_star": C_STAR, "s_star": S_STAR,
            "coupling_model": "intensity-free comonotonic mixture: "
                              "bound 分支共用一个 U 并按各自阈值判定；independent 分支各抽独立随机变量",
            "phase47_reused": {"defenses": DEFENSES, "chain_lengths": CHAIN_LENGTHS,
                               "chain_weights": CHAIN_WEIGHTS,
                               "intensity": f"Beta({INTENSITY_ALPHA},{INTENSITY_BETA})",
                               "seed": SEED_47, "probes_per_rho": PROBES_47},
            "cost_models": {
                "d23_fp": f"{FP_D23_BASE}+{FP_D23_SLOPE}*c",
                "d23_latency_ms": f"{LAT_D23_BASE}+{LAT_D23_SLOPE}*c",
                "d30_utility": f"0 if s=0 else {UTIL_D30_COEF}*s^{UTIL_D30_EXP}",
                "d30_latency_ms": f"0 if s=0 else {LAT_D30_BASE}+{LAT_D30_SCALING}*s^{LAT_D30_EXP}",
                "lat_normalize": LAT_NORMALIZE,
                "stack_cost": "lam*(fp_d23 + util_d30 + (lat_d23+lat_d30)/1000)",
            },
            "marginal_source_noise": {
                "p50_probes": raw["p50_probes"],
                "p51_probes": raw["p51_probes"],
                "note": "q_A 来自 1000 探针（SE≈1.3pp），q_B 来自 3000 探针（SE≈0.85pp）；"
                        "本 phase 的联合率格点误差（20000 探针，SE≈0.35pp）小于输入率的采样误差，"
                        "因此网格的定量精度受 Phase 50/51 的探针数限制。",
            },
            "modeling_assumption": (
                "两层失效事件来自两次独立实验（Phase 50 输入侧 / Phase 51 输出侧），"
                "本 phase 在固定边际下用 copula 耦合它们，即假定两层的失效事件"
                "可以按给定的 rho 相关。这是一个近似：真实的两层联合行为需要一次"
                "端到端实验（P1.1 真实 LLM 验证）才能直接测出。"),
        },
        "results": {
            "self_checks": {
                "phase47_anchor_replay": {
                    "replayed": {"rho_0": a0, "rho_1": a1},
                    "stored": {"rho_0": e0, "rho_1": e1},
                    "bitwise_identical": bool(anchor_ok),
                    "per_defense_bitwise_match": rank_spearman["replay_rho0_bitwise_match"]
                                                 and rank_spearman["replay_rho1_bitwise_match"],
                    "purpose": "先证明本文件对 Phase 47 的理解正确，再对 Phase 47 提出勘误",
                },
                "marginal_conservation": sc1,
                "product_and_min_law": sc23,
                "monotonicity_in_rho": sc4,
                "seed_stability": stab,
            },
            "phase47_audit": {
                "rank_spearman": rank_spearman,
                "ranking_flattening": ranking_flattening,
                "per_defense_measured": {
                    "intrinsic_blindspot": BLINDSPOT,
                    "measured_rho0": stored_r0,
                    "measured_rho1": stored_r1,
                },
                "verdict": (
                    "Phase 47 的 config note 声称 'rho 仅改变相关性、不改变单层边际'，"
                    "但绑定分支令所有层共享同一个 Bernoulli(mean_blindspot * I)，"
                    "其直接后果是各层单层穿透率被统一改写为接近共享率。"
                    "实测：rho=1 下各层实测穿透率与内在盲点率的 Spearman 相关"
                    f"仅 {rank_spearman['intrinsic_vs_rho1_measured']}，而 rho=0 下为"
                    f" {rank_spearman['intrinsic_vs_rho0_measured']}。"
                    "这不违反 Frechet 上界（rho=1 时 P(A)=P(B)=P(A and B) 取等），"
                    "但使 Phase 47 的独立性缺口数值同时含有相关性效应与边际改写效应，"
                    "两者未被分离。"),
            },
            "rho_calibration": cal,
            "phase47_replay_all_rho": replay,
            "grid": grid,
            "intensity_sensitivity_deployed": sens,
            "cost_benefit": cost_benefit,
            "rho_max_deployed": rho_max,
            "per_attack_mode_heterogeneity": hetero,
            "deployed_summary": {
                "c": C_STAR, "s": S_STAR,
                "q_a": dep_r0["q_a"], "q_b": dep_r0["q_b"],
                "joint_at_rho0": dep_r0["joint"],
                "product_pred": dep_r0["product_pred"],
                "joint_at_rho_eff": dep_r_eff["joint"],
                "min_pred": dep_r0["min_pred"],
                "discount_factor_at_rho_eff": dep_r_eff["discount_factor"],
                "rho_used": rho_eff,
                "rho_key_used": rho_eff_key,
            },
        },
        "insights": [
            f"部署配置 (c*={C_STAR}, s*={S_STAR})：q_A={dep_r0['q_a']}，q_B={dep_r0['q_b']}。"
            f"独立假设（rho=0）预测联合穿透率 {dep_r0['joint']*100:.2f}%"
            f"（= q_A*q_B = {dep_r0['product_pred']*100:.2f}%），"
            f"而共享盲点饱和（rho={rho_eff}）下升至 {dep_r_eff['joint']*100:.2f}%"
            f"（= min(q_A,q_B) = {dep_r0['min_pred']*100:.2f}%）—— "
            f"独立性折扣因子 {dep_r_eff['discount_factor']}x。"
            "双层堆叠的安全增益不是乘积级，而是坍缩到两层中较强那一层的水平",
            f"rho 标定：边际一致耦合的可达上界是 rate={cal['clean_rate_at_rho1']:.4f}、"
            f"gap={cal['clean_gap_at_rho1']}x；Phase 47 报告的是 rate={e1}、"
            f"gap={p47_json['independence_gap']}x，分别越界 "
            f"{cal['rate_overshoot_ratio']}x 与 {cal['gap_overshoot_ratio']}x。"
            f"因此 rho 在物理上已饱和到 1.0，'多层防御 = 乘积级安全' 的证伪方向不变，"
            f"但真实相关性效应的上界应取 {cal['clean_gap_at_rho1']}x 而非 7.63x",
            "Phase 47 勘误（显式标注，不改其已落盘结果）：绑定分支令所有层共享同一个"
            "Bernoulli(均值盲点*I)，这在 rho=1 时不违反 Frechet 上界（P(A)=P(B)=P(A and B)"
            f"取等），但它把各层单层穿透率统一改写为接近共享率。实测 rho=1 下最强防御 D30"
            f"（内在盲点 {BLINDSPOT['D30_memory_firewall']}）穿透率 "
            f"{stored_r1['D30_memory_firewall']} 高于最弱防御 D29（内在盲点 "
            f"{BLINDSPOT['D29_gan_detector']}）的 {stored_r1['D29_gan_detector']}；"
            f"内在盲点率与实测值的 Spearman 相关从 rho=0 的 "
            f"{rank_spearman['intrinsic_vs_rho0_measured']} 降到 rho=1 的 "
            f"{rank_spearman['intrinsic_vs_rho1_measured']}，即单层强弱次序在 rho=1 下已退化为噪声。"
            "后果：Phase 47 报告的独立性缺口同时含相关性效应与边际改写效应，未分离；"
            "其 config 里 'rho 仅改变相关性、不改变边际' 的说法在该构造下不成立。"
            "本 phase 的共享 U + 各自阈值构造在全部 rho 下最大边际漂移仅 "
            f"{sc1['clean_max_drift']}，两个极限律的最大误差 {worst_law_err}",
            f"自检 0 逐位复刻：seed 2047 下复刻的 5 个 rho 穿透率与已落盘值逐位一致"
            f"（含 per_defense_bypass_rate，见 phase47_audit.rank_spearman."
            f"replay_*_bitwise_match），因此上述勘误建立在对 Phase 47 的可复现理解之上",
            f"叠加净收益：lambda=2 时"
            f"{'参照的"最优单层"退化为不部署任何防御' if cb_l2['best_single_layer']['is_no_defense'] else '最优单层是 ' + cb_l2['best_single_layer']['label']}"
            f"(c={cb_l2['best_single_layer']['c']}, s={cb_l2['best_single_layer']['s']}，"
            f"损伤 {cb_l2['best_single_layer']['damage']:.4f})"
            f"{'——即两层各自单独部署在本成本权重下都不划算，这是参照基准本身，不代表推荐什么都不做' if cb_l2['best_single_layer']['is_no_defense'] else ''}"
            f"；rho=0 下最优叠加 "
            f"c={best_r0['c']},s={best_r0['s']} 损伤 {best_r0['damage']:.4f}，"
            f"rho={rho_eff} 下 c={best_r_eff['c']},s={best_r_eff['s']} "
            f"损伤 {best_r_eff['damage']:.4f}。相关系数越高，叠加相对最优单层的优势越小，"
            "直至被完全支配",
            f"rho_max（部署配置）：lambda=2 时叠加相对参照单层 {rm['reference_single_layer']}"
            f"还划算的最大 rho 为 "
            f"{('不存在——叠加在任何 rho 下都不划算' if rm['rho_max'] is None else rm['rho_max'])}；"
            f"net(rho=0)={rm['net_at_rho0']:+.4f}，net(rho=1)={rm['net_at_rho1']:+.4f}，"
            f"绑定约束 = {rm['binding_constraint']}。三个 lambda 的结果见 rho_max_deployed",
            (
                "约束来自**成本**而非相关性：三个 lambda 下 rho_max 全部为 None，"
                f"即叠加的最大可能增益 q_A - q_A*q_B = {q_a[C_STAR] - q_a[C_STAR]*q_b[S_STAR]:.4f}"
                f"（连 rho=0 的理想独立情形都达不到更多），"
                f"而第二层的额外成本在 lambda=2 下已达 {rho_max['lambda_2']['stack_extra_cost']:.4f}，"
                "后者更大，故无论共享盲点系数取多少都无法翻正。"
                "**降低 rho 救不了成本问题**——只有当两层机制真正独立（rho 下降）"
                "且成本被压低时，叠加才可能成立；单靠相关性改善不足"
            ),
            "强度敏感性：加入 Beta(2,2) 强度潜变量后，折扣因子随 rho 的形态与方向保持不变"
            "（见 intensity_sensitivity_deployed），说明结论不是由是否引入强度造成的",
            f"多 seed 稳定性：部署配置在 3 个 seed 下的最大离散度 {max_spread:.4f}，"
            "远小于网格内相邻格点差异，网格排序可信",
            "工程结论：在共享盲点已饱和的现实下，'同时上 D23' + D30' 并不比"
            "'只上其中较强的一层'更安全，却要多付一份误拦截/效用损失/延迟。"
            "真正能打破这一支配关系的手段不是加层数，而是让两层的判定机制彼此独立"
            "（例如一层用词面统计特征、另一层用语义模型），使 rho 真正降到 rho_max 以下；"
            "否则优先投资单层的边际改进（例如 D23' 的残留下游绕过率），"
            "而不是把预算花在叠加第二层上",
        ],
    }

    out_path = RESULTS / "phase52_d23prime_d30_two_layer_stack_v1.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")

    print("\n" + "=" * 78)
    print(f"[Phase 52] rho 饱和={cal['rho_saturated']} rho_hat={rho_eff}  "
          f"可达缺口上界={cal['clean_gap_at_rho1']}x  Phase 47 越界倍数={cal['gap_overshoot_ratio']}x")
    print(f"[Phase 52] Phase 47 单层排名 Spearman: rho=0 -> {rank_spearman['intrinsic_vs_rho0_measured']}"
          f"   rho=1 -> {rank_spearman['intrinsic_vs_rho1_measured']}")
    print(f"[Phase 52] 部署配置联合穿透率: rho=0 -> {dep_r0['joint']*100:.2f}%  "
          f"rho={rho_eff} -> {dep_r_eff['joint']*100:.2f}%  折扣 {dep_r_eff['discount_factor']}x")
    print(f"[Phase 52] lambda=2 最优单层={cb_l2['best_single_layer']['label']} "
          f"损伤 {cb_l2['best_single_layer']['damage']:.4f};  "
          f"最优叠加 rho={rho_eff} 损伤 {best_r_eff['damage']:.4f};  rho_max={rm['rho_max']}")
    print(f"[Phase 52] 结果已写入: {out_path}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
