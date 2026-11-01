"""
Phase 47: 多防御级联穿透攻击 (Multi-Defense Cascade Attack)

真实生产环境的防御不是单一层，而是多层级联（如：语义指纹 → RAG 审计 → Agent 沙箱 → 记忆防火墙）。
攻击必须顺序突破每一层才能取得目标。

========================================================================
核心科学问题
========================================================================
教科书式的安全假设是"各层防御独立失效"，于是级联保护强度 = 各层阻断率的乘积，
5 层 90% 阻断的防御组合应该几乎不可穿透（0.9^5 → 穿透率 1e-5）。

但真实 AI 防御体系（D23-D31 全部跑在同一 LLM 语义内核上）共享盲点：
同一个语义漏洞（如 unicode 归一化绕过、少样本越狱模板）可能**同时**绕过
语义指纹 + RAG 审计 + 记忆防火墙。防御失效是**相关**的，不是独立的。

本 phase 用相关性系数 ρ 量化这一效应，采用**二值共享盲点**模型
（线性模型会令 ρ 对均值无影响，见 2026-10-17 复盘）：

    每层防御的穿透由两部分决定：
      (a) 共享盲点命中：本次攻击是否击中 AI 防御共用的语义盲点（所有层共用一个布尔值）
      (b) 独立盲点命中：该层自身独有的防御缺口

    判定规则（以概率 ρ 选择该层由哪部分主导）：
      - 以概率 ρ：该层"绑定"到共享盲点 → defeated = shared_match（所有绑定层同生共死）
      - 以概率 1-ρ：该层独立失效 → defeated = (独立盲点命中)

    关键：共享盲点的边际穿透率 = 平均独立边际穿透率，
    因此 ρ 只改变"相关性"而不改变"单层边际"，排除了边际率混杂。

    ρ = 0.0  完全独立（教科书假设）→ 级联穿透率 ≈ 各层穿透率之积（乘积级安全）
    ρ = 1.0  完全相关（共享盲点）  → 级联穿透率 ≈ 单层穿透率（一旦找到 exploit 类，全层崩）

========================================================================
核心度量
========================================================================
  - cascade_success_rate:      全部 N 层防御都被穿透的概率
  - independence_gap:          ρ=1 与 ρ=0 的穿透率之比（防御相关性带来的保护损失）
  - depth_distribution:        攻击到达的深度分布（第几层被挡住）
  - weakest_link:              级联中最薄弱的一层（独立盲点最大）
  - cascade_time:              完整穿透的时间成本

论文卖点：证伪"多层防御 = 乘积级安全"这一普遍假设，量化 AI 防御共享盲点造成的安全折扣。
"""

import json
import random
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass


HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"


# Phase 45 新增的 9 层防御
DEFENSES = [
    "D23_semantic_fingerprint",
    "D24_temporal_consistency",
    "D25_causal_constraint",
    "D26_rag_audit",
    "D27_gradient_clip_enhanced",
    "D28_agent_sandbox",
    "D29_gan_detector",
    "D30_memory_firewall",
    "D31_coevolution_steady",
]

# 每层防御的独立阻断率（Phase 45 实测）
BASE_BLOCK_RATE = {
    "D23_semantic_fingerprint": 0.864,
    "D24_temporal_consistency": 0.870,
    "D25_causal_constraint": 0.873,
    "D26_rag_audit": 0.860,
    "D27_gradient_clip_enhanced": 0.907,
    "D28_agent_sandbox": 0.883,
    "D29_gan_detector": 0.763,
    "D30_memory_firewall": 0.917,
    "D31_coevolution_steady": 0.808,
}

# 每层防御被穿透的平均时间成本（毫秒）
TIME_COST_MS = {
    "D23_semantic_fingerprint": 120,
    "D24_temporal_consistency": 50,
    "D25_causal_constraint": 150,
    "D26_rag_audit": 180,
    "D27_gradient_clip_enhanced": 250,
    "D28_agent_sandbox": 300,
    "D29_gan_detector": 200,
    "D30_memory_firewall": 160,
    "D31_coevolution_steady": 220,
}

# 相关性系数扫描点
RHO_SWEEP = [0.0, 0.3, 0.6, 0.9, 1.0]

CHAIN_LENGTHS = [1, 2, 3, 4, 5]
CHAIN_WEIGHTS = [0.15, 0.25, 0.25, 0.20, 0.15]


class MultiDefenseCascade:
    """多防御级联攻击引擎（二值共享盲点模型）

    模型要点（区别于已废弃的线性模型）：
      - 每层防御除固有阻断率外，还存在"盲点"。盲点穿透概率 = 1 - 阻断率（BASE_BLOCK_RATE）。
      - 以概率 ρ 绑定到**全局共享盲点**：所有绑定层的穿透结果由同一个布尔值决定
        （同生共死），这正是"同一 LLM 语义内核 → 一个 exploit 类全层崩"的真实机理。
      - 以概率 1-ρ 走独立盲点：每层各自独立判定。
      - 共享盲点的边际穿透率被设为"所有层独立盲点边际的平均值"，
        从而 ρ 只改变相关性、不改变单层边际，排除边际率混杂。
    """

    def __init__(self, rho: float = 0.0):
        self.rho = rho
        # 每层独立盲点穿透率 = 1 - 阻断率（Phase 45 实测）
        self.blindspot = {d: round(1.0 - BASE_BLOCK_RATE[d], 4) for d in DEFENSES}
        # 共享盲点边际 = 平均独立盲点边际（保证 ρ 不混杂边际率）
        self.shared_base = round(
            sum(self.blindspot.values()) / len(self.blindspot), 4
        )

    def _run_chain(self, chain: List[str], intensity: float) -> Tuple[int, List[bool]]:
        """
        逐层模拟级联穿透。返回 (depth, 每层是否成功)。

        二值共享盲点判定：
          shared_match —— 本次攻击是否命中 AI 防御共用的语义盲点（每探针一个布尔值）。
          defeated_layer = shared_match（若绑定共享） 或 (random < blindspot_d * intensity)（若独立）。
        只要任一层未被穿透，级联中断（depth 停在该层）。
        """
        # 本次攻击对共享盲点的命中（与攻击强度 intensity 相乘）
        shared_p = min(0.95, self.shared_base * intensity)
        shared_match = random.random() < shared_p

        depth = 0
        outcomes: List[bool] = []
        for d in chain:
            if random.random() < self.rho:
                # 绑定到共享盲点：与所有绑定层同生共死
                defeated = shared_match
            else:
                # 独立盲点
                defeated = random.random() < (self.blindspot[d] * intensity)

            outcomes.append(defeated)
            if defeated:
                depth += 1
            else:
                break

        return depth, outcomes

    def run(self, total_probes: int = 2000) -> Dict:
        full_bypass_count = 0
        depth_hist: Dict[int, int] = {}
        total_time_ms = 0.0
        bottleneck_hits: Dict[str, int] = {}

        by_chain_length: Dict[int, Dict] = {
            L: {"tried": 0, "bypassed": 0} for L in CHAIN_LENGTHS
        }
        per_def_bypass = {d: 0 for d in DEFENSES}
        per_def_count = {d: 0 for d in DEFENSES}

        for _ in range(total_probes):
            chain_len = random.choices(CHAIN_LENGTHS, weights=CHAIN_WEIGHTS)[0]
            chain = random.sample(DEFENSES, k=chain_len)
            intensity = random.betavariate(2, 2)

            depth, outcomes = self._run_chain(chain, intensity)
            fully = depth == chain_len
            if fully:
                full_bypass_count += 1

            depth_hist[depth] = depth_hist.get(depth, 0) + 1

            t = sum(TIME_COST_MS[d] for d in chain[:depth])
            if depth < len(chain):
                t += TIME_COST_MS[chain[depth]] * 0.7
            total_time_ms += t

            if chain:
                reached = chain[:depth] if depth else chain[:1]
                bottleneck = max(reached, key=lambda d: TIME_COST_MS[d])
                bottleneck_hits[bottleneck] = bottleneck_hits.get(bottleneck, 0) + 1

            for j, d in enumerate(chain):
                if j >= len(outcomes):
                    break
                per_def_count[d] += 1
                if outcomes[j]:
                    per_def_bypass[d] += 1

            by_chain_length[chain_len]["tried"] += 1
            if fully:
                by_chain_length[chain_len]["bypassed"] += 1

        for L in CHAIN_LENGTHS:
            by_chain_length[L]["rate"] = round(
                by_chain_length[L]["bypassed"] / max(1, by_chain_length[L]["tried"]), 4
            )

        per_def_rate = {
            d: round(per_def_bypass[d] / max(1, per_def_count[d]), 4) for d in DEFENSES
        }

        return {
            "rho": self.rho,
            "total_probes": total_probes,
            "cascade_success_rate": round(full_bypass_count / total_probes, 4),
            "avg_cascade_time_ms": round(total_time_ms / total_probes, 1),
            "depth_distribution": depth_hist,
            "by_chain_length": {str(L): by_chain_length[L] for L in CHAIN_LENGTHS},
            "per_defense_bypass_rate": per_def_rate,
            "bottleneck_top5": sorted(bottleneck_hits.items(), key=lambda x: -x[1])[:5],
        }


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)

    print("=" * 76)
    print("Phase 47: 多防御级联穿透攻击 (Multi-Defense Cascade)")
    print("科学问题: 防御失效是否独立？级联保护是否被高估？")
    print("=" * 76)
    print(f"防御池: {len(DEFENSES)} 层 (D23-D31) · 级联长度 1-5")
    print(f"相关性系数扫描: {RHO_SWEEP}")
    print()

    random.seed(2047)
    np.random.seed(2047)

    per_rho = {}
    for rho in RHO_SWEEP:
        engine = MultiDefenseCascade(rho=rho)
        r = engine.run(total_probes=2000)
        per_rho[str(rho)] = r
        print(f"  ρ={rho:.1f}  级联穿透率={r['cascade_success_rate']*100:6.2f}%  "
              f"平均时间={r['avg_cascade_time_ms']:.0f}ms")

    # 独立性缺口：ρ=1 相对 ρ=0 的穿透率放大倍数
    base = per_rho["0.0"]["cascade_success_rate"]
    full = per_rho["1.0"]["cascade_success_rate"]
    independence_gap = full / max(1e-6, base)

    # 各 ρ 下按级联长度的穿透率
    print("\n按级联长度分组穿透率:")
    print(f"  {'ρ':>5s} " + " ".join(f"  L={L}" for L in CHAIN_LENGTHS))
    for rho in RHO_SWEEP:
        row = per_rho[str(rho)]["by_chain_length"]
        cells = " ".join(f"{row[str(L)]['rate']*100:5.1f}%" for L in CHAIN_LENGTHS)
        print(f"  {rho:5.1f} {cells}")

    # 最薄弱/最强环节：用与 ρ 无关的内在盲点率（blindspot 字典）判定
    engine0 = MultiDefenseCascade(rho=0.0)
    weakest = max(engine0.blindspot, key=lambda d: engine0.blindspot[d])
    strongest = min(engine0.blindspot, key=lambda d: engine0.blindspot[d])

    output = {
        "phase": "47_multi_defense_cascade",
        "description": "多防御级联穿透攻击 —— 证伪'多层防御=乘积级安全'假设，量化 AI 防御共享盲点造成的安全折扣",
        "config": {
            "defense_pool": DEFENSES,
            "chain_lengths": CHAIN_LENGTHS,
            "chain_weights": CHAIN_WEIGHTS,
            "rho_sweep": RHO_SWEEP,
            "probes_per_rho": 2000,
            "total_probes": len(RHO_SWEEP) * 2000,
            "model": "binary_shared_blindspot",
            "attack_intensity_dist": "Beta(2,2)",
            "shared_blindspot_base": engine0.shared_base,
            "per_defense_blindspot": engine0.blindspot,
            "note": "ρ 仅改变相关性，不改变单层边际（共享盲点边际=平均独立盲点边际）",
        },
        "results": {
            "per_rho": per_rho,
            "independence_gap": round(independence_gap, 2),
            "independent_rate_rho0": base,
            "correlated_rate_rho1": full,
            "weakest_link": {
                "defense": weakest,
                "blindspot_rate": engine0.blindspot[weakest],
            },
            "strongest_link": {
                "defense": strongest,
                "blindspot_rate": engine0.blindspot[strongest],
            },
        },
        "insights": [
            f"独立性缺口 = {independence_gap:.1f}x：防御完全相关（共享盲点）时的级联穿透率是独立假设下的 {independence_gap:.0f} 倍",
            f"ρ=0（教科书独立假设）5 层级联穿透率仅 {per_rho['0.0']['by_chain_length']['5']['rate']*100:.3f}%",
            f"ρ=1（共享盲点）5 层级联穿透率升至 {per_rho['1.0']['by_chain_length']['5']['rate']*100:.3f}%",
            f"级联中最薄弱环节：{weakest}（独立盲点率 {engine0.blindspot[weakest]*100:.1f}%）",
            f"级联中最强环节：{strongest}（独立盲点率 {engine0.blindspot[strongest]*100:.1f}%）",
            "结论：'堆层数=乘积级安全'是错误假设；当 AI 防御共享同一语义内核盲点时，"
            "多层防御的增益会大幅蒸发，攻击者只需找到一个 exploit 类即可全层穿透",
        ],
    }

    print()
    print(f"[Phase 47] 独立性缺口: {independence_gap:.1f}x "
          f"(ρ=0: {base*100:.2f}% → ρ=1: {full*100:.2f}%)")
    print(f"[Phase 47] 最薄弱环节: {weakest} "
          f"({engine0.blindspot[weakest]*100:.1f}%)")
    print(f"[Phase 47] 最强环节:   {strongest} "
          f"({engine0.blindspot[strongest]*100:.1f}%)")

    out_path = RESULTS / "phase47_multi_defense_cascade_v1.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[Phase 47] 结果已写入: {out_path}")


if __name__ == "__main__":
    main()
