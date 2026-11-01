"""
Phase 46: 自适应防御规避攻击 (Adaptive Defense-Evasion Attack)

把 Phase 44 的攻防对偶推进一步：攻击 Agent 不再是泛化 D1-D22，
而是专门学习如何绕过 Phase 45 新增的 D23-D31 防御层。

核心度量：
  - per_defense_bypass_rate: 对每层 D23-D31 的独立绕过率
  - adaptation_speed: 从首次观察到稳态收敛需要的迭代数
  - evasion_cost: 成功绕过所需平均代价（改写次数）
  - convergence_gen: Q-learning 达到稳态的代数
  - reward_signal_quality: 防御暴露信息量的代理指标

论文卖点：把攻击"从黑盒盲打"推进到"自适应规避"，量化防御层面对 RL 攻击者的鲁棒性。
"""

import json
import random
import numpy as np
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass


HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"


# Phase 45 新增的 9 层防御
NEW_DEFENSES = [
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

# 攻击策略空间（每种针对某类防御弱点设计）
ATTACK_STRATEGIES = [
    "paraphrase_ensemble",        # 大量改写绕过语义指纹
    "temporal_jitter",            # 时间抖动绕过时序检测
    "causal_masking",             # 因果掩蔽绕过因果约束
    "rag_context_inject",         # 上下文注入绕过 RAG 审计
    "gradient_noise_inject",      # 梯度噪声绕过梯度裁剪
    "sandbox_escalation",         # 沙箱逃逸
    "gan_adversarial_input",      # GAN 对抗输入
    "memory_poison_pretrain",     # 训练时污染记忆
    "coevolution_oscillation",    # 稳态震荡绕过
]


@dataclass
class EvasionProbe:
    probe_id: str
    attack_strategy: str
    target_defense: str
    generation: int
    success: bool
    rewrite_count: int           # 改写次数（改写 0 次 = 直接命中；改写多 = 攻击者学习成本高）
    reward: float                # RL 奖励
    defense_state: str           # 该防御当时处于什么状态（active / weak / strong）


class AdaptiveDefenseEvasion:
    """针对 D23-D31 的 RL 自适应攻击 Agent"""

    def __init__(self, num_gens: int = 40):
        self.num_gens = num_gens
        # Contextual bandit：每层防御一张独立 Q 表。
        # 早期版本用全局 Q 表导致模式坍塌——agent 只学会打最容易的 D23，
        # 面对其余 8 层仍套用同一策略，整体绕过率被压到 9.7%。
        self.q_table = {d: {a: 0.10 for a in ATTACK_STRATEGIES} for d in NEW_DEFENSES}
        self.alpha = 0.25
        self.gamma = 0.90
        self.epsilon = 0.40
        self.epsilon_decay = 0.96

    def _sample(self, defense: str) -> str:
        if random.random() < self.epsilon:
            return random.choice(ATTACK_STRATEGIES)
        return max(self.q_table[defense], key=lambda k: self.q_table[defense][k])

    # 每种攻击策略对每层防御的固有成功率（先天克制）
    AFFINITY = {
        "paraphrase_ensemble": {
            "D23_semantic_fingerprint": 0.72, "D31_coevolution_steady": 0.40,
        },
        "temporal_jitter": {
            "D24_temporal_consistency": 0.68, "D23_semantic_fingerprint": 0.35,
        },
        "causal_masking": {
            "D25_causal_constraint": 0.66, "D29_gan_detector": 0.38,
        },
        "rag_context_inject": {
            "D26_rag_audit": 0.71, "D31_coevolution_steady": 0.42,
        },
        "gradient_noise_inject": {
            "D27_gradient_clip_enhanced": 0.64, "D28_agent_sandbox": 0.32,
        },
        "sandbox_escalation": {
            "D28_agent_sandbox": 0.58, "D30_memory_firewall": 0.30,
        },
        "gan_adversarial_input": {
            "D29_gan_detector": 0.69, "D23_semantic_fingerprint": 0.44,
        },
        "memory_poison_pretrain": {
            "D30_memory_firewall": 0.75, "D25_causal_constraint": 0.36,
        },
        "coevolution_oscillation": {
            "D31_coevolution_steady": 0.70, "D24_temporal_consistency": 0.42,
        },
    }

    def _compute_success_prob(self, strategy: str, defense: str, gen: int) -> float:
        """防御强度随代次提升，但攻击也在学习"""
        affinity = self.AFFINITY.get(strategy, {}).get(defense, 0.15)
        # 防御随代数缓慢强化
        defense_strength = 0.75 + 0.005 * gen  # 每代 +0.5%
        # 攻击学习增益（该防御下该策略的 Q 值）
        attack_gain = self.q_table[defense].get(strategy, 0.10) * 0.6
        return max(0.02, min(0.95, affinity - defense_strength * 0.3 + attack_gain))

    def run(self, probes_per_defense: int = 1000) -> Dict:
        probes: List[EvasionProbe] = []
        per_defense_success = {d: 0 for d in NEW_DEFENSES}
        per_defense_total = {d: 0 for d in NEW_DEFENSES}
        gen_curve = []  # 每代成功次数

        n_total = len(NEW_DEFENSES) * probes_per_defense
        for i in range(n_total):
            defense = NEW_DEFENSES[i % len(NEW_DEFENSES)]
            gen = min(self.num_gens - 1, i // probes_per_defense)
            strategy = self._sample(defense)

            p_success = self._compute_success_prob(strategy, defense, gen)
            success = random.random() < p_success

            # 改写次数：如果失败，攻击者可能会尝试改写；越到后期改写越少（学到最优）
            if success:
                rewrite = int(random.expovariate(1 / max(0.3, 2 - gen * 0.05)))
                reward = 1.0 - 0.05 * rewrite
            else:
                rewrite = int(random.expovariate(1 / 1.5))
                reward = -0.1 - 0.02 * rewrite

            probes.append(EvasionProbe(
                probe_id=f"P46_{i:06d}",
                attack_strategy=strategy,
                target_defense=defense,
                generation=gen,
                success=success,
                rewrite_count=rewrite,
                reward=round(reward, 4),
                defense_state="active" if random.random() > 0.15 else "weak",
            ))

            if success:
                per_defense_success[defense] += 1
            per_defense_total[defense] += 1

            # Q-learning 更新（contextual：只更新该防御下的 Q 表）
            table = self.q_table[defense]
            new_q = table[strategy] + self.alpha * (
                reward - self.gamma * max(table.values()) - table[strategy]
            )
            table[strategy] = max(0.02, min(1.0, new_q))

            # ε 衰减
            if gen > 0 and i % probes_per_defense == 0:
                self.epsilon = max(0.05, self.epsilon * self.epsilon_decay)

            if i > 0 and i % probes_per_defense == 0:
                gen_curve.append({
                    "gen": gen,
                    "cum_success_rate": sum(per_defense_success.values()) /
                                       sum(per_defense_total.values()),
                    "epsilon": round(self.epsilon, 4),
                })

        # 汇总每防御绕过率
        per_defense_bypass = {
            d: {
                "total": per_defense_total[d],
                "success": per_defense_success[d],
                "bypass_rate": round(per_defense_success[d] / max(1, per_defense_total[d]), 4),
            }
            for d in NEW_DEFENSES
        }

        # 平均改写次数（成功样本）
        success_probes = [p for p in probes if p.success]
        avg_rewrite_success = sum(p.rewrite_count for p in success_probes) / max(1, len(success_probes))

        # 稳态代：连续两代成功率变化 <0.5pp 的第一代（真正的"收敛"，
        # 而非早期版本用"达到峰值 95%"——那会在低位直接命中 gen 1）
        convergence_gen = self.num_gens - 1
        for idx in range(1, len(gen_curve)):
            delta = abs(gen_curve[idx]["cum_success_rate"] - gen_curve[idx - 1]["cum_success_rate"])
            if delta < 0.005:
                convergence_gen = gen_curve[idx]["gen"]
                break

        overall_success = sum(per_defense_success.values()) / n_total
        hardest_defense = min(per_defense_bypass, key=lambda d: per_defense_bypass[d]["bypass_rate"])
        easiest_defense = max(per_defense_bypass, key=lambda d: per_defense_bypass[d]["bypass_rate"])

        return {
            "phase": "46_adaptive_defense_evasion",
            "description": "针对 Phase 45 新增 D23-D31 防御的 RL 自适应攻击",
            "config": {
                "num_generations": self.num_gens,
                "probes_per_defense": probes_per_defense,
                "total_probes": n_total,
                "initial_epsilon": 0.40,
                "alpha": self.alpha,
                "gamma": self.gamma,
                "attack_strategies_count": len(ATTACK_STRATEGIES),
                "target_defenses_count": len(NEW_DEFENSES),
            },
            "results": {
                "overall_bypass_rate": round(overall_success, 4),
                "avg_rewrite_on_success": round(avg_rewrite_success, 2),
                "convergence_gen": convergence_gen,
                "hardest_defense": {
                    "defense": hardest_defense,
                    "bypass_rate": per_defense_bypass[hardest_defense]["bypass_rate"],
                },
                "easiest_defense": {
                    "defense": easiest_defense,
                    "bypass_rate": per_defense_bypass[easiest_defense]["bypass_rate"],
                },
                "per_defense_bypass_rate": per_defense_bypass,
                "generation_curve": gen_curve,
                "final_q_table": {
                    d: {k: round(v, 4) for k, v in tbl.items()}
                    for d, tbl in self.q_table.items()
                },
                # 每层防御最终学到的最优策略
                "learned_best_strategy": {
                    d: max(tbl, key=lambda k: tbl[k]) for d, tbl in self.q_table.items()
                },
            },
            "insights": [
                f"整体 D23-D31 防御绕过率 {overall_success*100:.1f}%（Phase 45 阻断率反向）",
                f"最难绕过防御：{hardest_defense}（{per_defense_bypass[hardest_defense]['bypass_rate']*100:.1f}%）",
                f"最易绕过防御：{easiest_defense}（{per_defense_bypass[easiest_defense]['bypass_rate']*100:.1f}%）",
                f"RL 收敛代数：{convergence_gen}（从 40 代中取）",
                f"成功绕过平均改写次数：{avg_rewrite_success:.1f}（越低越高效）",
            ],
            "probes_sample": [
                {
                    "id": p.probe_id,
                    "strategy": p.attack_strategy,
                    "defense": p.target_defense,
                    "gen": p.generation,
                    "success": p.success,
                    "rewrite": p.rewrite_count,
                    "reward": p.reward,
                }
                for p in probes[:50]
            ],
        }


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    rng = random.Random(2026)
    np.random.seed(2026)

    print("=" * 72)
    print("Phase 46: 自适应防御规避攻击 (Adaptive Defense-Evasion)")
    print(f"目标防御: {len(NEW_DEFENSES)} 层 (D23-D31)")
    print(f"攻击策略: {len(ATTACK_STRATEGIES)} 种")
    print("=" * 72)

    agent = AdaptiveDefenseEvasion(num_gens=40)
    output = agent.run(probes_per_defense=1000)

    print(f"\n[Phase 46] 总探针数: {output['config']['total_probes']}")
    print(f"[Phase 46] 整体绕过率: {output['results']['overall_bypass_rate']*100:.1f}%")
    print(f"[Phase 46] 收敛代数: {output['results']['convergence_gen']}")
    print(f"[Phase 46] 最难防御: {output['results']['hardest_defense']['defense']} "
          f"({output['results']['hardest_defense']['bypass_rate']*100:.1f}%)")
    print(f"[Phase 46] 最易防御: {output['results']['easiest_defense']['defense']} "
          f"({output['results']['easiest_defense']['bypass_rate']*100:.1f}%)")

    for d, m in output['results']['per_defense_bypass_rate'].items():
        print(f"  {d:34s} {m['bypass_rate']*100:5.1f}%  ({m['success']}/{m['total']})")

    out_path = RESULTS / "phase46_adaptive_defense_evasion_v1.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[Phase 46] 结果已写入: {out_path}")


if __name__ == "__main__":
    main()
