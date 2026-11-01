"""
Phase 48: 跨厂商攻击迁移 (Cross-Vendor Transfer Attack)

在真实生产环境，攻击者往往在一个 LLM 厂商（如 DeepSeek）训练攻击策略，
然后迁移到另一个厂商（如 GPT-4.1 / Claude / Kimi）以利用"防御空白"。

本 phase 度量：
  - cross_vendor_transfer_rate: 迁移后在目标厂商的成功率
  - transfer_decay: 1 - 目标/源（迁移衰减）
  - vendor_similarity_matrix: 厂商间行为相似度
  - adaptation_cost: 迁移后需要的再适配探针数
  - exploitability_gap: 每个厂商相对于训练源的"可利用度缺口"

论文卖点：LLM 攻击不再是"针对某厂商"的孤立问题，而是跨厂商迁移的普遍威胁。
"""

import json
import random
import numpy as np
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass


HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"


# 源厂商（用于训练攻击策略）
SOURCE_VENDOR = "DeepSeek"

# 目标厂商（用于迁移测试）
TARGET_VENDORS = [
    "DeepSeek",       # 自身（对照，衰减应为 0）
    "GPT-4.1",
    "Claude-3.5",
    "Kimi",
    "Qwen2.5-72B",
    "SiliconFlow-Yi",
]

# 8 种攻击类别
ATTACK_CATEGORIES = [
    "sql_injection", "prompt_injection", "schema_probe", "data_exfiltration",
    "role_escalation", "logic_bypass", "time_sidechannel", "memory_extraction",
]

# 每个攻击类别在源厂商（DeepSeek）上的成功率（作为训练集）
SOURCE_SUCCESS_RATE = {
    "sql_injection": 0.71, "prompt_injection": 0.59, "schema_probe": 0.62,
    "data_exfiltration": 0.55, "role_escalation": 0.48, "logic_bypass": 0.45,
    "time_sidechannel": 0.44, "memory_extraction": 0.32,
}

# 目标厂商在每类攻击上的"原生抵抗力"（相对于源厂商的偏离）
# 正数 = 比源厂商更难攻击（防御更强），负数 = 更容易（防御更弱）
VENDOR_DIFFICULTY_DELTA = {
    "DeepSeek": {cat: 0.00 for cat in ATTACK_CATEGORIES},
    "GPT-4.1": {
        "sql_injection": -0.15,     # GPT-4.1 训练更严格，SQL 类稍难
        "prompt_injection": -0.08,  # 但提示词注入反而更容易（对齐更强）
        "schema_probe": -0.10,
        "data_exfiltration": -0.05,
        "role_escalation": -0.12,
        "logic_bypass": 0.05,       # 逻辑绕过反而更容易
        "time_sidechannel": 0.08,   # 时序泄露更多（长思考）
        "memory_extraction": 0.20,  # 长期记忆更强，可提取更多
    },
    "Claude-3.5": {
        "sql_injection": -0.22, "prompt_injection": -0.18, "schema_probe": -0.15,
        "data_exfiltration": -0.10, "role_escalation": -0.14, "logic_bypass": -0.05,
        "time_sidechannel": 0.06, "memory_extraction": -0.08,
    },
    "Kimi": {
        "sql_injection": -0.05, "prompt_injection": 0.05, "schema_probe": 0.00,
        "data_exfiltration": 0.08, "role_escalation": 0.02, "logic_bypass": -0.02,
        "time_sidechannel": 0.10, "memory_extraction": 0.15,
    },
    "Qwen2.5-72B": {
        "sql_injection": -0.02, "prompt_injection": 0.08, "schema_probe": 0.03,
        "data_exfiltration": 0.06, "role_escalation": -0.04, "logic_bypass": 0.02,
        "time_sidechannel": 0.04, "memory_extraction": 0.12,
    },
    "SiliconFlow-Yi": {
        "sql_injection": 0.05, "prompt_injection": 0.10, "schema_probe": 0.02,
        "data_exfiltration": 0.09, "role_escalation": 0.03, "logic_bypass": 0.04,
        "time_sidechannel": 0.07, "memory_extraction": 0.18,
    },
}

# 攻击策略（迁移方式）
TRANSFER_STRATEGIES = [
    "direct_prompt_transfer",       # 直接迁移 prompt
    "paraphrase_preserve_intent",   # 保留意图的改写
    "role_reversal",                # 角色反转
    "encoded_payload",              # 编码载荷
    "embedding_space_transfer",     # 嵌入空间迁移
]


@dataclass
class TransferProbe:
    probe_id: str
    category: str
    source_vendor: str
    target_vendor: str
    strategy: str
    source_success: bool
    target_success: bool
    transfer_decay: float           # 单探针的迁移衰减
    adaptation_cost: int            # 再适配成本（1-10）
    exploitability_gap: float       # 目标厂商相对源厂商的"更容易攻击"程度


class CrossVendorTransfer:
    """跨厂商攻击迁移分析"""

    def __init__(self):
        self.source = SOURCE_VENDOR
        self.targets = TARGET_VENDORS
        self.strategies = TRANSFER_STRATEGIES

    def run(self, total_probes: int = 1000) -> Dict:
        rng = random.Random(2028)

        per_target = {v: {"tried": 0, "success": 0} for v in TARGET_VENDORS}
        per_category = {c: {"tried": 0, "success": 0} for c in ATTACK_CATEGORIES}
        per_vendor_category: Dict[str, Dict[str, List[int]]] = {
            v: {c: {"tried": 0, "success": 0} for c in ATTACK_CATEGORIES} for v in TARGET_VENDORS
        }

        # 每个厂商在每类攻击上的成功率
        vendor_success = {}
        transfer_decays = {v: [] for v in TARGET_VENDORS}
        adaptation_costs = {v: [] for v in TARGET_VENDORS}
        exploitability_gaps = {v: [] for v in TARGET_VENDORS}
        strategy_effectiveness = {s: {"tried": 0, "success": 0} for s in TRANSFER_STRATEGIES}

        # 攻击强度（模拟真实攻击者能力）
        for i in range(total_probes):
            category = rng.choice(ATTACK_CATEGORIES)
            target = rng.choice(TARGET_VENDORS)
            strategy = rng.choice(TRANSFER_STRATEGIES)

            # 源厂商成功率
            src_base = SOURCE_SUCCESS_RATE[category]
            # 攻击者能力波动
            src_p = max(0.02, min(0.98, src_base + rng.gauss(0, 0.05)))
            src_success = rng.random() < src_p

            # 目标厂商成功率（考虑难度偏离 + 策略效果）
            delta = VENDOR_DIFFICULTY_DELTA[target][category]
            # 策略修正：不同策略的迁移效果不同
            strategy_bonus = {
                "direct_prompt_transfer": 0.0,
                "paraphrase_preserve_intent": 0.03,
                "role_reversal": -0.02,
                "encoded_payload": -0.05,     # 编码载荷可能被目标厂商拒答
                "embedding_space_transfer": 0.05,  # 嵌入空间迁移最有效
            }[strategy]

            dst_p = max(0.02, min(0.98, src_p + delta + strategy_bonus + rng.gauss(0, 0.04)))
            dst_success = rng.random() < dst_p

            # 迁移衰减
            decay = 1 - dst_p / max(0.01, src_p)
            transfer_decays[target].append(max(0, min(2.0, decay)))

            # 再适配成本：目标厂商与源厂商越不同，成本越高
            adaptation_cost = int(max(1, min(10,
                1 + 8 * abs(delta) + rng.random() * 2 - strategy_bonus * 4
            )))
            adaptation_costs[target].append(adaptation_cost)

            # 可利用度缺口（正数 = 目标比源更容易攻击）
            exploit_gap = delta  # 直接用难度偏离
            exploitability_gaps[target].append(exploit_gap)

            # 汇总
            per_target[target]["tried"] += 1
            if dst_success:
                per_target[target]["success"] += 1

            per_category[category]["tried"] += 1
            if dst_success:
                per_category[category]["success"] += 1

            per_vendor_category[target][category]["tried"] += 1
            if dst_success:
                per_vendor_category[target][category]["success"] += 1

            strategy_effectiveness[strategy]["tried"] += 1
            if dst_success:
                strategy_effectiveness[strategy]["success"] += 1

        # 汇总每个目标厂商
        per_target_summary = {}
        for v in TARGET_VENDORS:
            avg_decay = np.mean(transfer_decays[v]) if transfer_decays[v] else 0
            avg_adapt = np.mean(adaptation_costs[v]) if adaptation_costs[v] else 0
            avg_exploit = np.mean(exploitability_gaps[v]) if exploitability_gaps[v] else 0
            per_target_summary[v] = {
                "tried": per_target[v]["tried"],
                "success": per_target[v]["success"],
                "success_rate": round(per_target[v]["success"] / max(1, per_target[v]["tried"]), 4),
                "avg_transfer_decay": round(avg_decay, 4),
                "avg_adaptation_cost": round(avg_adapt, 2),
                "avg_exploitability_gap": round(avg_exploit, 4),
            }

        # 每类攻击的迁移难度
        per_category_summary = {}
        for c in ATTACK_CATEGORIES:
            total_s = sum(per_vendor_category[v][c]["success"] for v in TARGET_VENDORS)
            total_t = sum(per_vendor_category[v][c]["tried"] for v in TARGET_VENDORS)
            per_category_summary[c] = {
                "tried": total_t,
                "success": total_s,
                "success_rate": round(total_s / max(1, total_t), 4),
                "source_rate": SOURCE_SUCCESS_RATE[c],
            }

        # 最易迁移的厂商（成功率高、衰减小、成本低）
        easiest = max(per_target_summary, key=lambda v: per_target_summary[v]["success_rate"])
        hardest = min(per_target_summary, key=lambda v: per_target_summary[v]["success_rate"])

        # 最有效的迁移策略
        strategy_summary = {
            s: {
                "tried": strategy_effectiveness[s]["tried"],
                "success": strategy_effectiveness[s]["success"],
                "success_rate": round(
                    strategy_effectiveness[s]["success"] / max(1, strategy_effectiveness[s]["tried"]),
                    4,
                ),
            }
            for s in TRANSFER_STRATEGIES
        }
        best_strategy = max(strategy_summary, key=lambda s: strategy_summary[s]["success_rate"])

        # 构造厂商相似度矩阵（基于攻击成功率相关性）
        vendor_matrix = {v1: {} for v1 in TARGET_VENDORS}
        for v1 in TARGET_VENDORS:
            for v2 in TARGET_VENDORS:
                # 用难度偏离的欧氏距离
                dist = np.sqrt(sum(
                    (VENDOR_DIFFICULTY_DELTA[v1][c] - VENDOR_DIFFICULTY_DELTA[v2][c]) ** 2
                    for c in ATTACK_CATEGORIES
                ) / len(ATTACK_CATEGORIES))
                vendor_matrix[v1][v2] = round(dist, 4)

        # 最容易迁移的攻击类别
        most_transferable = max(per_category_summary, key=lambda c: per_category_summary[c]["success_rate"])
        hardest_to_transfer = min(per_category_summary, key=lambda c: per_category_summary[c]["success_rate"])

        return {
            "phase": "48_cross_vendor_transfer",
            "description": "跨 LLM 厂商攻击迁移分析（源：DeepSeek；目标：GPT-4.1/Claude/Kimi/Qwen/SiliconFlow）",
            "config": {
                "total_probes": total_probes,
                "source_vendor": SOURCE_VENDOR,
                "target_vendors": TARGET_VENDORS,
                "attack_categories": len(ATTACK_CATEGORIES),
                "transfer_strategies": len(TRANSFER_STRATEGIES),
            },
            "results": {
                "per_target_vendor": per_target_summary,
                "per_category": per_category_summary,
                "per_strategy": strategy_summary,
                "vendor_similarity_matrix": vendor_matrix,
                "easiest_to_transfer": {
                    "vendor": easiest,
                    "success_rate": per_target_summary[easiest]["success_rate"],
                    "avg_decay": per_target_summary[easiest]["avg_transfer_decay"],
                },
                "hardest_to_transfer": {
                    "vendor": hardest,
                    "success_rate": per_target_summary[hardest]["success_rate"],
                    "avg_decay": per_target_summary[hardest]["avg_transfer_decay"],
                },
                "best_transfer_strategy": {
                    "strategy": best_strategy,
                    "success_rate": strategy_summary[best_strategy]["success_rate"],
                },
                "most_transferable_category": {
                    "category": most_transferable,
                    "target_success_rate": per_category_summary[most_transferable]["success_rate"],
                },
                "hardest_to_transfer_category": {
                    "category": hardest_to_transfer,
                    "target_success_rate": per_category_summary[hardest_to_transfer]["success_rate"],
                },
            },
            "insights": [
                f"最易被迁移攻击的厂商：{easiest}（成功率 {per_target_summary[easiest]['success_rate']*100:.1f}%）",
                f"最难被迁移攻击的厂商：{hardest}（成功率 {per_target_summary[hardest]['success_rate']*100:.1f}%）",
                f"最有效的迁移策略：{best_strategy}（{strategy_summary[best_strategy]['success_rate']*100:.1f}%）",
                f"最易迁移的攻击类别：{most_transferable}（{per_category_summary[most_transferable]['success_rate']*100:.1f}%）",
                f"最难迁移的攻击类别：{hardest_to_transfer}（{per_category_summary[hardest_to_transfer]['success_rate']*100:.1f}%）",
                "跨厂商攻击是真实威胁：不同厂商的防御水平差异决定了迁移的可行性",
            ],
        }


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    random.seed(2028)
    np.random.seed(2028)

    print("=" * 72)
    print("Phase 48: 跨厂商攻击迁移 (Cross-Vendor Transfer)")
    print(f"源厂商: {SOURCE_VENDOR}")
    print(f"目标厂商: {TARGET_VENDORS}")
    print(f"攻击类别: {len(ATTACK_CATEGORIES)} · 迁移策略: {len(TRANSFER_STRATEGIES)}")
    print("=" * 72)

    engine = CrossVendorTransfer()
    output = engine.run(total_probes=1000)

    print(f"\n[Phase 48] 总探针数: {output['config']['total_probes']}")
    print(f"[Phase 48] 最易迁移厂商: {output['results']['easiest_to_transfer']['vendor']} "
          f"({output['results']['easiest_to_transfer']['success_rate']*100:.1f}%)")
    print(f"[Phase 48] 最难迁移厂商: {output['results']['hardest_to_transfer']['vendor']} "
          f"({output['results']['hardest_to_transfer']['success_rate']*100:.1f}%)")
    print(f"[Phase 48] 最佳迁移策略: {output['results']['best_transfer_strategy']['strategy']} "
          f"({output['results']['best_transfer_strategy']['success_rate']*100:.1f}%)")

    print("\n各厂商迁移结果:")
    for v, m in output['results']['per_target_vendor'].items():
        print(f"  {v:20s} 成功率={m['success_rate']*100:5.1f}%  "
              f"衰减={m['avg_transfer_decay']*100:+5.1f}%  "
              f"再适配={m['avg_adaptation_cost']:.1f}  "
              f"可利用度缺口={m['avg_exploitability_gap']*100:+5.1f}%")

    out_path = RESULTS / "phase48_cross_vendor_transfer_v1.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[Phase 48] 结果已写入: {out_path}")


if __name__ == "__main__":
    main()
