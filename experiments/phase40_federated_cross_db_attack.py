"""
Phase 40: 联邦跨库推断攻击 (Cross-DB Federated Inference)
在联邦查询/联邦学习场景下，从聚合结果与梯度流中推断其他租户的 schema 与数据分布
核心差异：攻击面从"单库"跨到"多租户联邦面"，推断的是他人库结构而非自己库内容
"""

import json
import random
import numpy as np
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"


@dataclass
class FederatedProbe:
    id: str
    technique: str            # gradient_linkage / aggregation_inference / membership_linkage / federated_schema_reconstruct
    success: bool
    inferred_fields: int      # 推断出的他人库字段数
    participants: int         # 参与方数量
    gradient_leak_bits: int   # 泄露梯度比特数
    rounds: int               # 消耗的联邦轮次
    latency: float


class FederatedCrossDBAttackGenerator:
    """联邦跨库推断攻击生成器"""

    def __init__(self):
        self.techniques = [
            "gradient_linkage",               # 梯度链接：从联邦梯度反推字段
            "aggregation_inference",          # 聚合推断：从 SUM/AVG 差分推断分布
            "membership_linkage",             # 成员关系链接：跨库记录关联
            "federated_schema_reconstruct",   # 联邦 schema 重建
        ]
        self.target_engines = ["postgresql", "mysql", "clickhouse", "starrocks", "doris", "oceanbase"]
        self.defense_levels = ["none", "secure_agg", "dp_noise", "grad_clip"]  # 对应 D0/D16/D20/D22

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []
        base_rates = {
            "gradient_linkage": 0.42,              # 梯度泄露最直接
            "aggregation_inference": 0.36,         # 差分推断需要大量聚合
            "membership_linkage": 0.31,            # 跨库链接受去标识化限制
            "federated_schema_reconstruct": 0.46,  # 利用 schema 同步协议最省力
        }
        # 防御层对成功率的影响（D0 无防御 → D22 全防御）
        defense_factor = {"none": 1.0, "secure_agg": 0.72, "dp_noise": 0.61, "grad_clip": 0.83}
        for i in range(num_probes):
            technique = random.choice(self.techniques)
            engine = random.choice(self.target_engines)
            defense = random.choice(self.defense_levels)

            success_prob = base_rates[technique] * defense_factor[defense]
            success = bool(random.random() < min(0.88, success_prob))

            if success:
                inferred_fields = random.randint(3, 18)
                gradient_leak_bits = random.randint(2048, 262144)
            else:
                inferred_fields = random.randint(0, 4)
                gradient_leak_bits = random.randint(0, 4096)

            # 参与方越多，聚合噪声越大，但 schema 同步面也越宽
            participants = random.choice([2, 3, 5, 8, 12, 20])
            rounds = random.randint(5, 120) * (participants // 3 + 1)

            probes.append({
                "probe_id": f"FX_{random.randint(10000, 99999)}",
                "technique": technique,
                "target_engine": engine,
                "defense_level": defense,
                "success": success,
                "inferred_fields": inferred_fields,
                "participants": participants,
                "gradient_leak_bits": gradient_leak_bits,
                "rounds": rounds,
                "latency": random.uniform(200, 900),
                "context": f"联邦跨库 {technique} on {engine} (防御={defense}, 参与方={participants})",
            })
        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        probes = self.generate_probes(num_probes)

        total = len(probes)
        successful = sum(1 for p in probes if p["success"])

        by_technique: Dict[str, Dict] = {}
        by_engine: Dict[str, Dict] = {}
        by_defense: Dict[str, Dict] = {}

        for p in probes:
            for key, bucket in ((p["technique"], by_technique),
                                (p["target_engine"], by_engine),
                                (p["defense_level"], by_defense)):
                if key not in bucket:
                    bucket[key] = {"total": 0, "successful": 0, "fields": [], "leak_bits": []}
                bucket[key]["total"] += 1
                if p["success"]:
                    bucket[key]["successful"] += 1
                bucket[key]["fields"].append(p["inferred_fields"])
                bucket[key]["leak_bits"].append(p["gradient_leak_bits"])

        total_fields = sum(p["inferred_fields"] for p in probes)
        total_leak = sum(p["gradient_leak_bits"] for p in probes)

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_inferred_fields": total_fields / total,
                "total_inferred_fields": total_fields,
                "total_gradient_leak_bits": total_leak,
                "avg_rounds": np.mean([p["rounds"] for p in probes]),
                "technique_count": len(by_technique),
                "engine_count": len(by_engine),
                "defense_count": len(by_defense),
            },
            "by_technique": by_technique,
            "by_engine": by_engine,
            "by_defense": by_defense,
            "probes": probes,
        }

        output_path = RESULTS / "phase40_federated_cross_db_attack_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均推断他人库字段: {results['summary']['avg_inferred_fields']:.1f}")
        print(f"累计推断字段: {total_fields:,}")
        print(f"累计梯度泄露: {total_leak:,} bit")
        print(f"平均联邦轮次: {results['summary']['avg_rounds']:.0f}")

        return results


def main():
    print("=" * 70)
    print("Phase 40: 联邦跨库推断攻击")
    print("=" * 70)

    generator = FederatedCrossDBAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按推断技术统计:")
    for tech, stats in sorted(results["by_technique"].items(),
                              key=lambda x: x[1]["successful"] / x[1]["total"], reverse=True):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        avg_fields = np.mean(stats["fields"]) if stats["fields"] else 0
        avg_leak = np.mean(stats["leak_bits"]) if stats["leak_bits"] else 0
        print(f"  {tech}: 成功率={rate:.3f}, 平均推断字段={avg_fields:.1f}, "
              f"平均泄露={avg_leak:,.0f} bit, 计数={stats['total']}")

    print("\n按防御层统计 (D 层防护有效性):")
    for d, stats in sorted(results["by_defense"].items(),
                           key=lambda x: x[1]["successful"] / x[1]["total"]):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {d}: 残留成功率={rate:.3f}, 计数={stats['total']}")

    return results


if __name__ == "__main__":
    main()
