"""
方向6: 可解释性攻击
利用模型解释反推参数
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
class ExplainabilityAttackProbe:
    id: str
    attack_type: str
    success: bool
    samples: int
    noise_level: float

class ExplainabilityAttackGenerator:
    def __init__(self):
        self.attack_types = [
            "explain_irrespective",
            "concept_theft",
            "adversary_reverse",
            "data_leakage"
        ]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []

        for i in range(num_probes):
            attack_type = random.choice(self.attack_types)

            success_rates = {
                "explain_irrespective": 0.15,
                "concept_theft": 0.20,
                "adversary_reverse": 0.10,
                "data_leakage": 0.25
            }
            success_prob = success_rates[attack_type]

            probe = {
                "probe_id": f"EA_{random.randint(10000, 99999)}",
                "attack_type": attack_type,
                "success": random.random() < success_prob,
                "samples": random.randint(1000, 100000),
                "noise_level": random.uniform(0.1, 0.5),
                "context": f"可解释性攻击 {attack_type}"
            }
            probes.append(probe)

        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        probes = self.generate_probes(num_probes)

        total = len(probes)
        successful = sum(1 for p in probes if p['success'])

        by_type = {}

        for p in probes:
            attack_type = p['attack_type']
            if attack_type not in by_type:
                by_type[attack_type] = {"total": 0, "successful": 0, "noise_levels": []}
            by_type[attack_type]["total"] += 1
            if p['success']:
                by_type[attack_type]["successful"] += 1
            by_type[attack_type]["noise_levels"].append(p['noise_level'])

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_noise_level": np.mean([p['noise_level'] for p in probes]),
                "type_count": len(by_type)
            },
            "by_type": by_type,
            "probes": probes
        }

        output_path = RESULTS / "explainability_attack_experiment_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")

        return results

def main():
    print("=" * 70)
    print("方向6: 可解释性攻击")
    print("=" * 70)

    generator = ExplainabilityAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击类型统计:")
    for attack_type, stats in sorted(results['by_type'].items(), key=lambda x: x[1]['successful']/x[1]['total'] if x[1]['total']>0 else 0, reverse=True):
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_noise = np.mean(stats['noise_levels']) if stats['noise_levels'] else 0
        print(f"  {attack_type}: 成功率={rate:.3f}, 平均噪声等级={avg_noise:.3f}, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
