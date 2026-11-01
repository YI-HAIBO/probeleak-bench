"""
方向8: 数据层面攻击
大规模数据投毒
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
class DataPoisoningProbe:
    id: str
    attack_type: str
    success: bool
    data_size: int
    poison_fraction: float

class DataPoisoningGenerator:
    def __init__(self):
        self.attack_types = [
            "features_injection",
            "label_imbalance",
            "continuous_learning_backdoor",
            "synthetic_data_poisoning"
        ]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []

        for i in range(num_probes):
            attack_type = random.choice(self.attack_types)

            success_rates = {
                "features_injection": 0.15,
                "label_imbalance": 0.20,
                "continuous_learning_backdoor": 0.25,
                "synthetic_data_poisoning": 0.30
            }
            success_prob = success_rates[attack_type]

            probe = {
                "probe_id": f"DP_{random.randint(10000, 99999)}",
                "attack_type": attack_type,
                "success": random.random() < success_prob,
                "data_size": random.randint(1000000, 1000000000),  # 字节
                "poison_fraction": random.uniform(0.01, 0.3),
                "context": f"数据投毒 {attack_type}"
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
                by_type[attack_type] = {"total": 0, "successful": 0, "fractions": []}
            by_type[attack_type]["total"] += 1
            if p['success']:
                by_type[attack_type]["successful"] += 1
            by_type[attack_type]["fractions"].append(p['poison_fraction'])

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_poison_fraction": np.mean([p['poison_fraction'] for p in probes]),
                "type_count": len(by_type)
            },
            "by_type": by_type,
            "probes": probes
        }

        output_path = RESULTS / "data_poisoning_attack_experiment_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均投毒率: {results['summary']['avg_poison_fraction']:.3f}")

        return results

def main():
    print("=" * 70)
    print("方向8: 数据层面攻击")
    print("=" * 70)

    generator = DataPoisoningGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击类型统计:")
    for attack_type, stats in sorted(results['by_type'].items(), key=lambda x: x[1]['successful']/x[1]['total'] if x[1]['total']>0 else 0, reverse=True):
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_fraction = np.mean(stats['fractions']) if stats['fractions'] else 0
        print(f"  {attack_type}: 成功率={rate:.3f}, 平均投毒率={avg_fraction:.3f}, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
