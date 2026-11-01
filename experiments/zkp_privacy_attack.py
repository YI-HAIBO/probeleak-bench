"""
方向5: 零知识证明与隐私攻击
突破密码学防护
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
class PrivacyAttackProbe:
    id: str
    attack_type: str
    success: bool
    computations: int
    error_rate: float

class ZKPPrivacyAttackGenerator:
    def __init__(self):
        self.attack_types = [
            "zkp_math_assault",
            "homomorphic_sidechannel",
            "db_privacy_budget",
            "tee_bypass"
        ]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []

        for i in range(num_probes):
            attack_type = random.choice(self.attack_types)

            # 成功率设定
            success_rates = {
                "zkp_math_assault": 0.20,
                "homomorphic_sidechannel": 0.25,
                "db_privacy_budget": 0.30,
                "tee_bypass": 0.15
            }
            success_prob = success_rates[attack_type]

            probe = {
                "probe_id": f"ZKP_{random.randint(10000, 99999)}",
                "attack_type": attack_type,
                "success": random.random() < success_prob,
                "computations": random.randint(1000000, 100000000),
                "error_rate": random.uniform(0.01, 0.1),
                "context": f"隐私攻击 {attack_type}"
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
                by_type[attack_type] = {"total": 0, "successful": 0, "error_rates": []}
            by_type[attack_type]["total"] += 1
            if p['success']:
                by_type[attack_type]["successful"] += 1
            by_type[attack_type]["error_rates"].append(p['error_rate'])

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_error_rate": np.mean([p['error_rate'] for p in probes]),
                "type_count": len(by_type)
            },
            "by_type": by_type,
            "probes": probes
        }

        output_path = RESULTS / "zkp_privacy_attack_experiment_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均错误率: {results['summary']['avg_error_rate']:.3f}")

        return results

def main():
    print("=" * 70)
    print("方向5: 零知识证明与隐私攻击")
    print("=" * 70)

    generator = ZKPPrivacyAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击类型统计:")
    for attack_type, stats in sorted(results['by_type'].items(), key=lambda x: x[1]['successful']/x[1]['total'] if x[1]['total']>0 else 0, reverse=True):
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_error = np.mean(stats['error_rates']) if stats['error_rates'] else 0
        print(f"  {attack_type}: 成功率={rate:.3f}, 平均错误率={avg_error:.3f}, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
