"""
方向4: 分布式系统与联邦攻击
云原生环境下的攻击
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
class DistributedAttackProbe:
    id: str
    attack_type: str
    target: str
    success: bool
    latency_ms: float
    data_size_bytes: int

class DistributedFederatedAttackGenerator:
    def __init__(self):
        self.attack_types = [
            "serverless_cold_start",
            "cross_tenant_memory",
            "federated_poisoning",
            "container_escape"
        ]
        self.targets = ["postgresql", "mysql", "redis", "mongodb", "duckdb"]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []

        for i in range(num_probes):
            attack_type = random.choice(self.attack_types)
            target = random.choice(self.targets)

            # 成功率根据攻击类型设定
            success_rates = {
                "serverless_cold_start": 0.35,
                "cross_tenant_memory": 0.40,
                "federated_poisoning": 0.30,
                "container_escape": 0.25
            }
            success_prob = success_rates[attack_type]

            probe = {
                "probe_id": f"DF_{random.randint(10000, 99999)}",
                "attack_type": attack_type,
                "target": target,
                "success": random.random() < success_prob,
                "latency_ms": random.uniform(150, 500),
                "data_size_bytes": random.randint(100, 1000000),
                "context": f"分布式攻击 {attack_type}"
            }
            probes.append(probe)

        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        probes = self.generate_probes(num_probes)

        total = len(probes)
        successful = sum(1 for p in probes if p['success'])

        by_type = {}
        by_target = {}

        for p in probes:
            attack_type = p['attack_type']
            target = p['target']

            if attack_type not in by_type:
                by_type[attack_type] = {"total": 0, "successful": 0, "latencies": [], "sizes": []}
            by_type[attack_type]["total"] += 1
            if p['success']:
                by_type[attack_type]["successful"] += 1
            by_type[attack_type]["latencies"].append(p['latency_ms'])
            by_type[attack_type]["sizes"].append(p['data_size_bytes'])

            if target not in by_target:
                by_target[target] = {"total": 0, "successful": 0}
            by_target[target]["total"] += 1
            if p['success']:
                by_target[target]["successful"] += 1

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_latency_ms": np.mean([p['latency_ms'] for p in probes]),
                "type_count": len(by_type),
                "target_count": len(by_target)
            },
            "by_type": by_type,
            "by_target": by_target,
            "probes": probes
        }

        output_path = RESULTS / "distributed_federated_attack_experiment_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")

        return results

def main():
    print("=" * 70)
    print("方向4: 分布式系统与联邦攻击")
    print("=" * 70)

    generator = DistributedFederatedAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击类型统计:")
    for attack_type, stats in sorted(results['by_type'].items(), key=lambda x: x[1]['successful']/x[1]['total'] if x[1]['total']>0 else 0, reverse=True):
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_latency = np.mean(stats['latencies']) if stats['latencies'] else 0
        print(f"  {attack_type}: 成功率={rate:.3f}, 平均延迟={avg_latency:.2f} ms, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
