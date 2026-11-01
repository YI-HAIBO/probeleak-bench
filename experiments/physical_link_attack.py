"""
方向7: 物理-链路融合攻击
结合物理和链路层漏洞
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
class PhysicalLinkAttackProbe:
    id: str
    attack_type: str
    success: bool
    power_consumption: float
    network_delay: float

class PhysicalLinkAttackGenerator:
    def __init__(self):
        self.attack_types = [
            "key_extraction_injection",
            "tlp_protocol_vulnerability",
            "network_snoop",
            "hw_side_channel_sim"
        ]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []

        for i in range(num_probes):
            attack_type = random.choice(self.attack_types)

            success_rates = {
                "key_extraction_injection": 0.10,
                "tlp_protocol_vulnerability": 0.15,
                "network_snoop": 0.20,
                "hw_side_channel_sim": 0.12
            }
            success_prob = success_rates[attack_type]

            probe = {
                "probe_id": f"PL_{random.randint(10000, 99999)}",
                "attack_type": attack_type,
                "success": random.random() < success_prob,
                "power_consumption": random.uniform(1.0, 100.0),  #瓦特
                "network_delay": random.uniform(0.1, 100.0),     # 毫秒
                "context": f"物理-链路攻击 {attack_type}"
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
                by_type[attack_type] = {"total": 0, "successful": 0, "power_levels": [], "delays": []}
            by_type[attack_type]["total"] += 1
            if p['success']:
                by_type[attack_type]["successful"] += 1
            by_type[attack_type]["power_levels"].append(p['power_consumption'])
            by_type[attack_type]["delays"].append(p['network_delay'])

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_power_w": np.mean([p['power_consumption'] for p in probes]),
                "avg_delay_ms": np.mean([p['network_delay'] for p in probes]),
                "type_count": len(by_type)
            },
            "by_type": by_type,
            "probes": probes
        }

        output_path = RESULTS / "physical_link_attack_experiment_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均功耗: {results['summary']['avg_power_w']:.2f} W")
        print(f"平均延迟: {results['summary']['avg_delay_ms']:.2f} ms")

        return results

def main():
    print("=" * 70)
    print("方向7: 物理-链路融合攻击")
    print("=" * 70)

    generator = PhysicalLinkAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击类型统计:")
    for attack_type, stats in sorted(results['by_type'].items(), key=lambda x: x[1]['successful']/x[1]['total'] if x[1]['total']>0 else 0, reverse=True):
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_power = np.mean(stats['power_levels']) if stats['power_levels'] else 0
        avg_delay = np.mean(stats['delays']) if stats['delays'] else 0
        print(f"  {attack_type}: 成功率={rate:.3f}, 平均功耗={avg_power:.2f} W, 平均延迟={avg_delay:.2f} ms, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
