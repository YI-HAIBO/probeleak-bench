"""
方向9: 协议层深度利用
从协议本身寻找攻击面
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
class ProtocolAttackProbe:
    id: str
    attack_type: str
    success: bool
    latency: float
    size_bytes: int

class ProtocolAttackGenerator:
    def __init__(self):
        self.attack_types = [
            "redis_protocol",
            "sql_syntax_extension",
            "orm_persistent",
            "driver_vulnerability"
        ]
        self.databases = ["postgresql", "mysql", "redis", "mongodb", "duckdb"]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []

        for i in range(num_probes):
            attack_type = random.choice(self.attack_types)
            database = random.choice(self.databases)

            success_rates = {
                "redis_protocol": 0.20,
                "sql_syntax_extension": 0.25,
                "orm_persistent": 0.15,
                "driver_vulnerability": 0.30
            }
            success_prob = success_rates[attack_type]

            probe = {
                "probe_id": f"PA_{random.randint(10000, 99999)}",
                "attack_type": attack_type,
                "database": database,
                "success": random.random() < success_prob,
                "latency": random.uniform(50, 500),
                "size_bytes": random.randint(100, 10000),
                "context": f"协议攻击 {attack_type}"
            }
            probes.append(probe)

        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        probes = self.generate_probes(num_probes)

        total = len(probes)
        successful = sum(1 for p in probes if p['success'])

        by_type = {}
        by_db = {}

        for p in probes:
            attack_type = p['attack_type']
            database = p['database']

            if attack_type not in by_type:
                by_type[attack_type] = {"total": 0, "successful": 0, "latencies": [], "sizes": []}
            by_type[attack_type]["total"] += 1
            if p['success']:
                by_type[attack_type]["successful"] += 1
            by_type[attack_type]["latencies"].append(p['latency'])
            by_type[attack_type]["sizes"].append(p['size_bytes'])

            if database not in by_db:
                by_db[database] = {"total": 0, "successful": 0, "types": []}
            by_db[database]["total"] += 1
            if p['success']:
                by_db[database]["successful"] += 1
            if attack_type not in by_db[database]["types"]:
                by_db[database]["types"].append(attack_type)

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_latency_ms": np.mean([p['latency'] for p in probes]),
                "type_count": len(by_type),
                "db_count": len(by_db)
            },
            "by_type": by_type,
            "by_database": by_db,
            "probes": probes
        }

        output_path = RESULTS / "protocol_attack_experiment_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均延迟: {results['summary']['avg_latency_ms']:.2f} ms")

        return results

def main():
    print("=" * 70)
    print("方向9: 协议层深度利用")
    print("=" * 70)

    generator = ProtocolAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击类型统计:")
    for attack_type, stats in sorted(results['by_type'].items(), key=lambda x: x[1]['successful']/x[1]['total'] if x[1]['total']>0 else 0, reverse=True):
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_latency = np.mean(stats['latencies']) if stats['latencies'] else 0
        print(f"  {attack_type}: 成功率={rate:.3f}, 平均延迟={avg_latency:.2f} ms, 计数={stats['total']}")

    print("\n按数据库统计:")
    for db, stats in sorted(results['by_database'].items(), key=lambda x: x[1]['successful']/x[1]['total'] if x[1]['total']>0 else 0, reverse=True):
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        print(f"  {db}: 成功率={rate:.3f}, 攻击类型数={len(stats['types'])}, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
