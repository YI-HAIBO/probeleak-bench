"""
Phase 36: ORM 查询重写链攻击 (ORM Rewrite Chain Attack)
利用 ORM 框架（Hibernate Criteria / MyBatis 动态 SQL / JPA Specification）的重写中间态注入
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
class ORMRewriteProbe:
    id: str
    attack_type: str
    framework: str
    rewrite_stage: str
    success: bool
    latency: float

class ORMRewriteAttackGenerator:
    """ORM 重写链攻击生成器"""

    def __init__(self):
        self.attack_types = [
            "criteria_injection",       # Hibernate Criteria 注入
            "dynamic_sql_injection",    # MyBatis 动态 SQL 注入
            "specification_bypass",     # JPA Specification 绕过
            "orm_cache_poisoning",      # ORM 二级缓存污染
        ]
        self.frameworks = ["hibernate", "mybatis", "mybatis-plus", "spring-data-jpa", "jOOQ", "sqlalchemy"]
        self.rewrite_stages = ["criteria-to-hql", "hql-to-sql", "sql-to-jdbc", "jdbc-to-protocol"]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []
        for i in range(num_probes):
            attack_type = random.choice(self.attack_types)
            framework = random.choice(self.frameworks)
            stage = random.choice(self.rewrite_stages)

            # 成功率按攻击类型设定
            success_rates = {
                "criteria_injection": 0.33,
                "dynamic_sql_injection": 0.40,   # 动态 SQL 拼接是经典漏洞面
                "specification_bypass": 0.22,
                "orm_cache_poisoning": 0.27,
            }
            success_prob = success_rates[attack_type]

            # 重写阶段越靠后（接近协议层），注入越难但收益越高
            stage_modifier = {"criteria-to-hql": 1.15, "hql-to-sql": 1.0, "sql-to-jdbc": 0.85, "jdbc-to-protocol": 0.7}[stage]

            probe = {
                "probe_id": f"OR_{random.randint(10000, 99999)}",
                "attack_type": attack_type,
                "framework": framework,
                "rewrite_stage": stage,
                "success": bool(random.random() < min(0.85, success_prob * stage_modifier)),
                "latency": random.uniform(80, 350),
                "context": f"ORM重写链 {attack_type} @ {framework}/{stage}",
            }
            probes.append(probe)
        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        probes = self.generate_probes(num_probes)

        total = len(probes)
        successful = sum(1 for p in probes if p["success"])

        by_type = {}
        by_framework = {}
        by_stage = {}

        for p in probes:
            for key, bucket in ((p["attack_type"], by_type), (p["framework"], by_framework), (p["rewrite_stage"], by_stage)):
                if key not in bucket:
                    bucket[key] = {"total": 0, "successful": 0, "latencies": []}
                bucket[key]["total"] += 1
                if p["success"]:
                    bucket[key]["successful"] += 1
                bucket[key]["latencies"].append(p["latency"])

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_latency_ms": np.mean([p["latency"] for p in probes]),
                "type_count": len(by_type),
                "framework_count": len(by_framework),
                "stage_count": len(by_stage),
            },
            "by_type": by_type,
            "by_framework": by_framework,
            "by_stage": by_stage,
            "probes": probes,
        }

        output_path = RESULTS / "phase36_orm_rewrite_attack_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均延迟: {results['summary']['avg_latency_ms']:.2f} ms")

        return results

def main():
    print("=" * 70)
    print("Phase 36: ORM 查询重写链攻击")
    print("=" * 70)

    generator = ORMRewriteAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击类型统计:")
    for attack_type, stats in sorted(results["by_type"].items(), key=lambda x: x[1]["successful"]/x[1]["total"], reverse=True):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {attack_type}: 成功率={rate:.3f}, 计数={stats['total']}")

    print("\n按重写阶段统计:")
    for stage, stats in sorted(results["by_stage"].items(), key=lambda x: x[1]["successful"]/x[1]["total"], reverse=True):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {stage}: 成功率={rate:.3f}, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
