"""
Phase 37: 影子数据库攻击 (Shadow Database Attack)
构建目标库的数字孪生 → 在孪生上离线优化攻击策略 → 迁移到真实目标
核心优势：将攻击查询成本从 N 次降到 1 次迁移
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
class ShadowDBProbe:
    id: str
    phase: str          # twin_construction / offline_optimization / strategy_migration / differential
    success: bool
    twin_fidelity: float   # 孪生保真度
    queries_saved: int     # 节省的查询次数
    latency: float

class ShadowDBAttackGenerator:
    """影子数据库攻击生成器"""

    def __init__(self):
        self.phases = [
            "twin_construction",       # 数字孪生构建
            "offline_optimization",    # 离线攻击优化
            "strategy_migration",      # 策略迁移
            "schema_differential",     # schema 差异探测
        ]
        self.target_engines = ["postgresql", "mysql", "redis", "mongodb", "duckdb", "clickhouse", "starrocks"]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []
        for i in range(num_probes):
            phase = random.choice(self.phases)
            engine = random.choice(self.target_engines)

            # 孪生保真度：构建阶段决定后续阶段成功率
            twin_fidelity = random.uniform(0.60, 0.98)

            # 各阶段成功率
            base_rates = {
                "twin_construction": 0.45,      # 构建孪生本身中等难度
                "offline_optimization": 0.55,   # 离线优化最自由（无检测风险）
                "strategy_migration": 0.38,     # 迁移是瓶颈（schema 差异导致）
                "schema_differential": 0.48,    # 差异探测
            }
            # 成功率受孪生保真度调制
            success_prob = base_rates[phase] * (0.5 + 0.5 * twin_fidelity)

            # 节省查询次数：离线阶段可节省最多
            queries_saved = {
                "twin_construction": random.randint(50, 200),
                "offline_optimization": random.randint(500, 5000),
                "strategy_migration": random.randint(100, 1000),
                "schema_differential": random.randint(20, 100),
            }[phase]

            probe = {
                "probe_id": f"SD_{random.randint(10000, 99999)}",
                "phase": phase,
                "target_engine": engine,
                "success": bool(random.random() < min(0.85, success_prob)),
                "twin_fidelity": twin_fidelity,
                "queries_saved": queries_saved,
                "latency": random.uniform(100, 400),
                "context": f"影子数据库 {phase} on {engine} (保真度={twin_fidelity:.2f})",
            }
            probes.append(probe)
        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        probes = self.generate_probes(num_probes)

        total = len(probes)
        successful = sum(1 for p in probes if p["success"])

        by_phase = {}
        by_engine = {}

        for p in probes:
            for key, bucket in ((p["phase"], by_phase), (p["target_engine"], by_engine)):
                if key not in bucket:
                    bucket[key] = {"total": 0, "successful": 0, "fidelity": [], "saved": []}
                bucket[key]["total"] += 1
                if p["success"]:
                    bucket[key]["successful"] += 1
                bucket[key]["fidelity"].append(p["twin_fidelity"])
                bucket[key]["saved"].append(p["queries_saved"])

        total_saved = sum(p["queries_saved"] for p in probes)

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_twin_fidelity": np.mean([p["twin_fidelity"] for p in probes]),
                "total_queries_saved": total_saved,
                "avg_queries_saved": total_saved / total,
                "phase_count": len(by_phase),
                "engine_count": len(by_engine),
            },
            "by_phase": by_phase,
            "by_engine": by_engine,
            "probes": probes,
        }

        output_path = RESULTS / "phase37_shadow_database_attack_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均孪生保真度: {results['summary']['avg_twin_fidelity']:.3f}")
        print(f"累计节省查询次数: {total_saved:,} (平均 {total_saved/total:.0f} 次/探针)")

        return results

def main():
    print("=" * 70)
    print("Phase 37: 影子数据库攻击")
    print("=" * 70)

    generator = ShadowDBAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击阶段统计:")
    for phase, stats in sorted(results["by_phase"].items(), key=lambda x: x[1]["successful"]/x[1]["total"], reverse=True):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        avg_fid = np.mean(stats["fidelity"]) if stats["fidelity"] else 0
        avg_saved = np.mean(stats["saved"]) if stats["saved"] else 0
        print(f"  {phase}: 成功率={rate:.3f}, 平均保真度={avg_fid:.3f}, 平均节省查询={avg_saved:.0f}, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
