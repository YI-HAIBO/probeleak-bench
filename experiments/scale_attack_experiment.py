"""
Scale Attack Experiment - 生成大量攻击探针并模拟执行
基于 attack_catalog.json 中的原语，生成组合探针并评估效果
"""

import json
import os
import random
from pathlib import Path
from typing import Dict, List, Any
import numpy as np
from dataclasses import dataclass, asdict

# 配置
HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
CATALOG_PATH = RESULTS / "attack_catalog.json"

@dataclass
class AttackRecord:
    probe_id: str
    vector: str
    action: str
    db_engine: str
    success: bool
    latency_ms: float
    llm_model: str
    context: str
    response: str

class AttackGenerator:
    """攻击探针生成器"""

    def __init__(self, catalog_path: Path):
        with open(catalog_path, 'r', encoding='utf-8') as f:
            self.catalog = json.load(f)

        self.action_types = self.catalog['action_types']
        self.vectors = self.catalog['vectors']
        self.patterns = self.catalog['attack_patterns']

    def generate_probe(self) -> AttackRecord:
        """生成单个探针"""
        # 随机选择攻击向量
        vector = random.choice(self.vectors)

        # 根据向量选择对应的操作类型
        if vector == "sql_injection":
            action = random.choice([
                "direct_select",
                "union_attack",
                "compare_sql_query_requirement",
                "stealth_select_query_prefix",
                "query_floating_point_adaptation"
            ])
        elif vector == "driver_escaping":
            action = random.choice([
                "parameterized",
                "driver_escaping",
                "string_concat",
                "backtick_quotes",
                "comment_injection"
            ])
        elif vector == "shard_routing":
            action = "shard_routing"
        elif vector == "replication_lag_stale_read":
            action = "replication_lag_stale_read"
        elif vector == "error_oracle":
            action = "error_oracle"
        else:
            action = "sql_injection"

        # 生成探针ID
        probe_id = f"probe_{random.randint(10000, 99999)}"

        # 模拟执行结果
        success = random.random() < 0.30  # 30% 成功率
        latency_ms = random.uniform(10.0, 500.0)

        # 选择一个数据库引擎
        db_engines = ["postgresql", "mysql", "redis", "mongodb", "duckdb"]
        db_engine = random.choice(db_engines)

        # 选择一个LLM模型（模拟）
        llm_models = ["gpt-4", "claude-3-opus", "unknown"]
        llm_model = random.choice(llm_models)

        # 生成上下文
        contexts = [
            f"数据库{db_engine}环境下的{vector}攻击",
            f"利用数据库{db_engine}的{action}漏洞",
            f"测试{db_engine}的{vector}验证"
        ]

        return AttackRecord(
            probe_id=probe_id,
            vector=vector,
            action=action,
            db_engine=db_engine,
            success=success,
            latency_ms=latency_ms,
            llm_model=llm_model,
            context=random.choice(contexts),
            response=f"probe_{probe_id}_response"
        )

def run_experiment(num_probes: int = 100) -> List[AttackRecord]:
    """运行攻击实验"""
    generator = AttackGenerator(CATALOG_PATH)
    records = []

    for i in range(num_probes):
        probe = generator.generate_probe()
        records.append(probe)

        if (i + 1) % 20 == 0:
            print(f"已生成 {i+1}/{num_probes} 个探针")

    return records

def summarize_results(records: List[AttackRecord]) -> Dict[str, Any]:
    """总结实验结果"""
    total = len(records)
    successful = sum(1 for r in records if r.success)

    # 按向量分组统计
    by_vector = {}
    for record in records:
        if record.vector not in by_vector:
            by_vector[record.vector] = {"total": 0, "successful": 0, "latencies": []}
        by_vector[record.vector]["total"] += 1
        if record.success:
            by_vector[record.vector]["successful"] += 1
        by_vector[record.vector]["latencies"].append(record.latency_ms)

    # 按数据库引擎分组统计
    by_engine = {}
    for record in records:
        if record.db_engine not in by_engine:
            by_engine[record.db_engine] = {"total": 0, "successful": 0, "latencies": []}
        by_engine[record.db_engine]["total"] += 1
        if record.success:
            by_engine[record.db_engine]["successful"] += 1
        by_engine[record.db_engine]["latencies"].append(record.latency_ms)

    return {
        "summary": {
            "total_probes": total,
            "successful_probes": successful,
            "success_rate": successful / total if total > 0 else 0,
            "avg_latency_ms": np.mean([r.latency_ms for r in records]),
            "vector_count": len(by_vector),
            "engine_count": len(by_engine)
        },
        "by_vector": by_vector,
        "by_engine": by_engine,
        "probes": [asdict(r) for r in records]
    }

def main():
    print("=" * 70)
    print("Scale Attack Experiment - 大规模攻击探针生成与评估")
    print("=" * 70)

    # 运行实验
    num_probes = 100  # 可以调整为更大
    print(f"\n开始生成 {num_probes} 个攻击探针...")
    records = run_experiment(num_probes)

    # 总结结果
    results = summarize_results(records)

    # 保存结果
    output_path = RESULTS / "scale_attack_experiment_v1.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n结果保存到：{output_path}")

    # 打印摘要
    print("\n" + "=" * 70)
    print("实验摘要")
    print("=" * 70)
    print(f"总会话数：{results['summary']['total_probes']}")
    print(f"成功会话数：{results['summary']['successful_probes']}")
    print(f"成功率：{results['summary']['success_rate']:.3f}")
    print(f"平均延迟：{results['summary']['avg_latency_ms']:.2f} ms")
    print(f"攻击向量数量：{results['summary']['vector_count']}")
    print(f"数据库引擎数量：{results['summary']['engine_count']}")

    # 按向量显示详细说明
    print("\n按攻击向量统计：")
    for vector, stats in results['by_vector'].items():
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_latency = np.mean(stats['latencies']) if stats['latencies'] else 0
        print(f"  {vector}: 成功率={rate:.3f}, 平均延迟={avg_latency:.2f} ms, 计数={stats['total']}")

    print("\n按数据库引擎统计：")
    for engine, stats in results['by_engine'].items():
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_latency = np.mean(stats['latencies']) if stats['latencies'] else 0
        print(f"  {engine}: 成功率={rate:.3f}, 平均延迟={avg_latency:.2f} ms, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
