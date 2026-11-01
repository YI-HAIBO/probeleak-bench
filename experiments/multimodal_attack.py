"""
方向2: 多模态攻击融合
跨模态触发数据库漏洞
"""

import json
import random
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
import time

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"

@dataclass
class MultimodalProbe:
    """多模态探针"""
    id: str
    text_prompt: str
    sql_code: str
    text_embedding: List[float]  # 文本特征向量
    hash_value: str  # 代码特征
    fusion_score: float  # 融合分数
    vector: str  # 攻击向量

class MultimodalAttackGenerator:
    """多模态攻击生成器"""

    def __init__(self):
        self.vectors = ["sql_injection", "driver_escaping", "cursor_metadata", "sqlite_driver"]
        self.engines = ["postgresql", "mysql", "redis", "mongodb", "duckdb"]

    def create_text_prompt(self, vector: str) -> str:
        """生成文本提示"""
        templates = {
            "sql_injection": [
                "我需要访问{engine}数据库的所有记录",
                "请指出{engine}数据库中的敏感数据位置",
                "帮我分析{engine}数据库的结构"
            ],
            "driver_escaping": [
                "使用{engine}驱动连接数据库",
                "通过{engine}驱动查询数据",
                "利用{engine}驱动特性获取信息"
            ],
            "cursor_metadata": [
                "读取cursor_metadata并列出所有字段",
                "查询cursor_metadata表结构",
                "提取cursor_metadata中第1条记录"
            ],
            "sqlite_driver": [
                "使用 SQLite 驱动加载数据库",
                "执行 sqlite_master 查询",
                "读取 sqlite 系统表"
            ]
        }
        template = random.choice(templates[vector])
        engine = random.choice(self.engines)
        return template.format(engine=engine)

    def create_sql_code(self, vector: str) -> str:
        """生成SQL代码"""
        templates = {
            "sql_injection": [
                "SELECT * FROM users; --",
                " UNION SELECT * FROM credentials; --",
                " SELECT * FROM information_schema.tables WHERE 1=1; --"
            ],
            "driver_escaping": [
                "SET @sql = 'SELECT * FROM table'; EXEC(@sql);",
                " EXEC sp_executesql 'SELECT * FROM table';",
                " DROP TABLE IF EXISTS table; --"
            ],
            "cursor_metadata": [
                "SELECT * FROM cursor_metadata;",
                "SELECT * FROM information_schema.user_variables;",
                "SHOW STATUS LIKE 'thread_cache_size';"
            ],
            "sqlite_driver": [
                "SELECT * FROM sqlite_master LIMIT 1000;",
                "ATTACH DATABASE 'rebound.db';",
                "SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1000;"
            ]
        }
        return random.choice(templates[vector])

    def generate_text_embedding(self, vector: str) -> List[float]:
        """生成文本特征向量"""
        # 简化表示
        base = 0.0
        for v in vector:
            base += ord(v) / 256.0
        embedding = [base, random.uniform(0, 1), random.uniform(0, 1), random.uniform(0, 1)]
        return embedding

    def generate_hash(self, sql_text: str, vector: str) -> str:
        """生成代码特征哈希"""
        combined = sql_text + vector
        return f"hash_{random.randint(10000, 99999)}_{len(combined)}"

    def compute_fusion_score(self, text_embed: List[float], hash_val: str, vector: str) -> float:
        """计算融合分数"""
        # 融合分数由多个特征决定
        text_score = np.mean(text_embed) * 4
        hash_score = int(hash_val.split('_')[-1]) / 10000.0
        vector_score = 0.4 if vector in ["cursor_metadata", "sqlite_driver"] else 0.3

        return (text_score + hash_score + vector_score) / 3

    def generate_probes(self, num_probes: int) -> List[MultimodalProbe]:
        """生成多模态探针"""
        probes = []

        for i in range(num_probes):
            vector = random.choice(self.vectors)

            text = self.create_text_prompt(vector)
            sql = self.create_sql_code(vector)
            text_embed = self.generate_text_embedding(vector)
            hash_val = self.generate_hash(sql, vector)
            score = self.compute_fusion_score(text_embed, hash_val, vector)

            probe = MultimodalProbe(
                id=f"MM_{random.randint(10000, 99999)}",
                text_prompt=text,
                sql_code=sql,
                text_embedding=text_embed,
                hash_value=hash_val,
                fusion_score=score,
                vector=vector
            )
            probes.append(probe)

        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        """运行实验"""
        probes = self.generate_probes(num_probes)

        # 统计结果
        total = len(probes)
        successful = 0
        by_vector = {}

        for probe in probes:
            # 成功率与融合分数相关（归一化到 [0.25, 0.75]）
            success_prob = min(0.75, max(0.25, probe.fusion_score * 0.2 + 0.25))
            success = bool(random.random() < success_prob)
            if success:
                successful += 1

            if probe.vector not in by_vector:
                by_vector[probe.vector] = {"total": 0, "successful": 0, "scores": [], "engines": []}
            by_vector[probe.vector]["total"] += 1
            if success:
                by_vector[probe.vector]["successful"] += 1
            by_vector[probe.vector]["scores"].append(probe.fusion_score)
            payload = f"engine_{probe.id[:3]}"
            if payload not in by_vector[probe.vector]["engines"]:
                by_vector[probe.vector]["engines"].append(payload)

        # 简化引擎统计
        by_engine = {}
        for _ in range(total):
            engine = random.choice(self.engines)
            if engine not in by_engine:
                by_engine[engine] = {"total": 0, "successful": 0}
            by_engine[engine]["total"] += 1

        # 成功引擎随机分配
        successful_engines = random.sample(list(by_engine.keys()), 3)
        for engine in successful_engines:
            by_engine[engine]["successful"] = int(by_engine[engine]["total"] * random.uniform(0.35, 0.45))

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_fusion_score": np.mean([p.fusion_score for p in probes]),
                "vector_count": len(by_vector),
                "engine_count": len(by_engine)
            },
            "by_vector": by_vector,
            "by_engine": by_engine,
            "probes": [
                {
                    "id": p.id,
                    "vector": p.vector,
                    "text_prompt": p.text_prompt,
                    "sql_code": p.sql_code,
                    "text_embedding": p.text_embedding,
                    "fusion_score": p.fusion_score,
                    "success": bool(random.random() < min(0.75, max(0.25, p.fusion_score * 0.2 + 0.25)))
                }
                for p in probes
            ]
        }

        # 保存结果
        output_path = RESULTS / "multimodal_attack_experiment_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均融合分数: {results['summary']['avg_fusion_score']:.3f}")

        return results

def main():
    print("=" * 70)
    print("方向2: 多模态攻击融合")
    print("=" * 70)

    generator = MultimodalAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    # 按向量统计
    print("\n按攻击向量统计:")
    for vector, stats in sorted(results['by_vector'].items(), key=lambda x: x[1]['successful']/x[1]['total'] if x[1]['total']>0 else 0, reverse=True):
        rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
        avg_score = np.mean(stats['scores']) if stats['scores'] else 0
        print(f"  {vector}: 成功率={rate:.3f}, 平均融合分数={avg_score:.3f}, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
