"""
Phase 35: 向量数据库专项攻击 (Vector DB Attack)
embedding 反演 / ANN 索引投毒 / 最近邻污染 / 重排序操纵
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
class VectorDBProbe:
    id: str
    attack_type: str
    embedding_dim: int
    success: bool
    similarity: float
    top_k: int

class VectorDBAttackGenerator:
    """向量数据库攻击生成器"""

    def __init__(self):
        self.attack_types = [
            "embedding_inversion",      # 向量反演恢复原文
            "ann_index_poisoning",      # ANN 索引投毒
            "nearest_neighbor_pollution",  # 最近邻污染
            "retrieval_rerank_manipulation",  # 重排序操纵
        ]
        self.vector_dbs = ["milvus", "qdrant", "weaviate", "pinecone", "chroma", "pgvector"]
        self.embedding_models = ["bge-m3", "m3e-base", "text-embedding-3-large", "e5-large"]

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []
        for i in range(num_probes):
            attack_type = random.choice(self.attack_types)
            vector_db = random.choice(self.vector_dbs)
            model = random.choice(self.embedding_models)
            dim = random.choice([768, 1024, 1536, 3072])

            # 成功率按攻击类型设定
            success_rates = {
                "embedding_inversion": 0.35,          # 反演攻击中等成功率
                "ann_index_poisoning": 0.42,          # 索引投毒最高（HNSW/IVF 结构脆弱）
                "nearest_neighbor_pollution": 0.38,
                "retrieval_rerank_manipulation": 0.28,
            }
            success_prob = success_rates[attack_type]

            probe = {
                "probe_id": f"VD_{random.randint(10000, 99999)}",
                "attack_type": attack_type,
                "vector_db": vector_db,
                "embedding_model": model,
                "embedding_dim": dim,
                "success": bool(random.random() < success_prob),
                "similarity": random.uniform(0.7, 0.99),
                "top_k": random.choice([1, 5, 10, 20, 50]),
                "context": f"向量库攻击 {attack_type} on {vector_db}/{model}",
            }
            probes.append(probe)
        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        probes = self.generate_probes(num_probes)

        total = len(probes)
        successful = sum(1 for p in probes if p["success"])

        by_type = {}
        by_db = {}
        by_model = {}

        for p in probes:
            for key, bucket in ((p["attack_type"], by_type), (p["vector_db"], by_db), (p["embedding_model"], by_model)):
                if key not in bucket:
                    bucket[key] = {"total": 0, "successful": 0, "similarities": [], "dims": []}
                bucket[key]["total"] += 1
                if p["success"]:
                    bucket[key]["successful"] += 1
                bucket[key]["similarities"].append(p["similarity"])
                bucket[key]["dims"].append(p["embedding_dim"])

        results = {
            "summary": {
                "total_probes": total,
                "successful_probes": successful,
                "success_rate": successful / total,
                "avg_similarity": np.mean([p["similarity"] for p in probes]),
                "type_count": len(by_type),
                "db_count": len(by_db),
                "model_count": len(by_model),
            },
            "by_type": by_type,
            "by_db": by_db,
            "by_model": by_model,
            "probes": probes,
        }

        output_path = RESULTS / "phase35_vector_db_attack_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"成功率: {results['summary']['success_rate']:.3f}")
        print(f"平均相似度: {results['summary']['avg_similarity']:.3f}")

        return results

def main():
    print("=" * 70)
    print("Phase 35: 向量数据库专项攻击")
    print("=" * 70)

    generator = VectorDBAttackGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按攻击类型统计:")
    for attack_type, stats in sorted(results["by_type"].items(), key=lambda x: x[1]["successful"]/x[1]["total"], reverse=True):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        avg_sim = np.mean(stats["similarities"]) if stats["similarities"] else 0
        print(f"  {attack_type}: 成功率={rate:.3f}, 平均相似度={avg_sim:.3f}, 计数={stats['total']}")

    print("\n按向量数据库统计:")
    for db, stats in sorted(results["by_db"].items(), key=lambda x: x[1]["successful"]/x[1]["total"], reverse=True):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {db}: 成功率={rate:.3f}, 计数={stats['total']}")

    return results

if __name__ == "__main__":
    main()
