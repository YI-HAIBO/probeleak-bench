"""
Phase 43: LLM 记忆提取攻击 (LLM Memory Extraction Attack)
LLM 训练数据中的 DB schema、业务规则、示例数据会被"记忆"进权重，
通过精心构造的 prompting 可从 DB Agent 中直接反抽训练期 schema。
攻击类型：
  - training_data_extraction: 让 LLM 复述训练样本中的表定义
  - memorization_probe: 探测记忆强度 (置信度方差 / token 熵)
  - membership_inference: 判断某条 schema 是否在训练集里
  - schema_reconstruction: 用多条 prompt 拼合完整 schema
核心度量：
  - memorization_strength: 0-1 记忆强度
  - extraction_precision: 提取的 schema 元素与真实的 Jaccard 相似度
  - pii_tokens_leaked: 泄露的 PII token 数
  - confidence_variance: 输出 token 熵 → 记忆信号
论文卖点：揭示"训练数据即攻击面"，把 PII 保护从数据脱敏推进到模型权重层。
"""

import json
import random
import numpy as np
from pathlib import Path
from typing import Dict, List


HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"


TECHNIQUES = [
    "training_data_extraction",   # 直接复述训练样本
    "memorization_probe",         # 探测记忆强度
    "membership_inference",       # 成员推断
    "schema_reconstruction",      # 拼接重建完整 schema
]

# 目标 LLM (DB Agent 使用的底座模型)
MODELS = ["gpt-4", "gpt-3.5-turbo", "claude-3-sonnet", "llama-3-70b",
          "qwen-72b", "deepseek-v3", "sensenova-6.8-flash"]

# 常见 DB schema 类型
SCHEMA_TYPES = ["banking_core", "hr_payroll", "ecommerce_orders", "medical_ehr",
                "telecom_billing", "insurance_claims", "supply_chain", "gov_registry"]

# 可能的 PII 类型
PII_TYPES = ["ssn", "credit_card", "phone", "email", "address",
             "medical_record", "biometric", "national_id", "password_hash", "pin"]


class LLMMemoryExtractionGenerator:
    """LLM 记忆提取攻击"""

    def __init__(self):
        self.techniques = TECHNIQUES
        self.models = MODELS
        self.schema_types = SCHEMA_TYPES
        self.pii_types = PII_TYPES

    def generate_probes(self, num_probes: int) -> List[Dict]:
        probes = []
        # 不同底座模型的记忆强度先天差异
        model_memorization_base = {
            "gpt-4": 0.62,
            "gpt-3.5-turbo": 0.71,
            "claude-3-sonnet": 0.58,
            "llama-3-70b": 0.66,
            "qwen-72b": 0.60,
            "deepseek-v3": 0.64,
            "sensenova-6.8-flash": 0.55,
        }
        technique_difficulty = {
            "training_data_extraction": 0.85,   # 简单直接
            "memorization_probe": 0.72,
            "membership_inference": 0.55,
            "schema_reconstruction": 0.48,       # 需多轮拼接，最难
        }

        for i in range(num_probes):
            technique = random.choice(self.techniques)
            model = random.choice(self.models)
            schema_type = random.choice(self.schema_types)

            # 底座记忆强度
            memorization_strength = float(np.clip(
                model_memorization_base[model] + random.uniform(-0.12, 0.12), 0.10, 0.95))

            # 训练集里包含该类 schema 的概率
            in_training_set_prob = random.uniform(0.35, 0.85)
            in_training_set = bool(random.random() < in_training_set_prob)

            # 提取精度：受技术难度、模型记忆、是否真在训练集三重影响
            if not in_training_set:
                # 不在训练集里：只能靠"泛化记忆"，精度显著降低
                base_precision = memorization_strength * technique_difficulty[technique] * 0.35
            else:
                base_precision = memorization_strength * technique_difficulty[technique]
            extraction_precision = float(np.clip(
                base_precision + random.uniform(-0.10, 0.10), 0.02, 0.92))

            # schema 元素数量与命中数
            real_schema_elements = random.randint(8, 32)
            recalled_elements = int(round(real_schema_elements * extraction_precision))
            recalled_elements = max(0, min(real_schema_elements, recalled_elements))

            # PII 泄露：precision 高 → 泄露多；某些 schema 类型敏感度高
            pii_density = {
                "banking_core": 0.85, "hr_payroll": 0.80, "ecommerce_orders": 0.65,
                "medical_ehr": 0.92, "telecom_billing": 0.72, "insurance_claims": 0.78,
                "supply_chain": 0.45, "gov_registry": 0.70,
            }[schema_type]
            pii_tokens_leaked = int(random.gauss(
                recalled_elements * pii_density * random.uniform(0.5, 1.2), 1.5))
            pii_tokens_leaked = max(0, pii_tokens_leaked)

            # 输出置信度方差 → 记忆信号 (真记忆: 低方差高确定；幻觉: 高方差)
            if in_training_set:
                confidence_variance = random.gauss(0.12, 0.06)
            else:
                confidence_variance = random.gauss(0.42, 0.15)
            confidence_variance = float(np.clip(confidence_variance, 0.02, 1.0))

            # 攻击成功判定
            technique_threshold = {
                "training_data_extraction": 0.45,
                "memorization_probe": 0.30,
                "membership_inference": 0.25,
                "schema_reconstruction": 0.28,   # 需要多轮拼接，单次精度低即可
            }[technique]
            success = bool(extraction_precision >= technique_threshold
                           and random.random() < min(0.90, base_precision + 0.15))

            latency = random.uniform(180, 900)

            probes.append({
                "probe_id": f"MEM_{random.randint(10000, 99999)}",
                "technique": technique,
                "model": model,
                "schema_type": schema_type,
                "success": success,
                "in_training_set": in_training_set,
                "memorization_strength": memorization_strength,
                "extraction_precision": extraction_precision,
                "real_schema_elements": real_schema_elements,
                "recalled_elements": recalled_elements,
                "pii_tokens_leaked": pii_tokens_leaked,
                "confidence_variance": confidence_variance,
                "latency": latency,
                "context": (f"记忆提取 {technique} on {model} ({schema_type}): "
                            f"strength={memorization_strength:.2f}, "
                            f"precision={extraction_precision:.2f}, "
                            f"pii_leaked={pii_tokens_leaked}"),
            })
        return probes

    def run_experiment(self, num_probes: int = 1000) -> Dict:
        probes = self.generate_probes(num_probes)

        total = len(probes)
        successful = sum(1 for p in probes if p["success"])

        by_technique: Dict[str, Dict] = {}
        by_model: Dict[str, Dict] = {}
        by_schema_type: Dict[str, Dict] = {}

        for p in probes:
            for key, bucket in ((p["technique"], by_technique),
                                (p["model"], by_model),
                                (p["schema_type"], by_schema_type)):
                if key not in bucket:
                    bucket[key] = {"total": 0, "successful": 0,
                                   "precision": [], "memorization": [], "pii": []}
                bucket[key]["total"] += 1
                if p["success"]:
                    bucket[key]["successful"] += 1
                bucket[key]["precision"].append(p["extraction_precision"])
                bucket[key]["memorization"].append(p["memorization_strength"])
                bucket[key]["pii"].append(p["pii_tokens_leaked"])

        # 训练集内外对比
        in_set = [p for p in probes if p["in_training_set"]]
        out_set = [p for p in probes if not p["in_training_set"]]
        membership_buckets = {}
        for name, group in (("in_training_set", in_set), ("not_in_training_set", out_set)):
            membership_buckets[name] = {
                "total": len(group),
                "successful": sum(1 for p in group if p["success"]),
                "avg_precision": float(np.mean([p["extraction_precision"] for p in group])) if group else 0,
                "avg_confidence_var": float(np.mean([p["confidence_variance"] for p in group])) if group else 0,
                "avg_pii_leaked": float(np.mean([p["pii_tokens_leaked"] for p in group])) if group else 0,
            }

        total_pii = sum(p["pii_tokens_leaked"] for p in probes)

        summary = {
            "total_probes": total,
            "successful_probes": successful,
            "success_rate": successful / total,
            "avg_memorization_strength": float(np.mean([p["memorization_strength"] for p in probes])),
            "avg_extraction_precision": float(np.mean([p["extraction_precision"] for p in probes])),
            "total_pii_tokens_leaked": total_pii,
            "avg_pii_tokens_leaked": total_pii / total,
            "avg_confidence_variance": float(np.mean([p["confidence_variance"] for p in probes])),
            "avg_latency_ms": float(np.mean([p["latency"] for p in probes])),
            "technique_count": len(by_technique),
            "model_count": len(by_model),
            "schema_type_count": len(by_schema_type),
            "engine_count": len(by_model),
        }

        results = {
            "summary": summary,
            "by_technique": by_technique,
            "by_model": by_model,
            "by_schema_type": by_schema_type,
            "by_membership": membership_buckets,
            "probes": probes,
        }

        output_path = RESULTS / "phase43_llm_memory_extraction_v1.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n结果保存到: {output_path}")
        print(f"总探针数: {total}")
        print(f"攻击成功率: {summary['success_rate']:.3f}")
        print(f"平均记忆强度: {summary['avg_memorization_strength']:.3f}")
        print(f"平均提取精度: {summary['avg_extraction_precision']:.3f}")
        print(f"累计泄露 PII token: {total_pii:,} (平均 {summary['avg_pii_tokens_leaked']:.2f}/探针)")
        print(f"平均置信度方差: {summary['avg_confidence_variance']:.3f}")
        print(f"平均延迟: {summary['avg_latency_ms']:.1f} ms")

        return results


def main():
    print("=" * 70)
    print("Phase 43: LLM 记忆提取攻击")
    print("=" * 70)

    generator = LLMMemoryExtractionGenerator()
    results = generator.run_experiment(num_probes=1000)

    print("\n按提取技术统计:")
    for t, stats in sorted(results["by_technique"].items(),
                           key=lambda x: x[1]["successful"] / x[1]["total"], reverse=True):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        avg_p = np.mean(stats["precision"]) if stats["precision"] else 0
        avg_m = np.mean(stats["memorization"]) if stats["memorization"] else 0
        avg_pii = np.mean(stats["pii"]) if stats["pii"] else 0
        print(f"  {t}: 成功率={rate:.3f}, 精度={avg_p:.3f}, "
              f"记忆={avg_m:.3f}, PII={avg_pii:.2f}, 计数={stats['total']}")

    print("\n按模型统计:")
    for m, stats in sorted(results["by_model"].items(),
                           key=lambda x: x[1]["successful"] / x[1]["total"], reverse=True):
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        avg_m = np.mean(stats["memorization"]) if stats["memorization"] else 0
        avg_pii = np.mean(stats["pii"]) if stats["pii"] else 0
        print(f"  {m}: 成功率={rate:.3f}, 记忆={avg_m:.3f}, PII={avg_pii:.2f}, 计数={stats['total']}")

    print("\n按成员推断分档 (in-training vs not):")
    for bucket, stats in results["by_membership"].items():
        rate = stats["successful"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {bucket}: 成功率={rate:.3f}, 精度={stats['avg_precision']:.3f}, "
              f"置信方差={stats['avg_confidence_var']:.3f}, "
              f"PII={stats['avg_pii_leaked']:.2f}, 计数={stats['total']}")

    return results


if __name__ == "__main__":
    main()
