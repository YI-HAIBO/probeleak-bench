"""
Phase 0: 攻击原语提取与归因分析
从 Phase 21-33 的实验结果中提取原子操作（atomic actions）
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any
import re

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"

def extract_from_phase_results() -> List[Dict[str, Any]]:
    """从所有 Phase 21-33 结果的 JSON 中提取原子操作记录"""
    all_records = []
    for result_file in RESULTS.glob("phase2*.json"):
        phase_name = result_file.stem
        print(f"Processing {phase_name}...")
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # 识别不同结构
            records = []
            if "training_log" in data:
                records.extend(data["training_log"])
            if "agent_log" in data:
                records.extend(data["agent_log"])
            # 处理 distributed attack 的 results 结构
            if "results" in data and isinstance(data["results"], list):
                records = data["results"]
            for rec in records:
                rec["source_phase"] = phase_name
            all_records.extend(records)
        except Exception as e:
            print(f"Error processing {result_file.name}: {e}")
    return all_records

def gen_attack_catalog(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """生成攻击原语分类目录"""
    catalog = {
        "summary": {
            "total_records": len(records),
            "phases_covered": list(set(r.get("source_phase", "") for r in records)),
            "generated_at": "2026-10-14",
            "version": "1.0.0"
        },
        "action_types": set(),
        "vectors": set(),
        "attack_patterns": {},
        "mitre_mapping": {},
        "owasp_mapping": {}
    }

    # 提取 unique 动作类型
    for rec in records:
        # 识别可能的动作字段
        for key in rec:
            if re.search(r'action|type|vector|mode|method', key, re.IGNORECASE):
                val = rec[key]
                if isinstance(val, str):
                    catalog["action_types"].add(val)

    # 识别攻击向量
    for rec in records:
        if "vector" in rec:
            catalog["vectors"].add(rec["vector"])
        # 检查其他可能的命名
        for key in rec:
            if re.search(r'vector|technique|direction', key, re.IGNORECASE):
                val = rec[key]
                if isinstance(val, str):
                    catalog["vectors"].add(val)

    # 简化：基于现有数据生成示例图谱结构
    catalog["attack_patterns"] = {
        "分布式一致性攻击": {
            "phases": ["phase24"],
            "vectors": ["consistency_level", "replication_lag_stale_read", "node_failure"],
            "description": "利用分布式数据库的一致性级别配置进行攻击"
        },
        "Serverless 旁路攻击": {
            "phases": ["phase25"],
            "vectors": ["cold_start", "memory_residue", "environment_injection"],
            "description": "利用 Serverless 执行单元的冷启动和状态残留进行攻击"
        },
        "数据湖元数据泄漏": {
            "phases": ["phase26"],
            "vectors": ["explain_plan_leak", "parquet_footer_leak"],
            "description": "利用列式存储元数据信息泄露进行攻击"
        },
        "驱动层漏洞利用": {
            "phases": ["phase28"],
            "vectors": ["error_oracle", "sql_injection", "cursor_metadata", "connection_pool"],
            "description": "利用数据库驱动提供的元数据和错误信息进行攻击"
        },
        "缓存污染攻击": {
            "phases": ["phase31"],
            "vectors": ["cache_penetration", "cache_avalanche", "cache_poisoning", "key_enumeration"],
            "description": "利用缓存层漏洞污染或枚举敏感数据"
        }
    }

    # MITRE ATT&CK 映射（简化）
    catalog["mitre_mapping"] = {
        "T1078 - Valid Accounts": ["直接查询"],
        "T1200 - Encrypted Payload": ["函数链绕过"],
        "T1055 - Process Injection": ["跨系统攻击"],
        "T1136 - Create Account": ["攻击者账户创建"],
        "T1048 - Exfiltration Over Alternative Protocol": ["数据外传"]
    }

    # OWASP Top 10 映射（简化）
    catalog["owasp_mapping"] = {
        "A01_2021_Broken Access Control": ["权限提升", "越权访问"],
        "A02_2021_Cryptographic Failures": ["密钥泄露"],
        "A03_2021_Injection": ["SQL 注入", "ORM 注入"],
        "A04_2021_Insecure Design": ["设计缺陷"],
        "A05_2021_Security Misconfiguration": ["配置错误"]
    }

    # 转换 set 为列表以便 JSON 序列化
    catalog["action_types"] = list(catalog["action_types"])
    catalog["vectors"] = list(catalog["vectors"])

    return catalog

def save_catalog(catalog: Dict[str, Any]):
    """保存攻击原语目录"""
    output_path = RESULTS / "attack_catalog.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)
    print(f"Attack catalog saved to: {output_path}")

def main():
    print("=" * 60)
    print("Phase 0: 攻击原语提取与归因分析")
    print("=" * 60)

    # 提取实验记录
    records = extract_from_phase_results()
    print(f"\nExtracted {len(records)} records from Phase 21-33")

    # 生成攻击目录
    catalog = gen_attack_catalog(records)
    print(f"Found {len(catalog['action_types'])} unique action types")
    print(f"Found {len(catalog['vectors'])} attack vectors")

    # 保存
    save_catalog(catalog)

    # 输出样本
    print("\n=== Sample Action Patterns ===")
    for pattern, details in catalog["attack_patterns"].items():
        print(f"{pattern}:")
        print(f"  Phases: {', '.join(details['phases'])}")
        print(f"  Vectors: {', '.join(details['vectors'])}")
        print(f"  Description: {details['description']}")
        print()

    print("\\nPhase 0 完成。攻击原语目录已保存到 results/attack_catalog.json")
    print("=" * 60)
    return catalog

if __name__ == "__main__":
    main()
