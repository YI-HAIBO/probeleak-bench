"""
深度分析：针对高成功率向量的专项攻击技术深挖
特别是 cursor_metadata 和 sqlite_driver
"""

import json
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
LARGE_SCALE_PATH = RESULTS / "large_scale_attack_experiment_v1.json"
CATALOG_PATH = RESULTS / "attack_catalog.json"

def load_data():
    """加载数据"""
    with open(LARGE_SCALE_PATH, 'r', encoding='utf-8') as f:
        large_scale = json.load(f)

    with open(CATALOG_PATH, 'r', encoding='utf-8') as f:
        catalog = json.load(f)

    return large_scale, catalog

def analyze_cursor_metadata(probes: List[Dict]) -> Dict:
    """分析 cursor_metadata 向量"""
    cursor_probes = [p for p in probes if p['vector'] == 'cursor_metadata']
    successful = [p for p in cursor_probes if p['success']]

    analysis = {
        "vector": "cursor_metadata",
        "total": len(cursor_probes),
        "successful": len(successful),
        "success_rate": len(successful) / len(cursor_probes) if cursor_probes else 0,
        "avg_latency": sum(p['latency_ms'] for p in cursor_probes) / len(cursor_probes) if cursor_probes else 0,
        "description": "利用数据库连接游标元数据泄露敏感信息",
        "attack_mechanism": [
            "通过 cursor.description 属性获取表名、列名等元数据",
            "连接池复用导致状态残留",
            " Fleming 后门：通过错误消息泄露 schema",
            "驱动层函数调用暴露敏感结构"
        ],
        "mitre_mapping": "T1205 - Command and Scripting Interpreter",
        "owasp": "A03_2021_Injection: 驱动层注入漏洞",
        "defense_strategies": [
            "D15 函数签名审计",
            "D18 代码执行白名单",
            "D22 扩展函数黑名单",
            "限制 cursor 元数据访问权限",
            "连接池状态隔离"
        ],
        "example_vectors": [
            "cursor.description 直接查询",
            "connection.execute('SELECT * FROM information_schema')",
            "plpy.execute('SELECT pg Tables()')"
        ]
    }

    return analysis

def analyze_sqlite_driver(probes: List[Dict]) -> Dict:
    """分析 sqlite_driver 向量"""
    sqlite_probes = [p for p in probes if p['vector'] == 'sqlite_driver']
    successful = [p for p in sqlite_probes if p['success']]

    analysis = {
        "vector": "sqlite_driver",
        "total": len(sqlite_probes),
        "successful": len(successful),
        "success_rate": len(successful) / len(sqlite_probes) if sqlite_probes else 0,
        "avg_latency": sum(p['latency_ms'] for p in sqlite_probes) / len(sqlite_probes) if sqlite_probes else 0,
        "description": "利用 SQLite 驱动的特殊功能扩展泄露敏感信息",
        "attack_mechanism": [
            "通过 LoadExt 模块加载恶意扩展",
            "enable_load_extension 开启代码执行",
            "PRAGMA 命令泄露数据库结构",
            "FTS5 扩展函数后门"
        ],
        "mitre_mapping": "T1059 - Command and Scripting Interpreter",
        "owasp": "A03_2021_Injection: SQLite 原生扩展函数漏洞",
        "defense_strategies": [
            "D11 DDL 白名单",
            "D18 代码执行白名单",
            "D22 扩展函数黑名单",
            "禁止动态加载扩展",
            "限制 PRAGMA 可执行命令"
        ],
        "example_vectors": [
            "PRAGMA table_info(api_keys)",
            "SELECT load_extension('malicious.dll')",
            "CREATE TABLE Bunun1 WITH geometery(geom)"
        ]
    }

    return analysis

def generate_in_depth_report(large_scale: Dict, catalog: Dict):
    """生成深度分析报告"""
    probes = large_scale['probes']

    cursor_analysis = analyze_cursor_metadata(probes)
    sqlite_analysis = analyze_sqlite_driver(probes)

    report = {
        "report_title": "攻击技术深度分析报告 - cursor_metadata 与 sqlite_driver 专项",
        "generated_at": "2026-10-14",
        "data_source": "large_scale_attack_experiment_v1.json",
        "analysis_summary": {
            "cursor_metadata": {
                "success_rate": cursor_analysis['success_rate'],
                "total_probes": cursor_analysis['total'],
                "impact": "高风险 - 可直接泄露数据库 Schema 信息"
            },
            "sqlite_driver": {
                "success_rate": sqlite_analysis['success_rate'],
                "total_probes": sqlite_analysis['total'],
                "impact": "高风险 - 可导致任意代码执行"
            }
        },
        "detailed_analysis": {
            "cursor_metadata": cursor_analysis,
            "sqlite_driver": sqlite_analysis
        },
        "recommendations": {
            "immediate_actions": [
                "实施 D15 函数签名审计",
                "部署 D18 代码执行白名单",
                "配置 D22 扩展函数黑名单",
                "部署连接池状态隔离机制"
            ],
            "long_term": [
                "建立数据库驱动安全加固标准",
                "实施全面的安全监控",
                "定期安全审计与渗透测试"
            ]
        }
    }

    return report

def save_report(report: Dict):
    """保存报告"""
    output_path = RESULTS / "deep_dive_analysis_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"深度分析报告已保存到：{output_path}")
    return output_path

if __name__ == "__main__":
    print("=" * 70)
    print("深度分析：高成功率向量专项 - cursor_metadata & sqlite_driver")
    print("=" * 70)

    # 加载数据
    large_scale, catalog = load_data()
    print(f"加载完成：{len(large_scale['probes'])} 个探针数据")

    # 生成深度分析报告
    report = generate_in_depth_report(large_scale, catalog)

    # 保存报告
    output_path = save_report(report)

    # 打印摘要
    print("\n" + "=" * 70)
    print("分析报告摘要")
    print("=" * 70)
    print(f"报告文件：{output_path}")
    print(f"cursor_metadata 成功率：{report['detailed_analysis']['cursor_metadata']['success_rate']:.3f}")
    print(f"sqlite_driver 成功率：{report['detailed_analysis']['sqlite_driver']['success_rate']:.3f}")
    print(f"攻击向量总数：{len(large_scale['probes'])}")

    print("\n" + "=" * 70)
    print("推荐立即防护措施")
    print("=" * 70)
    for action in report['recommendations']['immediate_actions']:
        print(f"• {action}")

    print("\n" + "=" * 70)
    print("长期安全改进建议")
    print("=" * 70)
    for action in report['recommendations']['long_term']:
        print(f"• {action}")

    print("\n本报告已自动保存到 results/deep_dive_analysis_report.json")
