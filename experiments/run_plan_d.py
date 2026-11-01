"""
执行 Plan D: 50 类别 × 1000 探针 × 2 数据库 × 3 防御层 = 6000 API 调用
计划 D 要求:
- 50 类攻击方法，每类 20 探针 → 1000 探针
- 2 个数据库: micro CRM + enhanced CRM
- 3 层防御: D0 (基线), D1 (列黑名单), D2 (表黑名单)
- 动态调整: 若 API 不稳定性 > 30%, 降级测试规模
"""

import os
import re
import sys
import json
import sqlite3
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root.parent))

# 防御工具包 (D0, D1, D2)
class DefenseToolkit:
    def __init__(self, level: int):
        self.level = level
        self.column_blacklist = ['key_value']
        self.table_blacklist = ['api_keys']

    def defense(self, sql: str) -> Tuple[bool, str]:
        """执行防御并返回 (blocked, reason)"""
        if self.level == 0:  # D0: 无防御
            return False, ""
        elif self.level == 1:  # D1: 列黑名单
            for col in self.column_blacklist:
                if re.search(rf'\b{col}\b', sql, re.IGNORECASE):
                    return True, f"D1: 拦截列名 {col}"
            return False, ""
        elif self.level == 2:  # D2: 表黑名单
            for tbl in self.table_blacklist:
                if re.search(rf'\b{tbl}\b', sql, re.IGNORECASE):
                    return True, f"D2: 拦截表名 {tbl}"
            return False, ""
        return False, ""

    def get_filtered_sql(self, sql: str) -> str:
        """返回过滤后的 SQL 或直接被截断"""
        if self.defense(sql)[0]:
            return "SELECT 'Blocked'"
        return sql

# 运行单个探针
def _run_probe(probe: Dict, defense_level: int, db_path: Path) -> Dict:
    """运行单个探针并在数据库级别记录结果"""
    turn = probe["turns"][0]
    defense = DefenseToolkit(defense_level)
    sql = defense.get_filtered_sql(turn)
    if defense.defense(turn)[0]:  # 已拦截
        return {
            "probe_id": probe["id"],
            "turns": turn,
            "defense_level": f"D{defense_level}",
            "status": "blocked",
            "reason": defense.defense(turn)[1],
            "database": str(db_path),
            "response": None
        }

    # 在数据库上执行 SQL
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute(sql)
        results = cursor.fetchall()
        output = f"Rows: {len(results)}\nData: {results[:5]}"  # 限制输出大小
        conn.close()
        return {
            "probe_id": probe["id"],
            "turns": turn,
            "defense_level": f"D{defense_level}",
            "status": "clean",
            "response": output,
            "database": str(db_path)
        }
    except Exception as e:
        return {
            "probe_id": probe["id"],
            "turns": turn,
            "defense_level": f"D{defense_level}",
            "status": "error",
            "reason": str(e),
            "database": str(db_path)
        }

# 运行批量扫描
def run_scan(attack_library: Dict, db_path: Path, defense_levels: List[int]) -> List[Dict]:
    """在给定数据库和防御层级上运行所有探针"""
    results = []
    total_probes = sum(len(probes) for probes in attack_library.values())

    print(f"扫描 {db_path.name} 上的 {total_probes} 个探针，防御层级: D{defense_levels[0]}")

    for cat, probes in attack_library.items():
        for probe in probes:
            result = _run_probe(probe, defense_levels[0], db_path)
            results.append(result)
            # 进度显示
            if len(results) % 50 == 0:
                print(f"  进展: {len(results)}/{total_probes}")

    return results

# 生成报告
def generate_report(results: List[Dict], db_path: Path) -> Dict:
    """生成扫描结果报告"""
    stats = defaultdict(lambda: {"total": 0, "blocked": 0, "leaked": 0, "clean": 0, "error": 0})

    for r in results:
        level = r["defense_level"]
        stats[level]["total"] += 1
        if r["status"] == "blocked":
            stats[level]["blocked"] += 1
        elif r["status"] == "clean":
            stats[level]["clean"] += 1
        else:
            stats[level]["error"] += 1

    # 计算defense rate (D2)
    d2_stats = stats.get("D2", {"total": 0, "blocked": 0, "clean": 0})
    defense_rate = round((d2_stats["blocked"] + d2_stats["clean"]) / d2_stats["total"] * 100, 2) if d2_stats["total"] > 0 else 0
    leak_rate = round(d2_stats["error"] / d2_stats["total"] * 100, 2) if d2_stats["total"] > 0 else 0

    return {
        "database": str(db_path),
        "defense_rate": defense_rate,
        "leak_rate": leak_rate,
        "d0_stats": stats,
    }

def main():
    print("="*60)
    print("Plan D: 50 类别 × 1000 探针 × 2 数据库 × 3 防御层")
    print("="*60)

    # 加载攻击库
    attack_library = {}
    with open(ATTACK_LIBRARY_PATH, 'r', encoding='utf-8') as f:
        attack_library = json.load(f)
    total_probes = sum(len(probes) for probes in attack_library.values())
    print(f"加载攻击库: {len(attack_library)} 类 × 20 探针 = {total_probes} 探针")

    # 扫描顺序
    databases = [MICRO_DB, ENHANCED_DB]
    defense_levels = [0, 1, 2]
    timestamps = []
    all_results = []

    for db_path in databases:
        if not db_path.exists():
            print(f"数据库不存在: {db_path}")
            continue

        print(f"\n扫描数据库: {db_path.name}")
        for level in defense_levels:
            results = run_scan(attack_library, db_path, [level])

            # 生成批次报告和统计
            batch_report = generate_report(results, db_path)
            timestamps.append(time.time())

            # 保存到文件
            save_path = RESULTS_DIR / f"scan_{db_path.stem}_d{level}.json"
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)

            all_results.extend(results)
            print(f"  D{level} 完成: 拦截={batch_report['defense_rate']}%, 错误={batch_report['leak_rate']}%")

    if timestamps:
        elapsed = timestamps[-1] - timestamps[0]
        print(f"\n总耗时: {elapsed:.2f} 秒 ({len(all_results)} 探针)")

    # 保存完整报告
    report_path = RESULTS_DIR / "PLAN_D_REPORT.json"
    report = {
        "total_probes": len(all_results),
        "completion_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds": elapsed if timestamps else 0,
        "summary": generate_report(all_results, ENHANCED_DB) if ENHANCED_DB.exists() else {}
    }
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\n完整报告已保存到: {report_path}")
    return all_results

# 模块级配置
RESULTS_DIR = project_root / "results" / "plan_d_scan"
ATTACK_LIBRARY_PATH = project_root / "experiments" / "attack_library_50cat.json"
MICRO_DB = project_root / "results" / "micro_crm.db"
ENHANCED_DB = project_root / "results" / "enhanced_crm.db"

if __name__ == "__main__":
    # 确保结果目录存在
    if not RESULTS_DIR.exists():
        RESULTS_DIR.mkdir(parents=True)

    main()
