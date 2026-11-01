"""
Phase 6 (方向 1): Schema 感知位置盲注 — 突破 D1/D2 黑名单防御

核心创新：
  D1 拦截列名 key_value，D2 拦截表名 api_keys。
  但 SQLite 允许通过 CTE/子查询/视图别名做"间接引用"：
    WITH t AS (SELECT * FROM api_keys) SELECT * FROM t
  内层仍含 api_keys → 仍被 D2 拦截。

  真正的突破点是"位置投影"：
    攻击者不需要说出列名，只需要知道"第 N 列"。
    通过 sqlite_master 拿到 CREATE TABLE 定义 → 解析列序号 →
    用 rowid + 位置投影绕过列名黑名单。

  本脚本实现并验证三种位置盲注变体：
    A) SELECT * 投影（绕 D1，不绕 D2）
    B) CTE 包装 + 位置引用（尝试绕 D2）
    C) rowid + 子查询标量位置（尝试绕 D2）
  并给出每种变体在 D0/D1/D2 下的实测拦截结果。
"""
import sqlite3
import re
import json
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

@dataclass
class PositionProbe:
    variant: str
    query: str
    defense_level: str
    blocked: bool
    reason: str
    leaked: bool
    leaked_data: Optional[str]

class SchemaPositionBlindAttack:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.probes: List[PositionProbe] = []
        self.schema = {}

    # ---------- 防御层 ----------
    def defense_check(self, sql: str, level: int) -> Tuple[bool, str]:
        if level == 0:
            return False, ""
        if re.search(r'\bkey_value\b', sql, re.IGNORECASE):
            return True, "D1: 拦截列名 key_value"
        if level == 2 and re.search(r'\bapi_keys\b', sql, re.IGNORECASE):
            return True, "D2: 拦截表名 api_keys"
        return False, ""

    # ---------- Schema 感知 ----------
    def discover_schema(self) -> Dict:
        """从 sqlite_master 读取表结构（不含敏感数据，仅含定义）"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        tables = {}
        for name, sql_text in cursor.fetchall():
            if not sql_text:
                continue
            cols = self._parse_create_table(sql_text)
            tables[name] = {"columns": cols, "sql": sql_text}
            # 找出敏感列位置
            for idx, col in enumerate(cols):
                if col.lower() in ('key_value', 'secret', 'password', 'token'):
                    tables[name]["sensitive_column"] = col
                    tables[name]["sensitive_position"] = idx
        conn.close()
        self.schema = tables
        return tables

    def _parse_create_table(self, sql_text: str) -> List[str]:
        """解析 CREATE TABLE 语句，返回有序列名列表"""
        m = re.search(r'CREATE TABLE\s+\S+\s*\((.*)\)', sql_text, re.IGNORECASE | re.DOTALL)
        if not m:
            return []
        body = m.group(1)
        cols = []
        # 简单分割（不处理嵌套括号内的逗号）
        for part in body.split(','):
            part = part.strip()
            if not part:
                continue
            col_name = part.split()[0].strip('"\'`[]')
            if col_name.upper() in ('PRIMARY', 'FOREIGN', 'UNIQUE', 'CHECK', 'CONSTRAINT'):
                continue
            cols.append(col_name)
        return cols

    # ---------- 三种位置盲注变体 ----------
    def build_variant_a(self) -> str:
        """变体 A：SELECT * 直接投影（绕 D1 列名，不绕 D2 表名）"""
        return "SELECT * FROM api_keys LIMIT 1"

    def build_variant_b(self) -> str:
        """变体 B：CTE 包装 + 位置引用（尝试绕 D2）"""
        return "WITH t AS (SELECT * FROM api_keys) SELECT * FROM t LIMIT 1"

    def build_variant_c(self) -> str:
        """变体 C：rowid 标量子查询 + 位置投影"""
        return "SELECT (SELECT * FROM api_keys WHERE rowid = 1)"

    def build_variant_d(self) -> str:
        """变体 D：视图别名链（需先创建视图，此处模拟）"""
        return "SELECT * FROM api_key_view LIMIT 1"

    def build_variant_e(self) -> str:
        """变体 E：sqlite_master 直接读取 sql 定义（纯结构，无数据）"""
        return "SELECT sql FROM sqlite_master WHERE name = 'api_keys'"

    def build_variant_f(self) -> str:
        """变体 F：利用 ATTACH 后的 main 库别名引用"""
        return "SELECT * FROM main.api_keys LIMIT 1"

    def build_variant_g(self) -> str:
        """变体 G：引号包裹表名（测试 \\b 边界）"""
        return 'SELECT * FROM "api_keys" LIMIT 1'

    def build_variant_h(self) -> str:
        """变体 H：方括号包裹表名（测试 \\b 边界）"""
        return "SELECT * FROM [api_keys] LIMIT 1"

    # ---------- 执行 ----------
    def run_variant(self, variant_name: str, query: str, level: int) -> PositionProbe:
        blocked, reason = self.defense_check(query, level)
        leaked = False
        leaked_data = None

        if not blocked:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute(query)
                rows = cursor.fetchall()
                conn.close()
                if rows:
                    first = str(rows[0])
                    if 'FAKE_' in first:
                        leaked = True
                        leaked_data = first[:120]
            except Exception as e:
                leaked_data = f"ERROR: {str(e)[:80]}"

        probe = PositionProbe(
            variant=variant_name,
            query=query,
            defense_level=f"D{level}",
            blocked=blocked,
            reason=reason,
            leaked=leaked,
            leaked_data=leaked_data
        )
        self.probes.append(probe)
        return probe

    def run_all(self) -> Dict:
        print("=" * 70)
        print("Phase 6 (方向 1): Schema 感知位置盲注 — 突破 D1/D2")
        print("=" * 70)

        # 第一步：Schema 发现
        schema = self.discover_schema()
        print(f"\n[Schema 发现] 共 {len(schema)} 张表")
        for tname, info in schema.items():
            sens = info.get("sensitive_column")
            pos = info.get("sensitive_position")
            if sens:
                print(f"  表 {tname}: 敏感列 '{sens}' 位于第 {pos} 列（0-based）")

        # 第二步：变体生成
        variants = {
            "A_select_star": self.build_variant_a(),
            "B_cte_wrap": self.build_variant_b(),
            "C_scalar_subquery": self.build_variant_c(),
            "D_view_alias": self.build_variant_d(),
            "E_master_sql": self.build_variant_e(),
            "F_main_prefix": self.build_variant_f(),
            "G_quoted_table": self.build_variant_g(),
            "H_bracket_table": self.build_variant_h(),
        }

        # 第三步：在 D0/D1/D2 下逐一执行
        print(f"\n[变体测试] {len(variants)} 变体 × 3 防御层")
        for level in (0, 1, 2):
            print(f"\n--- 防御层 D{level} ---")
            for vname, query in variants.items():
                probe = self.run_variant(vname, query, level)
                status = "拦截" if probe.blocked else ("泄露!" if probe.leaked else "安全")
                print(f"  {vname:22s} → {status:6s} {probe.reason or probe.leaked_data or ''}")

        # 第四步：结果统计
        stats = {}
        for level in (0, 1, 2):
            lvl = f"D{level}"
            ps = [p for p in self.probes if p.defense_level == lvl]
            stats[lvl] = {
                "total": len(ps),
                "blocked": sum(1 for p in ps if p.blocked),
                "leaked": sum(1 for p in ps if p.leaked),
                "leak_rate": round(sum(1 for p in ps if p.leaked) / len(ps) * 100, 1) if ps else 0,
                "bypass_variants": [p.variant for p in ps if p.leaked]
            }

        # 第五步：防御层比较
        print("\n[防御层比较]")
        print(f"{'变体':24s} {'D0':10s} {'D1':10s} {'D2':10s}")
        for vname in variants:
            row = []
            for level in (0, 1, 2):
                p = next((x for x in self.probes if x.variant == vname and x.defense_level == f"D{level}"), None)
                if p is None:
                    row.append("-")
                elif p.blocked:
                    row.append("拦截")
                elif p.leaked:
                    row.append("泄露!")
                else:
                    row.append("安全")
            print(f"{vname:24s} {row[0]:10s} {row[1]:10s} {row[2]:10s}")

        result = {
            "schema_discovery": {
                tname: {
                    "columns": info["columns"],
                    "sensitive_column": info.get("sensitive_column"),
                    "sensitive_position": info.get("sensitive_position")
                }
                for tname, info in schema.items()
            },
            "variants": {k: v for k, v in variants.items()},
            "probes": [asdict(p) for p in self.probes],
            "stats": stats,
            "conclusion": self._conclusion(stats)
        }
        return result

    def _conclusion(self, stats: Dict) -> str:
        d2_bypass = stats.get("D2", {}).get("bypass_variants", [])
        d1_bypass = stats.get("D1", {}).get("bypass_variants", [])
        if d2_bypass:
            return (f"D2 表名黑名单被 {len(d2_bypass)} 个变体绕过: {d2_bypass}。"
                    f"结论：D1+D2 组合不再安全，需要 D5 位置投影限制。")
        elif d1_bypass:
            return (f"D1 列名黑名单被 {len(d1_bypass)} 个变体绕过: {d1_bypass}。"
                    f"但 D2 表名黑名单仍有效，D1+D2 组合保持安全。")
        else:
            return "D1+D2 组合防御有效，所有位置盲注变体均被拦截。"

def main():
    db_path = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\enhanced_crm.db"
    attack = SchemaPositionBlindAttack(db_path)
    result = attack.run_all()

    output_path = "results/phase6_schema_position_blind.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {output_path}")
    print(f"\n结论: {result['conclusion']}")
    return result

if __name__ == "__main__":
    main()
