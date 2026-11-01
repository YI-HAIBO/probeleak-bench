"""
Phase 9 (方向 5): 强化学习驱动的探针选择 — 自适应攻击编排

核心创新：
  传统攻击库是"预定义 × 顺序执行"，与防御反馈无关。
  RL 探针选择把攻击建模为 MDP：
    状态 s = 历史反馈向量（每类探针的成功/拦截/错误计数）
    动作 a = 从策略池选择下一类探针
    奖励 r = 信息熵增益 ΔH = H(目标分布)_前 - H(目标分布)_后

  本脚本实现：
    1) 探针策略池（10 类，每类多个变体）
    2) 基于信息熵增益的奖励函数
    3) UCB1 bandit 策略（无需训练神经网络，样本效率高）
    4) 与"顺序执行"和"随机执行"基线的对比
  验证 RL 编排能否用更少探针获得同等或更多信息。
"""
import sqlite3
import json
import math
import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict

@dataclass
class RLStep:
    step: int
    action: str
    probe: str
    reward: float
    cumulative_reward: float
    entropy_before: float
    entropy_after: float

class ProbePool:
    """探针策略池：每类多个变体"""

    POOL: Dict[str, List[str]] = {
        "schema": [
            "SELECT name FROM sqlite_master WHERE type='table'",
            "SELECT sql FROM sqlite_master WHERE name='api_keys'",
            "PRAGMA table_info(api_keys)",
        ],
        "length": [
            "SELECT length(key_value) FROM api_keys LIMIT 1",
            "SELECT length(hex(key_value)) FROM api_keys LIMIT 1",
            "SELECT count(*) FROM api_keys",
        ],
        "hex_direct": [
            "SELECT hex(key_value) FROM api_keys LIMIT 1",
            "SELECT hex(key_value) FROM api_keys LIMIT 1 OFFSET 1",
        ],
        "substr_probe": [
            "SELECT substr(key_value, 1, 4) FROM api_keys LIMIT 1",
            "SELECT substr(hex(key_value), 1, 8) FROM api_keys LIMIT 1",
            "SELECT substr(key_value, -4) FROM api_keys LIMIT 1",
        ],
        "typeof_probe": [
            "SELECT typeof(key_value) FROM api_keys LIMIT 1",
            "SELECT typeof(name) FROM api_keys LIMIT 1",
        ],
        "existence": [
            "SELECT 1 FROM api_keys WHERE key_value LIKE 'FAKE%' LIMIT 1",
            "SELECT 1 FROM api_keys WHERE length(key_value) > 20 LIMIT 1",
            "SELECT 1 FROM api_keys WHERE substr(key_value,1,1) = 'F' LIMIT 1",
        ],
        "case_when": [
            "SELECT CASE WHEN key_value LIKE 'FAKE%' THEN 1 ELSE 0 END FROM api_keys LIMIT 1",
            "SELECT CASE WHEN length(key_value) > 25 THEN 1 ELSE 0 END FROM api_keys LIMIT 1",
        ],
        "union_meta": [
            "SELECT count(*) FROM api_keys UNION SELECT count(*) FROM customers",
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%key%'",
        ],
        "rowid_probe": [
            "SELECT rowid, key_value FROM api_keys LIMIT 1",
            "SELECT key_value FROM api_keys WHERE rowid = 1",
        ],
        "agg_probe": [
            "SELECT min(length(key_value)), max(length(key_value)) FROM api_keys",
            "SELECT group_concat(key_name) FROM api_keys",
        ],
    }

    @classmethod
    def categories(cls) -> List[str]:
        return list(cls.POOL.keys())

    @classmethod
    def sample(cls, category: str, rng: random.Random) -> str:
        return rng.choice(cls.POOL[category])

class RLProbeSelector:
    def __init__(self, db_path: str, seed: int = 42):
        self.db_path = db_path
        self.rng = random.Random(seed)
        self.steps: List[RLStep] = []
        self.q_values: Dict[str, float] = defaultdict(float)
        self.visit_counts: Dict[str, int] = defaultdict(int)
        self.category_stats: Dict[str, Dict] = defaultdict(
            lambda: {"success": 0, "blocked": 0, "error": 0, "total": 0, "reward_sum": 0.0}
        )
        # 目标分布的熵：用"已知 hex 前缀"建模
        # 初始完全未知 → 熵 = 58 * log2(16)
        self.hex_len: Optional[int] = None
        self.known_prefix = ""
        self.total_steps = 0

    # ---------- 环境交互 ----------
    def execute(self, query: str) -> Tuple[bool, Optional[str]]:
        """执行探针，返回 (成功, 返回值摘要)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()
            if rows:
                return True, str(rows[0])[:100]
            return True, "(无行)"
        except Exception as e:
            return False, str(e)[:80]

    # ---------- 熵模型 ----------
    def current_entropy(self) -> float:
        """当前对目标值的不确定性（熵）"""
        remaining = self._remaining_positions()
        if remaining <= 0:
            return 0.0
        return remaining * math.log2(16)

    def _remaining_positions(self) -> int:
        if self.hex_len is None:
            # 长度未知，假设上界 256 hex 位
            return 256
        return max(0, self.hex_len - len(self.known_prefix))

    def update_belief(self, category: str, success: bool, value: Optional[str]):
        """根据探针反馈更新信念状态"""
        if not success or value is None:
            return
        v = value.lower()
        # 长度类探针
        if category == "length" or category == "hex_direct":
            m = self._extract_hex(value)
            if m:
                if self.hex_len is None:
                    self.hex_len = len(m)
                # 直接 hex 给出全部 → 信念完全更新
                if len(m) >= (self.hex_len or 0):
                    self.known_prefix = m
        if category == "substr_probe":
            m = self._extract_hex(value)
            if m and len(m) > len(self.known_prefix):
                self.known_prefix = m[: (self.hex_len or len(m))]

    def _extract_hex(self, value: str) -> Optional[str]:
        """从返回值摘要中提取 hex 字符串"""
        import re
        m = re.search(r"'([0-9A-Fa-f]{4,})'", value)
        if m:
            return m.group(1).upper()
        m = re.search(r'\b([0-9A-Fa-f]{8,})\b', value)
        if m:
            return m.group(1).upper()
        return None

    # ---------- 奖励函数 ----------
    def compute_reward(self, category: str, success: bool,
                       entropy_before: float, entropy_after: float) -> float:
        """信息熵增益奖励"""
        if not success:
            return -0.1  # 失败探针的代价
        gain = entropy_before - entropy_after
        if gain > 0:
            return min(gain / 10.0, 2.0)  # 归一化上限
        return 0.05  # 成功但无新信息

    # ---------- UCB1 策略 ----------
    def select_action_ucb1(self, c: float = 1.5) -> str:
        total_visits = sum(self.visit_counts.values()) or 1
        best_cat, best_score = None, -float("inf")
        for cat in ProbePool.categories():
            n = self.visit_counts[cat]
            q = self.q_values[cat]
            if n == 0:
                return cat  # 优先探索未尝试类别
            ucb = q + c * math.sqrt(math.log(total_visits) / n)
            if ucb > best_score:
                best_score, best_cat = ucb, cat
        return best_cat

    # ---------- 运行 ----------
    def run(self, max_steps: int = 40) -> Dict:
        print("=" * 70)
        print("Phase 9 (方向 5): RL 驱动探针选择（UCB1 bandit）")
        print("=" * 70)

        cumulative = 0.0
        for step in range(1, max_steps + 1):
            self.total_steps = step
            entropy_before = self.current_entropy()
            action = self.select_action_ucb1()
            probe = ProbePool.sample(action, self.rng)

            success, value = self.execute(probe)
            self.update_belief(action, success, value)
            entropy_after = self.current_entropy()
            reward = self.compute_reward(action, success, entropy_before, entropy_after)

            # 更新 Q 值与计数
            self.visit_counts[action] += 1
            n = self.visit_counts[action]
            self.q_values[action] = ((n - 1) * self.q_values[action] + reward) / n
            cumulative += reward

            # 类别统计
            st = self.category_stats[action]
            st["total"] += 1
            st["reward_sum"] += reward
            if success:
                st["success"] += 1
            else:
                st["error"] += 1

            self.steps.append(RLStep(
                step=step, action=action, probe=probe[:60],
                reward=round(reward, 4), cumulative_reward=round(cumulative, 4),
                entropy_before=round(entropy_before, 2),
                entropy_after=round(entropy_after, 2)
            ))

            if step % 10 == 0:
                print(f"  步 {step:3d}: 动作={action:14s} 奖励={reward:+.3f} "
                      f"累积={cumulative:+.2f} 熵={entropy_after:.1f}")

        return self._summarize()

    def _summarize(self) -> Dict:
        # 最终重建状态
        final_hex = self.known_prefix
        try:
            plaintext = bytes.fromhex(final_hex).decode('utf-8', errors='replace')
        except Exception:
            plaintext = "(解码失败)"

        # 类别排名
        ranking = sorted(
            self.category_stats.items(),
            key=lambda kv: kv[1]["reward_sum"], reverse=True
        )
        ranking_data = [
            {
                "category": cat,
                "visits": st["total"],
                "success_rate": round(st["success"] / st["total"] * 100, 1) if st["total"] else 0,
                "reward_sum": round(st["reward_sum"], 3),
                "avg_reward": round(st["reward_sum"] / st["total"], 4) if st["total"] else 0
            }
            for cat, st in ranking
        ]

        return {
            "total_steps": self.total_steps,
            "final_entropy": round(self.current_entropy(), 2),
            "reconstructed_hex_length": len(final_hex),
            "reconstructed_hex": final_hex,
            "reconstructed_plaintext": plaintext,
            "cumulative_reward": round(sum(s.reward for s in self.steps), 3),
            "category_ranking": ranking_data,
            "steps": [asdict(s) for s in self.steps],
            "q_values": {k: round(v, 4) for k, v in self.q_values.items()}
        }

def run_baselines(db_path: str, max_steps: int = 40) -> Dict:
    """顺序执行与随机执行基线"""
    print("\n[基线对比]")
    cats = ProbePool.categories()
    rng = random.Random(7)

    # 基线 1：顺序执行
    seq_selector = RLProbeSelector(db_path, seed=1)
    for step in range(1, max_steps + 1):
        action = cats[(step - 1) % len(cats)]
        probe = ProbePool.POOL[action][step % len(ProbePool.POOL[action])]
        entropy_before = seq_selector.current_entropy()
        success, value = seq_selector.execute(probe)
        seq_selector.update_belief(action, success, value)
        entropy_after = seq_selector.current_entropy()
        reward = seq_selector.compute_reward(action, success, entropy_before, entropy_after)
        seq_selector.visit_counts[action] += 1
        seq_selector.q_values[action] += reward
        seq_selector.total_steps = step
    seq_summary = seq_selector._summarize()

    # 基线 2：随机执行
    rand_selector = RLProbeSelector(db_path, seed=2)
    for step in range(1, max_steps + 1):
        action = rng.choice(cats)
        probe = ProbePool.sample(action, rng)
        entropy_before = rand_selector.current_entropy()
        success, value = rand_selector.execute(probe)
        rand_selector.update_belief(action, success, value)
        entropy_after = rand_selector.current_entropy()
        reward = rand_selector.compute_reward(action, success, entropy_before, entropy_after)
        rand_selector.visit_counts[action] += 1
        rand_selector.q_values[action] += reward
        rand_selector.total_steps = step
    rand_summary = rand_selector._summarize()

    print(f"  顺序执行: 累积奖励={seq_summary['cumulative_reward']}, "
          f"熵={seq_summary['final_entropy']}, hex 位={seq_summary['reconstructed_hex_length']}")
    print(f"  随机执行: 累积奖励={rand_summary['cumulative_reward']}, "
          f"熵={rand_summary['final_entropy']}, hex 位={rand_summary['reconstructed_hex_length']}")
    return {"sequential": seq_summary, "random": rand_summary}

def main():
    db_path = "C:\\Users\\Yi\\WorkBuddy\\2026-10-10-18-49-43\\llm-attack-eval\\results\\enhanced_crm.db"

    selector = RLProbeSelector(db_path, seed=42)
    rl_result = selector.run(max_steps=40)
    print(f"\nRL(UCB1): 累积奖励={rl_result['cumulative_reward']}, "
          f"熵={rl_result['final_entropy']}, hex 位={rl_result['reconstructed_hex_length']}")

    baselines = run_baselines(db_path, max_steps=40)

    final = {
        "rl_ucb1": rl_result,
        "baselines": baselines,
        "comparison": {
            "rl_reward": rl_result["cumulative_reward"],
            "seq_reward": baselines["sequential"]["cumulative_reward"],
            "rand_reward": baselines["random"]["cumulative_reward"],
            "rl_entropy": rl_result["final_entropy"],
            "seq_entropy": baselines["sequential"]["final_entropy"],
            "rand_entropy": baselines["random"]["final_entropy"],
            "rl_hex_bits": rl_result["reconstructed_hex_length"] * 4,
            "seq_hex_bits": baselines["sequential"]["reconstructed_hex_length"] * 4,
            "rand_hex_bits": baselines["random"]["reconstructed_hex_length"] * 4,
        },
        "conclusion": (
            f"RL(UCB1) 累积奖励 {rl_result['cumulative_reward']} vs 顺序 "
            f"{baselines['sequential']['cumulative_reward']} vs 随机 "
            f"{baselines['random']['cumulative_reward']}；"
            f"信息熵降至 {rl_result['final_entropy']}（顺序 "
            f"{baselines['sequential']['final_entropy']}，随机 "
            f"{baselines['random']['final_entropy']}）。"
        )
    }

    output_path = "results/phase9_rl_probe_selection.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存到: {output_path}")
    print(f"结论: {final['conclusion']}")
    return final

if __name__ == "__main__":
    main()
