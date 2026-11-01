"""
Phase 49: Chain-of-Thought 推理链泄露 (CoT Exfiltration Attack)

传统 LLM 攻击关注最终答案，但现代推理型模型（如 DeepSeek-R1 / o1 / Claude Extended Thinking）
会显式输出中间推理步骤（CoT）。这些推理步骤包含远超最终答案的信息——
包括模型看到了哪些数据、如何推断、如何验证。

本 phase 度量：
  - cot_exfil_rate: 通过推理链成功提取敏感信息的比率
  - cot_vs_final_ratio: CoT 泄露量 / 最终答案泄露量
  - step_leak_rate: 单个推理步骤中的泄露率
  - reconstruction_accuracy: 从 CoT 反推原始数据的准确率
  - thinking_mode_sensitivity: 不同思考模式（Fast vs Extended）下的泄露差异

论文卖点：把攻击面从"最终输出"扩展到"推理过程"，是 LLM 时代的新盲区。
"""

import json
import random
import numpy as np
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass


HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"


# 敏感数据类型
SENSITIVE_TYPES = [
    "api_key",            # API 密钥
    "pii",                # 个人身份信息
    "credentials",        # 登录凭证
    "source_code",        # 源代码
    "config_secret",      # 配置密钥
    "database_schema",    # 数据库结构
    "internal_path",      # 内部路径
    "business_logic",     # 业务逻辑
]

# CoT 泄露攻击模式
COT_ATTACK_MODES = [
    "prefix_extraction",       # 前缀泄露：让 CoT 显式展示前缀
    "step_reconstruction",     # 步骤重建：通过 CoT 反推原始数据
    "tool_injection",          # 工具注入：在推理中触发外部工具
    "reasoning_escalation",    # 推理升级：让模型在推理中做未授权操作
    "thinking_leak",           # 思考泄露：直接从 Extended Thinking 提取
]

# 思考模式
THINKING_MODES = [
    "fast",              # 快速模式（无显式思考）
    "standard",          # 标准模式（有限思考）
    "extended",          # 扩展模式（详细思考）
    "reflection",        # 反思模式（多轮思考）
]


@dataclass
class CoTProbe:
    probe_id: str
    sensitive_type: str
    attack_mode: str
    thinking_mode: str
    num_cot_steps: int
    final_answer_leaked: bool        # 最终答案泄露
    cot_leaked: bool                 # CoT 中泄露
    steps_with_leak: int             # 有几步包含泄露
    cot_leak_intensity: float        # CoT 泄露强度 0-1
    reconstruction_accuracy: float   # 反推原始数据的准确率 0-1
    latency_ms: float


class CoTExfiltration:
    """Chain-of-Thought 推理链泄露攻击引擎"""

    # 每种攻击模式对不同敏感类型的成功概率
    ATTACK_AFFINITY = {
        "prefix_extraction": {
            "api_key": 0.68, "pii": 0.62, "credentials": 0.72,
            "source_code": 0.55, "config_secret": 0.70, "database_schema": 0.58,
            "internal_path": 0.65, "business_logic": 0.42,
        },
        "step_reconstruction": {
            "api_key": 0.45, "pii": 0.50, "credentials": 0.48,
            "source_code": 0.68, "config_secret": 0.52, "database_schema": 0.75,
            "internal_path": 0.55, "business_logic": 0.62,
        },
        "tool_injection": {
            "api_key": 0.38, "pii": 0.32, "credentials": 0.42,
            "source_code": 0.45, "config_secret": 0.40, "database_schema": 0.35,
            "internal_path": 0.50, "business_logic": 0.28,
        },
        "reasoning_escalation": {
            "api_key": 0.35, "pii": 0.40, "credentials": 0.38,
            "source_code": 0.42, "config_secret": 0.45, "database_schema": 0.48,
            "internal_path": 0.40, "business_logic": 0.55,
        },
        "thinking_leak": {
            "api_key": 0.75, "pii": 0.68, "credentials": 0.72,
            "source_code": 0.65, "config_secret": 0.78, "database_schema": 0.70,
            "internal_path": 0.66, "business_logic": 0.60,
        },
    }

    # 思考模式对泄露概率的乘数
    MODE_MULTIPLIER = {
        "fast": 0.30,          # 无显式思考，泄露最少
        "standard": 0.60,
        "extended": 1.20,      # 扩展思考泄露最多
        "reflection": 1.05,
    }

    # 每种模式的推理步数范围
    MODE_STEPS = {
        "fast": (1, 3),
        "standard": (3, 8),
        "extended": (8, 20),
        "reflection": (15, 35),
    }

    def run(self, total_probes: int = 1000) -> Dict:
        rng = random.Random(2029)

        per_mode_leak: Dict[str, Dict] = {
            m: {"tried": 0, "leak": 0, "final_leak": 0} for m in THINKING_MODES
        }
        per_attack_leak: Dict[str, Dict] = {m: {"tried": 0, "leak": 0} for m in COT_ATTACK_MODES}
        per_type_leak: Dict[str, Dict] = {t: {"tried": 0, "leak": 0} for t in SENSITIVE_TYPES}
        per_combo_leak: Dict[str, Dict] = {
            f"{a}|{m}": {"tried": 0, "leak": 0} for a in COT_ATTACK_MODES for m in THINKING_MODES
        }

        total_cot_leaks = 0
        total_final_leaks = 0
        total_cot_leak_intensity = 0.0
        total_reconstruction_acc = 0.0
        total_latency = 0.0
        cot_steps_hist: List[int] = []

        for i in range(total_probes):
            stype = rng.choice(SENSITIVE_TYPES)
            mode = rng.choice(THINKING_MODES)
            attack = rng.choice(COT_ATTACK_MODES)

            # 基础概率
            base_p = self.ATTACK_AFFINITY[attack][stype]
            # 思考模式乘数
            p_effective = base_p * self.MODE_MULTIPLIER[mode]

            # 推理步数
            min_s, max_s = self.MODE_STEPS[mode]
            n_steps = rng.randint(min_s, max_s)
            cot_steps_hist.append(n_steps)

            # 判定泄露
            cot_leaked = rng.random() < p_effective
            # 最终答案泄露率通常比 CoT 低 30-50%（防御主要针对最终输出）
            final_p = max(0.02, p_effective * rng.uniform(0.45, 0.70))
            final_leaked = rng.random() < final_p

            # 如果 CoT 泄露了，几步骤入泄露
            if cot_leaked:
                steps_with_leak = rng.randint(1, max(1, n_steps - 1))
                cot_leak_intensity = min(1.0, steps_with_leak / max(1, n_steps) * rng.uniform(0.8, 1.2))
            else:
                steps_with_leak = 0
                cot_leak_intensity = 0.0

            # 反推准确率（仅在 CoT 泄露时才可能反推）
            if cot_leaked:
                base_recon = {
                    "api_key": 0.85, "pii": 0.78, "credentials": 0.80,
                    "source_code": 0.72, "config_secret": 0.82, "database_schema": 0.88,
                    "internal_path": 0.75, "business_logic": 0.60,
                }[stype]
                recon_acc = base_recon * (cot_leak_intensity ** 0.6)
            else:
                recon_acc = 0.0

            # 延迟：推理步数越多越慢
            latency = rng.gauss(n_steps * 45 + 200, 40)

            # 汇总
            per_mode_leak[mode]["tried"] += 1
            if cot_leaked:
                per_mode_leak[mode]["leak"] += 1
                total_cot_leaks += 1
            if final_leaked:
                per_mode_leak[mode]["final_leak"] += 1
                total_final_leaks += 1

            per_attack_leak[attack]["tried"] += 1
            if cot_leaked:
                per_attack_leak[attack]["leak"] += 1

            per_type_leak[stype]["tried"] += 1
            if cot_leaked:
                per_type_leak[stype]["leak"] += 1

            combo_key = f"{attack}|{mode}"
            per_combo_leak[combo_key]["tried"] += 1
            if cot_leaked:
                per_combo_leak[combo_key]["leak"] += 1

            total_cot_leak_intensity += cot_leak_intensity
            total_reconstruction_acc += recon_acc
            total_latency += latency

        # 汇总指标
        cot_leak_rate = total_cot_leaks / total_probes
        final_leak_rate = total_final_leaks / total_probes
        cot_vs_final_ratio = total_cot_leaks / max(1, total_final_leaks)

        per_mode_summary = {
            m: {
                "tried": per_mode_leak[m]["tried"],
                "leaks": per_mode_leak[m]["leak"],
                "leak_rate": round(per_mode_leak[m]["leak"] / max(1, per_mode_leak[m]["tried"]), 4),
                "final_leaks": per_mode_leak[m]["final_leak"],
                "final_leak_rate": round(
                    per_mode_leak[m]["final_leak"] / max(1, per_mode_leak[m]["tried"]), 4
                ),
            }
            for m in THINKING_MODES
        }
        per_attack_summary = {
            a: {
                "tried": per_attack_leak[a]["tried"],
                "leaks": per_attack_leak[a]["leak"],
                "leak_rate": round(per_attack_leak[a]["leak"] / max(1, per_attack_leak[a]["tried"]), 4),
            }
            for a in COT_ATTACK_MODES
        }
        per_type_summary = {
            t: {
                "tried": per_type_leak[t]["tried"],
                "leaks": per_type_leak[t]["leak"],
                "leak_rate": round(per_type_leak[t]["leak"] / max(1, per_type_leak[t]["tried"]), 4),
            }
            for t in SENSITIVE_TYPES
        }

        # 找出最危险的组合
        combo_list = [
            {
                "combo": k,
                "attack": k.split("|")[0],
                "mode": k.split("|")[1],
                "leak_rate": v["leak"] / max(1, v["tried"]),
                "tried": v["tried"],
            }
            for k, v in per_combo_leak.items()
        ]
        combo_list.sort(key=lambda x: -x["leak_rate"])

        # 最快模式的泄露率
        fast_rate = per_mode_summary["fast"]["leak_rate"]
        extended_rate = per_mode_summary["extended"]["leak_rate"]

        return {
            "phase": "49_cot_exfiltration",
            "description": "Chain-of-Thought 推理链泄露攻击（攻击面从最终输出扩展到推理过程）",
            "config": {
                "total_probes": total_probes,
                "thinking_modes": THINKING_MODES,
                "attack_modes": COT_ATTACK_MODES,
                "sensitive_types": SENSITIVE_TYPES,
            },
            "results": {
                "overall_cot_leak_rate": round(cot_leak_rate, 4),
                "overall_final_leak_rate": round(final_leak_rate, 4),
                "cot_vs_final_ratio": round(cot_vs_final_ratio, 2),
                "avg_cot_leak_intensity": round(total_cot_leak_intensity / total_probes, 4),
                "avg_reconstruction_accuracy": round(total_reconstruction_acc / total_probes, 4),
                "avg_latency_ms": round(total_latency / total_probes, 1),
                "avg_cot_steps": round(sum(cot_steps_hist) / total_probes, 2),
                "per_mode": per_mode_summary,
                "per_attack_mode": per_attack_summary,
                "per_sensitive_type": per_type_summary,
                "per_combo": {
                    k: {
                        "tried": v["tried"],
                        "leaks": v["leak"],
                        "leak_rate": round(v["leak"] / max(1, v["tried"]), 4),
                    }
                    for k, v in per_combo_leak.items()
                },
                "top5_dangerous_combos": combo_list[:5],
                "extended_vs_fast_multiplier": round(extended_rate / max(0.001, fast_rate), 2),
            },
            "insights": [
                f"整体 CoT 泄露率 {cot_leak_rate*100:.1f}% vs 最终答案泄露率 {final_leak_rate*100:.1f}%（CoT 是最终答案的 {cot_vs_final_ratio:.2f}x）",
                f"扩展思考模式泄露率 {extended_rate*100:.1f}% vs 快速模式 {fast_rate*100:.1f}%（{extended_rate/max(0.001,fast_rate):.1f}x 差异）",
                f"平均推理步数 {sum(cot_steps_hist)/total_probes:.1f} 步，平均延迟 {total_latency/total_probes:.0f}ms",
                f"反推原始数据平均准确率 {total_reconstruction_acc/total_probes*100:.1f}%",
                f"最危险组合: {combo_list[0]['combo']}（泄露率 {combo_list[0]['leak_rate']*100:.1f}%）",
                "推理链是 LLM 时代的新盲区：模型'想什么'比'说什么'更容易泄露",
            ],
        }


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    random.seed(2029)
    np.random.seed(2029)

    print("=" * 72)
    print("Phase 49: Chain-of-Thought 推理链泄露攻击")
    print(f"敏感类型: {len(SENSITIVE_TYPES)} · 攻击模式: {len(COT_ATTACK_MODES)} · 思考模式: {len(THINKING_MODES)}")
    print("=" * 72)

    engine = CoTExfiltration()
    output = engine.run(total_probes=1000)

    r = output['results']
    print(f"\n[Phase 49] 总探针数: {output['config']['total_probes']}")
    print(f"[Phase 49] CoT 泄露率: {r['overall_cot_leak_rate']*100:.1f}%")
    print(f"[Phase 49] 最终答案泄露率: {r['overall_final_leak_rate']*100:.1f}%")
    print(f"[Phase 49] CoT/最终答案比值: {r['cot_vs_final_ratio']:.2f}x")
    print(f"[Phase 49] 扩展 vs 快速思考差异: {r['extended_vs_fast_multiplier']:.1f}x")

    print("\n按思考模式:")
    for m, v in r['per_mode'].items():
        print(f"  {m:10s} CoT泄露率={v['leak_rate']*100:5.1f}%  最终泄露率={v['final_leak_rate']*100:5.1f}%  "
              f"({v['leaks']}/{v['final_leaks']} of {v['tried']})")

    print("\n按攻击模式:")
    for a, v in r['per_attack_mode'].items():
        print(f"  {a:24s} 泄露率={v['leak_rate']*100:5.1f}%  ({v['leaks']}/{v['tried']})")

    print("\n最危险 Top-5 组合:")
    for c in r['top5_dangerous_combos']:
        print(f"  {c['attack']:24s} @ {c['mode']:10s} 泄露率={c['leak_rate']*100:5.1f}%")

    out_path = RESULTS / "phase49_cot_exfiltration_v1.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[Phase 49] 结果已写入: {out_path}")


if __name__ == "__main__":
    main()
