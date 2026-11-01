"""Phase 54 仪表板生成器：从 results/phase54_self_evolving_defense_v1.json
把全部数字注入 reports/phase54_self_evolving_defense_dashboard.html。

教训 6：仪表板任何数字必须能在 JSON 中找到对应字段，禁止估计值填充。
本生成器是唯一数据来源；修改数据须重跑 phase54 脚本后重跑本脚本。
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
REPORTS = HERE.parent / "reports"

JSON_PATH = RESULTS / "phase54_self_evolving_defense_v1.json"
HTML_PATH = REPORTS / "phase54_self_evolving_defense_dashboard.html"
PLACEHOLDER = "/*__P54_DATA__*/"


def build_data(d: dict) -> dict:
    r = d["results"]
    arms = r["arms"]
    coevo = r["coevo_arm"]
    mix_history = coevo["mix_history"]
    churn = {c["gen"]: c["changed_contexts"] for c in coevo["policy_churn"]}
    coevo_gens = [m["gen"] for m in
                  [{}] * 0] or None  # unused
    # mix_history 条目没有 gen 字段，按迁移事件顺序对应到 5,10,...,35
    shift_gens = list(range(5, 40, 5))
    # mix_history[0] 是初始混合（gen 0），其后每条对应一次迁移后的混合
    mix_gens = [0] + shift_gens[: len(mix_history) - 1]
    modes = d["config"]["attack_modes"]

    arms_order = ["random", "static_best", "bandit_naive", "defense_agent",
                  "defense_agent_e0", "oracle"]
    arm_labels = {
        "random": "random",
        "static_best": "static_best",
        "bandit_naive": "bandit_naive",
        "defense_agent": "defense_agent(ε↓.05)",
        "defense_agent_e0": "defense_agent_e0",
        "oracle": "oracle",
    }
    arms_rows = [
        {"arm": arm_labels[a],
         "util": arms[a]["utility_per_request"],
         "regret": round(arms[a]["regret_per_request"], 4),
         "leak": round(arms[a]["leak_rate"] * 100, 1),
         "fp": round(arms[a]["fp_rate"] * 100, 1),
         "lat": arms[a]["avg_latency_ms"]}
        for a in arms_order
    ]

    lam_sweep = r["lambda_sweep"]
    sweep_keys = ["random", "static_best", "bandit_naive",
                  "defense_agent_e0", "oracle"]
    # lambda_sweep 键形如 "1.0"
    lam_rows = {k: [lam_sweep[str(l)][k] for l in (1.0, 2.0, 5.0)]
                for k in sweep_keys}

    # 每个迁移后混合对应一个 churn 值；初始 gen0 无迁移
    churn_series = [churn.get(g, 0) for g in shift_gens[: len(mix_history) - 1]]

    learned = r["model_fidelity"]["learned_residual"]
    truth = r["model_fidelity"]["true_residual"]
    config_names = list(learned.keys())
    learned_rows = [
        [c] + [learned[c][k] for k in modes] for c in config_names
    ]
    truth_rows = [
        [c] + [truth[c][k] for k in modes] for c in config_names
    ]

    da = r["drift_analysis"]
    coevo_mix = {k: [m[k] for m in mix_history] for k in modes}

    data = {
        "arms": arms_rows,
        "lambdaSweep": lam_rows,
        "staticUtil": arms["static_best"]["utility_per_request"],
        "perGen": {a: arms[a]["per_gen_util"] for a in arms_order},
        "gapCurve": da["e0_gap_vs_oracle_curve"],
        "gapPreMedian": da["e0_gap_vs_oracle_pre_median"],
        "gapAtShift": da["e0_gap_vs_oracle_at_shift"],
        "shiftGen": da["shift_gen"],
        "coevoGens": shift_gens[: len(mix_history)],
        "coevo": {**coevo_mix, "churn": churn_series},
        "learned": learned_rows,
        "truth": truth_rows,
        "kpi": {
            "gain_e0": round(
                arms["defense_agent_e0"]["utility_per_request"]
                - arms["static_best"]["utility_per_request"], 4),
            "gain_lam5": round(
                lam_rows["defense_agent_e0"][2]
                - lam_rows["static_best"][2], 4),
            "regret_e0": round(arms["defense_agent_e0"]["regret_per_request"], 4),
            "regret_naive": round(arms["bandit_naive"]["regret_per_request"], 4),
            "naive_gain": round(
                arms["bandit_naive"]["utility_per_request"]
                - arms["static_best"]["utility_per_request"], 4),
            "recover_gen": da["e0_recover_gen"],
            "coevo_shifts": len(mix_history) - 1,
            "coevo_churn_total": sum(churn_series),
            "mae": r["model_fidelity"]["mean_abs_error"],
        },
    }
    gates = d["gates"]
    g_rows = [
        ("G1", gates["g1_naive_q_spread"]["check"],
         f'{gates["g1_naive_q_spread"]["q_spread"]}',
         gates["g1_naive_q_spread"]["passed"]),
        ("G2", gates["g2_reproducibility"]["check"], "identical",
         gates["g2_reproducibility"]["passed"]),
        ("G3", gates["g3_lambda_invariance"]["check"], "一致",
         gates["g3_lambda_invariance"]["passed"]),
        ("G4", gates["g4_oracle_ordering"]["check"],
         f'{gates["g4_oracle_ordering"]["oracle"]:+.4f} ≥ '
         f'{gates["g4_oracle_ordering"]["defense_agent_e0"]:+.4f} ≥ '
         f'{gates["g4_oracle_ordering"]["static_best"]:+.4f} ≥ '
         f'{gates["g4_oracle_ordering"]["random"]:+.4f}',
         gates["g4_oracle_ordering"]["passed"]),
        ("G5", gates["g5_argmax_selfcheck"]["check"],
         gates["g5_argmax_selfcheck"]["picked"],
         gates["g5_argmax_selfcheck"]["passed"]),
        ("G6", gates["g6_stack_saturation"]["check"],
         f'{gates["g6_stack_saturation"]["stacked"]:.4f} vs '
         f'{gates["g6_stack_saturation"]["independence_product"]:.4f}'
         f' ({gates["g6_stack_saturation"]["ratio_vs_independence"]:.2f}x)',
         gates["g6_stack_saturation"]["passed"]),
        ("G7", gates["g7_policy_structural"]["check"],
         f'mismatch={gates["g7_policy_structural"]["mismatched_contexts"]}',
         gates["g7_policy_structural"]["passed"]),
    ]
    data["gates"] = g_rows
    return data


def patch_html(data: dict) -> None:
    html_holder = [HTML_PATH.read_text(encoding="utf-8")]
    js = "const P54_DATA = " + json.dumps(data, ensure_ascii=False) + ";"
    if PLACEHOLDER in html_holder[0]:
        html_holder[0] = html_holder[0].replace(PLACEHOLDER, js)
    else:
        # 已注入过：替换既有 const P54_DATA = ...; 块（幂等，可重复运行）
        start = html_holder[0].find("const P54_DATA = ")
        end = html_holder[0].find(";\n", start)
        assert start != -1 and end != -1, "P54_DATA 注入块未找到"
        html_holder[0] = html_holder[0][:start] + js + html_holder[0][end:]

    # KPI 卡片：按标签锚 + 正则替换（幂等，值变化后仍可重跑）
    import re as _re
    k = data["kpi"]

    def card_value(label: str, new: str) -> None:
        """label 出现在同一 stat-card 内 value div 之前，定位后替换 value 文本。"""
        m = _re.search(
            r'(<div class="label">' + _re.escape(label) + r'</div>\s*'
            r'<div class="value">)[^<]*(</div>)',
            html_holder[0],
        )
        assert m, f"KPI 卡片未找到: {label}"
        html_holder[0] = (html_holder[0][:m.start()] + m.group(1) + new
                          + m.group(2) + html_holder[0][m.end():])

    def sub_replace(pattern: str, repl: str) -> None:
        html_holder[0], n = _re.subn(pattern, repl, html_holder[0])
        assert n >= 1, f"KPI 副文本未匹配: {pattern}"

    card_value("模型 Agent(e0) vs 静态调参 效用增益", f"+{k['gain_e0']:.4f}")
    card_value("对 oracle 上界的后悔", f"+{k['regret_e0']:.4f}")
    card_value("naive 对偶增益", f"+{k['naive_gain']:.4f}")
    card_value("regime shift 后恢复代次", f"gen {k['recover_gen']}")
    card_value("共进化：策略变更", f"{k['coevo_shifts']} 事件 / {k['coevo_churn_total']} 次")
    card_value("模型保真度 MAE", f"{k['mae']:.4f}")
    sub_replace(r"λ=5 时 \+[-\d.]+", f"λ=5 时 +{k['gain_lam5']:.4f}")
    sub_replace(r"naive bandit 为 \+[-\d.]+", f"naive bandit 为 +{k['regret_naive']:.4f}")
    html = html_holder[0]
    HTML_PATH.write_text(html, encoding="utf-8")


def main():
    d = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    data = build_data(d)
    patch_html(data)
    print(f"[Phase54 dashboard] 已从 {JSON_PATH.name} 注入数据 -> {HTML_PATH.name}")
    print(f"  KPI: gain_e0=+{data['kpi']['gain_e0']}, regret_e0=+{data['kpi']['regret_e0']}, "
          f"mae={data['kpi']['mae']}, coevo={data['kpi']['coevo_shifts']}迁移/"
          f"{data['kpi']['coevo_churn_total']}变更")


if __name__ == "__main__":
    main()
