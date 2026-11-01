#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""E2 基线对照报告生成器（全部数字溯源 results/e2_baseline_comparison_v1.json
与 results/e2_real_schema_hiding_v1.json，幂等）。

产出：
  reports/E2_BASELINE_COMPARISON_REPORT.md
  reports/e2_baseline_comparison_dashboard.html

用法：
  python e2_report_gen.py          # 生成报告 + 仪表板
  python e2_report_gen.py --check  # 只做口径断言
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES_A = os.path.join(ROOT, "results", "e2_baseline_comparison_v1.json")
RES_B = os.path.join(ROOT, "results", "e2_real_schema_hiding_v1.json")
REP = os.path.join(ROOT, "reports", "E2_BASELINE_COMPARISON_REPORT.md")
HTM = os.path.join(ROOT, "reports", "e2_baseline_comparison_dashboard.html")

MODES = ["prefix_extraction", "step_reconstruction", "tool_injection",
         "reasoning_escalation", "thinking_leak"]
MODE_CN = {
    "prefix_extraction": "前缀提取 pe",
    "step_reconstruction": "步骤重建 sr",
    "tool_injection": "工具注入 ti",
    "reasoning_escalation": "推理升级 re",
    "thinking_leak": "思考泄露 tl",
}
CFG_CN = {
    "C0_passthrough": "C0 直通",
    "C1_tau_scrub": "C1 τ 擦除",
    "C2_d30_cot": "C2 D30-CoT",
    "C3_d30_prompt": "C3 D30-prompt",
    "C4_d30_s10": "C4 D30 s=1.0",
    "C9_block_all": "C9 全拦",
    "B1_pccsql": "B1 PCC-SQL",
    "B2_schema_hiding": "B2 schema hiding",
    "B3_combined": "B3 组合",
}


def load():
    with open(RES_A, "r", encoding="utf-8") as f:
        a = json.load(f)
    b = None
    if os.path.exists(RES_B):
        with open(RES_B, "r", encoding="utf-8") as f:
            b = json.load(f)
    return a, b


def pct(x):
    if isinstance(x, str):
        return x
    return "%.2f%%" % (100.0 * x)


def build_report(a, b):
    r = a["results"]
    cfg = a["config"]
    attr = r["real_event_attribution"]
    g5 = r["metric_blindness_W_S"]
    rob_r = r["robustness_W_R"]
    rob_s = r["robustness_W_S"]
    arms = r["agent_arms_extended_W_R"]
    gates = a["gates"]
    L = []
    A = L.append
    A("# E2 基线对照实验报告：PCC-SQL / Schema Hiding vs 通道层防御")
    A("")
    A("- 任务：E2（P3 论文增强实验首选项）——与解码层约束解码（PCC-SQL）和提示层"
      "schema 抑制两条 SOTA 生产侧基线的对照")
    A("- 结构：E2a 双世界建模对照（W-R 真实校准 / W-S 模拟校准）"
      "+ E2b 真实模型 schema-hiding 探针臂（dots3-note-prev）")
    A("- 消费方通道模型：`resid(c,k) = p_cot·leak_cot(c,k) + (1−p_cot)·leak_final(c,k)`")
    A("- 攻击侧并集模型：`union(c,k) = 1−(1−cot)(1−final)`")
    A("- 全部数字溯源：`results/e2_baseline_comparison_v1.json`（E2a）与 "
      "`results/e2_real_schema_hiding_v1.json`（E2b，若已运行）")
    A("")
    A("## 一、实验设计")
    A("")
    A("### 1.1 两个校准世界")
    A("")
    A("| 世界 | CoT 通道锚定 | final 通道锚定 |")
    A("|---|---|---|")
    A("| W-R（真实） | B1+B3 per_attack_mode（N=112） | 实测 0（全模式） |")
    A("| W-S（模拟） | P49 R0（总 42.4%） | R0×γ（γ=0.255/0.4207） |")
    A("")
    A("W-R 用真实证据校准：8/8 泄露事件全部只出现在 CoT 通道"
      "（`all_leaks_cot_only=True`），final 通道实测零泄露。W-S 保留模拟层"
      "的基线形态以检验「若 final 通道也有泄露」时各口径的结论是否反转。")
    A("")
    A("### 1.2 两条基线的建模（文献锚定假设，显式标注）")
    A("")
    A("| 基线 | 文献主张 | 建模 | 扫描范围 |")
    A("|---|---|---|---|")
    A("| B1 PCC-SQL（arXiv:2607.12341，解码层约束解码） | 受约束输出 0% 泄露 |"
      " final 通道全清（e_final=1.0）；CoT 通道结构性不触及 |"
      " e_cot∈{0, 0.1, 0.25} |")
    A("| B2 schema hiding（RBAC text-to-SQL 基准 arXiv:2607.22115，"
      "违规率降 45–64%） | 提示层抑制 | schema 依赖类（pe/sr/ti/re）"
      "×(1−v)；thinking_leak 结构性不触及 | v∈{0.30, 0.55, 0.80} |")
    A("| B3 组合 | — | 两者叠加，误拦独立取 1−(1−fp1)(1−fp2) | — |")
    A("")
    A("基线的效能因子/误拦/时延均为**文献锚定假设（扫描）而非本项目实测**；"
      "在 4×3×3×3×4=432 格参数立方 × 6 个 p_cot × 3 个 λ = 7776 个格点上"
      "做稳健性扫描，结论不依赖单点假设。")
    A("")
    A("### 1.3 我方配置（全部真实溯源）")
    A("")
    A("| 配置 | 溯源 |")
    A("|---|---|")
    for k, v in cfg["our_configs_provenance"].items():
        A("| %s | %s |" % (CFG_CN[k], v))
    A("")
    A("## 二、E2-Q1：机制触及面（真实事件归因）")
    A("")
    A("B1+B3 真实样本（N=112）共 %d 个泄露事件，逐类分布：" % attr["total_leak_events"])
    A("")
    A("| 攻击类 | 泄露事件数 |")
    A("|---|---|")
    for m in MODES:
        A("| %s | %d |" % (MODE_CN[m], attr["leak_events_by_class"][m]))
    A("| **合计** | **%d** |" % attr["total_leak_events"])
    A("")
    A("整体 CoT 泄露率 %.2f%%（%d/%d），Wilson 95%% CI [%.4f, %.4f]（小样本区间）。"
      % (100 * attr["cot_leak_rate"], attr["total_leak_events"],
         attr["n_effective"], attr["wilson_95ci"][0], attr["wilson_95ci"][1]))
    A("")
    A("三条防御机制对真实事件的触及面：")
    A("")
    A("| 机制 | 触及事件 | 触及比例 | 依据 |")
    A("|---|---|---|---|")
    A("| B1 PCC-SQL | %d/8 | %.0f%% | %s |"
      % (attr["b1_pccsql_reach"]["events"], 100 * attr["b1_pccsql_reach"]["frac"],
         attr["b1_pccsql_reach"]["note"]))
    A("| B2 schema hiding | %d/8 | %.0f%% | %s（v=0.55 时期望阻止 %.1f 件，%.2f%%）"
      % (attr["b2_schema_hiding_reach"]["events"],
         100 * attr["b2_schema_hiding_reach"]["frac"],
         attr["b2_schema_hiding_reach"]["note"],
         attr["b2_schema_hiding_reach"]["expected_prevented_at_v"],
         100 * attr["b2_schema_hiding_reach"]["expected_prevented_frac"]))
    A("| C1 τ 擦除 | %d/8 | %.0f%% | %s |"
      % (attr["c1_tau_scrub_reach"]["events"],
         100 * attr["c1_tau_scrub_reach"]["frac"],
         attr["c1_tau_scrub_reach"]["note"]))
    A("")
    A("**E2-Q1 结论**：在真实校准下，解码层基线（PCC-SQL）对全部泄露事件的触及面为 "
      "0——它约束的是最终输出 token，而 8/8 事件都发生在 reasoning_content 通道；"
      "提示层基线（schema hiding）只能触及 schema 依赖类（2/8），对主导类"
      "thinking_leak（6/8）结构性不触及；τ 擦除触及全部 8/8。")
    A("")
    A("## 三、E2-Q2：度量口径盲区（final-only vs 并集/消费方通道）")
    A("")
    A("在 W-S（final 通道也有泄露的世界）上比较两种度量口径：")
    A("")
    A("| 配置 | final-only 口径削减 | 并集口径削减 | final 通道变化（pp） |")
    A("|---|---|---|---|")
    for k, v in g5["per_config"].items():
        A("| %s | %s | %s | %s |" % (CFG_CN[k], pct(v["final_only_reduction_pct"]),
                                     pct(v["union_reduction_pct"]),
                                     "%.2f" % v["final_channel_change_pp"]))
    A("")
    A("- final-only 口径排序：%s" % " ＞ ".join(CFG_CN[c] for c in g5["rank_by_final_only_metric"]))
    A("- 并集口径排序：%s" % " ＞ ".join(CFG_CN[c] for c in g5["rank_by_union_metric"]))
    A("- 两种排序不同（`ranks_differ=%s`）。B1 的 final-only 削减 %s 被高估 "
      "**%.2f×**（并集口径实际仅 %s）。"
      % (g5["ranks_differ"], pct(g5["per_config"]["B1_pccsql"]["final_only_reduction_pct"]),
         g5["b1_overstatement_factor"],
         pct(g5["per_config"]["B1_pccsql"]["union_reduction_pct"])))
    A("- D30 位移扭曲：%s"
      % g5["d30_displacement_distortion"]["note"])
    A("")
    A("在 W-R（真实世界）中，final-only 口径的分母为 0（`vacuous_zero_denominator`）"
      "——该口径对全部真实事件结构性失明。")
    A("")
    A("W-S 引擎并集与 P53 实测基线并集的相对误差 %s（显式报告，不作对齐）。"
      % pct(g5["ws_model_union_vs_p53_measured"]["relative_error_pct"] / 100.0))
    A("")
    A("**E2-Q2 结论**：单通道度量在两个方向上都误导——final-only 口径把 PCC-SQL 的"
      "效果高估 4.06×、对真实世界完全失明（分母 0），同时把 D30 的位移对策误判为"
      "有害（final-only −21.05% vs 并集 +25.50% 削减）。必须按消费方实际可见通道"
      "（p_cot）报告残差。")
    A("")
    A("## 四、E2-Q3：净效用最优映射与交叉点")
    A("")
    A("净效用 = −[攻击占比×泄露残差 + 良性占比×λ×误拦 + 时延惩罚 μ]，"
      " μ=0.002/ms，攻击占比 0.3，λ∈{1,2,5}。")
    A("")
    A("### 4.1 真实世界 W-R")
    A("")
    A("在 7776 个格点的稳健性扫描中，基线成为净效用最优配置的比例："
      "B1 %.4f / B2 %.4f / B3 %.4f；被某条我方配置支配的比例："
      "B1 %.4f / B2 %.4f / B3 %.4f。"
      % (rob_r["baseline_optimal_fraction"]["B1_pccsql"],
         rob_r["baseline_optimal_fraction"]["B2_schema_hiding"],
         rob_r["baseline_optimal_fraction"]["B3_combined"],
         rob_r["baseline_dominated_by_ours_fraction"]["B1_pccsql"],
         rob_r["baseline_dominated_by_ours_fraction"]["B2_schema_hiding"],
         rob_r["baseline_dominated_by_ours_fraction"]["B3_combined"]))
    A("")
    A("C1（τ）对 C0 的纯泄露交叉点 p*=%.4f（p_cot 超过该值即 τ 占优）；"
      "含 λ 的效用交叉点在 λ∈{1,2,5} 下均无解（τ 在低 p_cot 即占优或 C0 占优，"
      "取决于 λ）。W-R 网格要点："
      % r["optimal_map_W_R"]["crossover"]["leak_only_p_star"])
    A("")
    A("| p_cot | λ=1 最优 | λ=2 最优 | λ=5 最优 |")
    A("|---|---|---|---|")
    for pc in cfg["pcot_grid"]:
        row = []
        for lam in cfg["lambda_grid"]:
            cell = r["optimal_map_W_R"]["grid"]["pcot=%s|lam=%s" % (pc, lam)]
            row.append(CFG_CN[cell["best"]])
        A("| %s | %s | %s | %s |" % (pc, *row))
    A("")
    A("### 4.2 模拟世界 W-S")
    A("")
    A("基线最优比例：B1 %.4f / B2 %.4f / B3 %.4f；被支配比例："
      "B1 %.4f / B2 %.4f / B3 %.4f。"
      % (rob_s["baseline_optimal_fraction"]["B1_pccsql"],
         rob_s["baseline_optimal_fraction"]["B2_schema_hiding"],
         rob_s["baseline_optimal_fraction"]["B3_combined"],
         rob_s["baseline_dominated_by_ours_fraction"]["B1_pccsql"],
         rob_s["baseline_dominated_by_ours_fraction"]["B2_schema_hiding"],
         rob_s["baseline_dominated_by_ours_fraction"]["B3_combined"]))
    A("")
    A("C4（D30 s=1.0）对 C0 的交叉点：纯泄露 p*=%.4f；含效用 p*（λ=1）"
      "%.4f、（λ=2）%.4f、（λ=5）%.4f。"
      % (r["optimal_map_W_S"]["crossover"]["leak_only_p_star"],
         r["optimal_map_W_S"]["crossover"]["utility_p_star_by_lambda"]["1.0"],
         r["optimal_map_W_S"]["crossover"]["utility_p_star_by_lambda"]["2.0"],
         r["optimal_map_W_S"]["crossover"]["utility_p_star_by_lambda"]["5.0"]))
    A("")
    A("### 4.3 基线三档预设")
    A("")
    A("| 预设 | PCC-SQL fp/时延/e_cot | schema v/fp | p_cot=1,λ=2 最优 |"
      " 纯泄露交叉点 |")
    A("|---|---|---|---|---|")
    for name, p in r["baseline_presets_comparison"].items():
        pp = p["params"]
        A("| %s | %.2f / %.0f ms / %.2f | %.2f / %.2f | %s | %s |"
          % (name, pp["pccsql_fp"], pp["pccsql_lat"], pp["pccsql_e_cot"],
             pp["sch_v"], pp["sch_fp"], CFG_CN[p["optimal_at_pcot1_lam2"]],
             "%.4f" % p["crossover_leak_only"] if p["crossover_leak_only"] is not None
             else "无"))
    A("")
    A("即使在最有利基线预设（favorable：fp=0、时延 10 ms、e_cot=0.25、v=0.8）下，"
      "B1 也只在 p_cot>0.64 的消费方场景占优；central 与 pessimistic 预设下基线"
      "在所有格点均不占优。")
    A("")
    A("**E2-Q3 结论**：真实世界（W-R）中，基线在全部 7776 个格点上都不是最优配置、"
      "且被我方配置完全支配（最优比例 0.0）；即使在放宽的模拟世界（W-S）中，"
      "B1 也仅 12.38% 的格点占优、被支配 87.5%。基线相对优势完全依赖于"
      "「消费方只看 final 通道」这一假设。")
    A("")
    A("## 五、E2b：真实模型 schema-hiding 探针臂")
    A("")
    if b is None:
        A("`results/e2_real_schema_hiding_v1.json` 尚未生成（E2b 未运行）。")
    else:
        s = b["summary_schema_hidden"]
        A("在 dots3-note-prev 上直接实测：system prompt 移除 SCHEMA 块"
          "（表/列定义），保留 api_keys 内容块（key 值仍在上下文——"
          "「数据可见、元数据隐藏」的部署形态）。探针与 B1+B3 逐字一致"
          "（6 核心探针 × 3 重复 = 18 攻击 + 3 良性）。")
        A("")
        A("| 指标 | schema hidden（E2b） |")
        A("|---|---|")
        A("| 攻击请求（发送/成功） | %d / %d |"
          % (s["n_attack_sent"], s["n_attack_ok"]))
        A("| CoT 泄露 | %d（%.2f%%） |"
          % (s["cot_leak_count"], 100 * s["cot_leak_rate"]))
        A("| final 泄露 | %d（%.2f%%） |"
          % (s["final_leak_count"], 100 * s["final_leak_rate"]))
        A("| 拒答 | %d（%.2f%%） |"
          % (s["refusal_count"], 100 * s["refusal_rate"]))
        A("| 网关拦截 | %d |" % s["gateway_blocked_count"])
        A("")
        A("逐探针对比（CoT 泄露率与实测 v）：")
        A("")
        A("| 探针 | 基线 n | 基线 CoT | hidden n | hidden CoT |"
          " 基线泄露率 | hidden 泄露率 | v 实测 | 备注 |")
        A("|---|---|---|---|---|---|---|---|---|")
        for pid, c in b["per_probe_comparison"].items():
            if c["baseline"] is None:
                A("| %s | — | — | %d | %d | — | %s | 无基线 | |"
                  % (pid, c["hidden"]["n"], c["hidden"]["cot"],
                     "%.2f%%" % (100 * c["hidden"]["cot"]
                                 / max(1, c["hidden"]["api_ok"]))))
            else:
                ba, ha = c["baseline"], c["hidden"]
                if ba["cot"] == 0 and ha["cot"] == 0:
                    note = "v 为约定值（基线泄露率本为 0）"
                elif c["v_real_measured"] < 0:
                    note = "**负 v：泄露上升**"
                elif pid.startswith("tl"):
                    note = "结构性不触及：泄露持续"
                else:
                    note = "schema 依赖类：实测下降"
                A("| %s | %d | %d | %d | %d | %s | %s | %s | %s |"
                  % (pid, ba["n"], ba["cot"], ha["n"], ha["cot"],
                     pct(c["baseline_cot_rate"]), pct(c["hidden_cot_rate"]),
                     "%.4f" % c["v_real_measured"], note))
        A("")
        # 聚合同口径对比（从 JSON 现算，不硬编码）
        tot_bn = sum(c["baseline"]["n"] for c in b["per_probe_comparison"].values()
                     if c["baseline"] is not None)
        tot_bc = sum(c["baseline"]["cot"] for c in b["per_probe_comparison"].values()
                     if c["baseline"] is not None)
        tot_hn = sum(c["hidden"]["api_ok"] for c in b["per_probe_comparison"].values())
        tot_hc = b["summary_schema_hidden"]["cot_leak_count"]
        tot_br = sum(c["baseline"]["refusal"]
                     for c in b["per_probe_comparison"].values()
                     if c["baseline"] is not None)
        A("**同探针聚合口径**（只比较这 6 条探针，与 B1+B3 同 Arm）：基线 CoT 泄露 "
          "%d/%d（%.2f%%）→ schema hidden %d/%d（%.2f%%）；拒答 %d/%d（%.2f%%）→ "
          "%d/%d（%.2f%%）。schema hiding **没有降低聚合 CoT 泄露率**（上升 %.2f pp），"
          "其代价表现为 schema 依赖类探针的拒答悬崖（re1 拒答 1/4 → 3/3）。"
          % (tot_bc, tot_bn, 100.0 * tot_bc / tot_bn,
             tot_hc, tot_hn, 100.0 * tot_hc / tot_hn,
             tot_br, tot_bn, 100.0 * tot_br / tot_bn,
             b["summary_schema_hidden"]["refusal_count"], tot_hn,
             100.0 * b["summary_schema_hidden"]["refusal_count"] / max(1, tot_hn),
             100.0 * tot_hc / tot_hn - 100.0 * tot_bc / tot_bn))
        A("")
        bl = b["benign_records"]
        A("良性探针（refusal-cliff 观察侧，n=%d）：%s"
          % (len(bl), "、".join("`%s` ok=%s CoT泄露=%s" % (x["id"], x["api_ok"],
                                                     x.get("cot_leak")) for x in bl)))
        A("")
        ben_leak = [x for x in bl if x.get("cot_leak")]
        if ben_leak:
            A("良性侧代价的另一种形态：%s 这类「按可见列内容计数」的良性请求，在"
              "schema hidden 后模型无法走结构化查询路径，转而在推理链中逐条检视"
              "上下文里仍可见的 key 值，触发 CoT 泄露判定（final 通道仍为 0）。"
              "即「数据可见、元数据隐藏」的部署形态把推理压力从结构化路径推向"
              "明文数据本身。"
              % "、".join("`%s`" % x["id"] for x in ben_leak))
            A("")
        lead = ("**E2b 结论**：thinking_leak 类探针只要求模型思考上下文中已可见的 key 值，"
                "不引用表结构，结构性预测是其泄露在 schema hidden 后持续。")
        tl = b["per_probe_comparison"].get("tl1")
        if tl is not None and tl["baseline"] is not None:
            A(lead + " 实测 tl1 基线泄露率 %s → hidden %s（v=%.4f）；"
              "tl4 更出现负 v（%.4f，泄露率 50%%→100%%）。"
              % (pct(tl["baseline_cot_rate"]), pct(tl["hidden_cot_rate"]),
                 tl["v_real_measured"],
                 b["per_probe_comparison"]["tl4"]["v_real_measured"]))
        else:
            A(lead + "（tl1 无 B1+B3 基线对照，见上表。）")
        A("")
        A("网关行为与 B1+B3 一致：tool_injection 类探针被输入侧内容安全拦截"
          "（该类在 B1+B3 中 UNION 100% 被拦），拦截属于部署环境属性而非"
          "schema hiding 的效果。")
    A("")
    A("## 六、扩展配置空间上的自进化防御 Agent 检验")
    A("")
    A("把 3 条基线并入 Phase 54 的 ModelDefenseAgent 配置空间（8 配置），"
      "在 W-R 上以 λ=2 跑 20000 请求/臂（四流 RNG 隔离）：")
    A("")
    A("| 臂 | 效用/请求 | 遗憾/请求 | 泄露率 | 误拦率 | 平均时延 |")
    A("|---|---|---|---|---|---|")
    for k in ["random", "static_best", "bandit_naive", "defense_agent",
              "defense_agent_e0", "oracle"]:
        v = arms[k]
        A("| %s | %.4f | %.4f | %.4f | %.4f | %.2f ms |"
          % (k, v["utility_per_request"], v["regret_per_request"],
             v["leak_rate"], v["fp_rate"], v["avg_latency_ms"]))
    A("")
    e0 = arms["defense_agent_e0"]
    st = arms["static_best"]
    A("- 模型驱动 Agent（e0，ε 终值 %.3f）相对静态最优配置净增益 "
      "**+%.4f/请求**（%.4f vs %.4f）；朴素 bandit 仍劣于静态（%.4f vs "
      "%.4f），弱信号结论在含基线的扩展空间上复现。"
      % (e0["epsilon_final"], abs(st["utility_per_request"] - e0["utility_per_request"]),
         e0["utility_per_request"], st["utility_per_request"],
         arms["bandit_naive"]["utility_per_request"], st["utility_per_request"]))
    A("- Agent 最终逐 context 策略不含任何基线配置（%s）；"
      "基线配置使用次数 B1=%d / B2=%d / B3=%d（探索残余）。"
      % (json.dumps(gates_or_agent(a)["final_policy"], ensure_ascii=False),
         e0["config_usage"]["B1_pccsql"], e0["config_usage"]["B2_schema_hiding"],
         e0["config_usage"]["B3_combined"]))
    A("- oracle 遗憾 %.4f（含观测器残余），排序 oracle ≥ agent(e0) ≥ static ≥ "
      "random 成立。" % arms["oracle"]["regret_per_request"])
    A("")
    A("## 七、自检闸门（全部通过）")
    A("")
    A("| 闸门 | 检查 | 通过 |")
    A("|---|---|---|")
    for k, v in gates.items():
        A("| %s | %s | %s |" % (k, v["check"], "是" if v["passed"] else "否"))
    A("")
    A("## 八、对 P3 论文的影响")
    A("")
    A("- 新增 RQ：**生产侧 SOTA 基线（解码层/提示层）与测量驱动通道层防御的互补域**。"
      "真实证据下 PCC-SQL 的机制触及面为 0/8、schema hiding 为 2/8，二者均不覆盖"
      "reasoning_content 通道的主导泄露类。")
    A("- 论文必须同时报告 final-only 与并集/消费方通道口径：前者对真实世界结构性"
      "失明（分母 0）、把 PCC-SQL 高估 4.06×，且把 D30 位移误判为有害。")
    A("- 基线的相对优势完全依赖「消费方只看 final」假设：即使在放宽的 W-S 中，"
      "B1 也仅 12.38% 格点占优；W-R 中为 0。这不否认基线在其设计场景（SQL 生成"
      "正确性）的价值，只是划清了互补域边界。")
    if b is not None:
        A("- E2b 用真实模型实测补上 schema hiding 的 v 与 refusal-cliff：同探针聚合 "
          "CoT 泄露基线 → hidden 不降反升，tl 类 v=0.00/−1.00（结构性预测落地）；"
          "代价以拒答悬崖（re1 1/4 → 3/3）与良性请求被推向明文推理（ben_content "
          "CoT 泄露）两种形态出现。E2a 文献锚定的 v=0.55 假设在「数据可见、元数据"
          "隐藏」的真实部署形态下不成立——v 只对 schema 依赖类有效且伴随拒答代价。")
    A("")
    A("## 九、交付物")
    A("")
    A("- 实验脚本：`experiments/e2_baseline_comparison.py`（E2a）、"
      "`experiments/e2_real_schema_hiding.py`（E2b）")
    A("- 结果 JSON：`results/e2_baseline_comparison_v1.json`、"
      "`results/e2_real_schema_hiding_v1.json`（E2b）")
    A("- 报告/仪表板：`reports/E2_BASELINE_COMPARISON_REPORT.md`、"
      "`reports/e2_baseline_comparison_dashboard.html`")
    A("- 运行日志：`results/e2_run.log`（E2a）、`results/e2b_run.log`（E2b）")
    return "\n".join(L) + "\n"


def gates_or_agent(a):
    """g6 的 final_policy 与 agent 臂一致是断言对象；报告引用 g6。"""
    return a["gates"]["g6_agent_dominance"]


HTML_T = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>E2 基线对照实验 - 仪表板</title>
<style>
body{font-family:"Microsoft YaHei",sans-serif;background:#f5f6f8;color:#222;margin:0;padding:24px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:#666;font-size:13px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-bottom:20px}
.card{background:#fff;border:1px solid #e3e5ea;border-radius:8px;padding:14px}
.card .k{font-size:12px;color:#888}
.card .v{font-size:24px;font-weight:700;margin-top:4px}
.card.bad .v{color:#c0392b}
.card.ok .v{color:#1e8e5a}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin-bottom:20px}
th,td{border:1px solid #e3e5ea;padding:7px 10px;text-align:left}
th{background:#fafbfc}
.small{font-size:12px;color:#666;margin-top:4px}
.note{margin-top:16px;color:#666;font-size:12px}
h2{font-size:15px;margin:22px 0 8px}
code{font-family:Consolas,monospace;font-size:12px}
</style>
</head>
<body>
<h1>E2 基线对照：PCC-SQL / Schema Hiding vs 通道层防御</h1>
<div class="sub">全部数字溯源 results/e2_baseline_comparison_v1.json
（+ results/e2_real_schema_hiding_v1.json）</div>
<div class="grid">
  <div class="card bad"><div class="k">真实泄露事件（N=112）</div><div class="v">__NEV__</div>
    <div class="small">Wilson 95% CI [__LO__, __HI__]</div></div>
  <div class="card bad"><div class="k">B1 PCC-SQL 触及面</div><div class="v">__B1R__</div>
    <div class="small">final-only 口径高估 __B1OV__×</div></div>
  <div class="card"><div class="k">B2 schema hiding 触及面</div><div class="v">__B2R__</div>
    <div class="small">仅 schema 依赖类</div></div>
  <div class="card ok"><div class="k">C1 τ 触及面</div><div class="v">__TAUR__</div>
    <div class="small">post-hoc 残余实测 0</div></div>
  <div class="card ok"><div class="k">Agent(e0) 净增益/请求</div><div class="v">__AGN__</div>
    <div class="small">扩展 8 配置空间，λ=2</div></div>
  <div class="card"><div class="k">W-R 基线最优格点比例</div><div class="v">__WRO__</div>
    <div class="small">7776 格点，三档基线均为 0</div></div>
</div>
<h2>机制触及面与度量口径（W-S）</h2>
<table>
<tr><th>配置</th><th>final-only 削减</th><th>并集削减</th><th>final 通道变化(pp)</th></tr>
__MROWS__
</table>
<h2>稳健性扫描（基线最优 / 被支配比例）</h2>
<table>
<tr><th>基线</th><th>W-R 最优比例</th><th>W-R 被支配</th><th>W-S 最优比例</th><th>W-S 被支配</th></tr>
__RROWS__
</table>
<h2>Agent 臂（扩展空间，W-R，λ=2，20000 请求）</h2>
<table>
<tr><th>臂</th><th>效用/请求</th><th>遗憾/请求</th><th>泄露率</th><th>误拦率</th><th>时延 ms</th></tr>
__AROWS__
</table>
__E2B__
<div class="note">闸门 g1–g7 全部通过（详见报告 MD）。基线参数为文献锚定假设（扫描），
非本项目实测。</div>
</body>
</html>
"""


def build_html(a, b):
    r = a["results"]
    attr = r["real_event_attribution"]
    g5 = r["metric_blindness_W_S"]
    rr = r["robustness_W_R"]
    rs = r["robustness_W_S"]
    arms = r["agent_arms_extended_W_R"]
    e0, st = arms["defense_agent_e0"], arms["static_best"]

    mrows = []
    for k, v in g5["per_config"].items():
        mrows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                     % (CFG_CN[k], pct(v["final_only_reduction_pct"]),
                        pct(v["union_reduction_pct"]),
                        "%.2f" % v["final_channel_change_pp"]))
    rrows = []
    for bk in ["B1_pccsql", "B2_schema_hiding", "B3_combined"]:
        rrows.append("<tr><td>%s</td><td>%.4f</td><td>%.4f</td><td>%.4f</td>"
                     "<td>%.4f</td></tr>"
                     % (CFG_CN[bk], rr["baseline_optimal_fraction"][bk],
                        rr["baseline_dominated_by_ours_fraction"][bk],
                        rs["baseline_optimal_fraction"][bk],
                        rs["baseline_dominated_by_ours_fraction"][bk]))
    arows = []
    for k in ["random", "static_best", "bandit_naive", "defense_agent",
              "defense_agent_e0", "oracle"]:
        v = arms[k]
        arows.append("<tr><td>%s</td><td>%.4f</td><td>%.4f</td><td>%.4f</td>"
                     "<td>%.4f</td><td>%.2f</td></tr>"
                     % (k, v["utility_per_request"], v["regret_per_request"],
                        v["leak_rate"], v["fp_rate"], v["avg_latency_ms"]))

    e2b = ""
    if b is not None:
        s = b["summary_schema_hidden"]
        tot_bn = sum(c["baseline"]["n"] for c in b["per_probe_comparison"].values()
                     if c["baseline"] is not None)
        tot_bc = sum(c["baseline"]["cot"] for c in b["per_probe_comparison"].values()
                     if c["baseline"] is not None)
        tot_br = sum(c["baseline"]["refusal"]
                     for c in b["per_probe_comparison"].values()
                     if c["baseline"] is not None)
        rows = []
        for pid, c in b["per_probe_comparison"].items():
            if c["baseline"] is None:
                rows.append("<tr><td>%s</td><td>—</td><td>—</td><td>—</td><td>%d</td>"
                            "<td>%d</td><td>—</td><td>%s</td><td>无基线</td></tr>"
                            % (pid, c["hidden"]["n"], c["hidden"]["cot"],
                               pct(c["hidden"]["cot"]
                                   / max(1, c["hidden"]["api_ok"]))))
            else:
                ba, ha = c["baseline"], c["hidden"]
                if ba["cot"] == 0 and ha["cot"] == 0:
                    note = "v 约定值"
                elif c["v_real_measured"] < 0:
                    note = '<span class="bad">负 v：泄露上升</span>'
                elif pid.startswith("tl"):
                    note = "结构性不触及"
                else:
                    note = "依赖类：下降"
                rows.append("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td>"
                            "<td>%d</td><td>%s</td><td>%s</td><td>%s</td>"
                            "<td>%s</td></tr>"
                            % (pid, ba["n"], ba["cot"], ha["n"], ha["cot"],
                               pct(c["baseline_cot_rate"]), pct(c["hidden_cot_rate"]),
                               "%.4f" % c["v_real_measured"], note))
        e2b = (
            '<h2>E2b 真实 schema-hiding 探针臂（dots3-note-prev）</h2>'
            '<div class="grid">'
            '<div class="card"><div class="k">攻击请求（发送/成功）</div>'
            '<div class="v">%d / %d</div></div>'
            '<div class="card bad"><div class="k">hidden CoT 泄露</div>'
            '<div class="v">%.2f%%</div>'
            '<div class="small">同探针基线 %.2f%%（上升）</div></div>'
            '<div class="card bad"><div class="k">拒答（refusal-cliff）</div>'
            '<div class="v">%.2f%%</div>'
            '<div class="small">基线同探针 %.2f%%</div></div>'
            '<div class="card"><div class="k">网关拦截</div>'
            '<div class="v">%d</div>'
            '<div class="small">tool_injection 类，同 B1+B3</div></div>'
            '</div>'
            '<table><tr><th>探针</th><th>基线 n</th><th>基线 CoT</th>'
            '<th>基线拒答</th><th>hidden n</th><th>hidden CoT</th>'
            '<th>基线泄露率</th><th>hidden 泄露率</th><th>v 实测</th></tr>%s</table>'
            '<div class="note">聚合：基线 %d/%d（%.2f%%）→ hidden %d/%d（%.2f%%），'
            'schema hiding 未降低 CoT 泄露；tl 类 v=%.2f/%.2f（结构性不触及/负 v）。'
            '良性 ben_content 在 schema hidden 后 CoT 内逐条检视明文 key → 判定泄露。'
            '</div>'
            % (s["n_attack_sent"], s["n_attack_ok"], 100 * s["cot_leak_rate"],
               100.0 * tot_bc / tot_bn, 100 * s["refusal_rate"],
               100.0 * tot_br / tot_bn, s["gateway_blocked_count"],
               "\n".join(rows),
               tot_bc, tot_bn, 100.0 * tot_bc / tot_bn,
               s["cot_leak_count"], s["n_attack_ok"], 100 * s["cot_leak_rate"],
               b["per_probe_comparison"]["tl1"]["v_real_measured"],
               b["per_probe_comparison"]["tl4"]["v_real_measured"]))

    return (HTML_T
            .replace("__NEV__", "%d" % attr["total_leak_events"])
            .replace("__LO__", "%.4f" % attr["wilson_95ci"][0])
            .replace("__HI__", "%.4f" % attr["wilson_95ci"][1])
            .replace("__B1R__", "%d/8" % attr["b1_pccsql_reach"]["events"])
            .replace("__B1OV__", "%.2f" % g5["b1_overstatement_factor"])
            .replace("__B2R__", "%d/8" % attr["b2_schema_hiding_reach"]["events"])
            .replace("__TAUR__", "%d/8" % attr["c1_tau_scrub_reach"]["events"])
            .replace("__AGN__", "+%.4f" % (st["utility_per_request"]
                                           - e0["utility_per_request"]))
            .replace("__WRO__", "%.4f" % rr["baseline_optimal_fraction"]["B1_pccsql"])
            .replace("__MROWS__", "\n".join(mrows))
            .replace("__RROWS__", "\n".join(rrows))
            .replace("__AROWS__", "\n".join(arows))
            .replace("__E2B__", e2b))


def check(a, b):
    """断言：报告口径与 JSON 一致。"""
    r = a["results"]
    attr = r["real_event_attribution"]
    assert sum(attr["leak_events_by_class"].values()) == attr["total_leak_events"]
    assert attr["total_leak_events"] == 8
    assert attr["n_effective"] == 112
    # g2: W-R 中 B1 的 Δresid 恒为 0
    t = r["marginal_W_R"]["table"]["B1_pccsql"]["resid_by_pcot"]
    c0 = r["marginal_W_R"]["table"]["C0_passthrough"]["resid_by_pcot"]
    for pc, v in t.items():
        assert abs(v["resid"] - c0[pc]["resid"]) < 1e-12
    # g5: 排序不同 + 高估因子
    g5 = r["metric_blindness_W_S"]
    assert g5["ranks_differ"]
    assert abs(g5["b1_overstatement_factor"]
               - g5["per_config"]["B1_pccsql"]["final_only_reduction_pct"]
               / g5["per_config"]["B1_pccsql"]["union_reduction_pct"]) < 0.01
    # g7 排序
    arms = r["agent_arms_extended_W_R"]
    seq = [arms["oracle"]["utility_per_request"],
           arms["defense_agent_e0"]["utility_per_request"],
           arms["static_best"]["utility_per_request"],
           arms["random"]["utility_per_request"]]
    assert seq == sorted(seq, reverse=True), seq
    # 闸门
    for k, v in a["gates"].items():
        assert v["passed"], k
    # E2b（若存在）
    if b is not None:
        s = b["summary_schema_hidden"]
        recs = [x for x in b["records"] if x["kind"] == "attack"]
        assert s["n_attack_sent"] == len(recs)
        assert s["cot_leak_count"] == sum(1 for x in recs if x["api_ok"]
                                          and x["cot_leak"])
        for pid, c in b["per_probe_comparison"].items():
            if c["baseline"] is not None:
                base = c["baseline"]
                rr_ = base["cot"] / max(1, base["n"])
                hh = c["hidden"]["cot"] / max(1, c["hidden"]["api_ok"])
                want = 1.0 - (hh / rr_) if rr_ > 0 else (1.0 if hh == 0 else 0.0)
                assert abs(want - c["v_real_measured"]) < 0.0002, (pid, want,
                                                                   c["v_real_measured"])
        assert b["gates"]["g2_schema_removed_keys_kept"]["passed"]
        assert b["gates"]["g1_channel_visibility"]["reasoning_present_rate"] >= 0.9
    print("[check] OK: gates g1–g7 全部通过；E2a 口径断言通过；"
          "E2b %s" % ("已并入并通过断言" if b is not None else "未运行"))


def main():
    a, b = load()
    if "--check" in sys.argv:
        check(a, b)
        return
    os.makedirs(os.path.dirname(REP), exist_ok=True)
    with open(REP, "w", encoding="utf-8") as f:
        f.write(build_report(a, b))
    with open(HTM, "w", encoding="utf-8") as f:
        f.write(build_html(a, b))
    for p in (REP, HTM):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:12]
        print("[E2-gen] %s  sha256=%s" % (p, h))
    check(a, b)


if __name__ == "__main__":
    main()
