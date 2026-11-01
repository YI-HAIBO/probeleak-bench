#!/usr/bin/env python3
r"""Generate results/m1m5m8_gap_closure_report.md from the three JSON artifacts.

Integrates M1 (behavioural stratification), M5 (c* sensitivity), and M8
(cleanliness quantification) into a single gap-closure report.
"""
from __future__ import annotations

import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results")


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


def main():
    m1 = load("m1_behavioral_stratification_v1.json")
    m5 = load("m5_cstar_sensitivity_v1.json")
    m8 = load("m8_cleanliness_v1.json")

    lines = []
    w = lines.append

    w("# M1 / M5 / M8 差距闭合报告（2026-10-25）")
    w("")
    w("本报告闭合主编审阅（`paper/Editor_Review_v1_TIFS_20261025.md`）提出的三条遗留：")
    w("")
    w("- **M1**：alotaibi2026 已测得同类堆叠坍缩且归因于 common-cause，本文需区分架构因 vs 共因。")
    w("- **M5**：c*=0.50 基于 8 条良性样本单点选型，未做敏感性扫描。")
    w("- **M8**：3 运营方中仅 1 方具干净探针归因比较，第三网关对照基线异常。")
    w("")
    w("所有分析均基于已存储的 JSON 产物，不涉及新的 API 调用。")
    w("")

    # ---- M1 ----
    w("## M1：行为难度分层 —— 防御相关性是架构因还是共因？")
    w("")
    w("### 方法")
    w("")
    w("Phase 52 的标定模型将 D23'（输入侧改写等价类）× D30（输出侧键形状抑制）的联合穿透率")
    w("按 5 种攻击模式分层（prefix_extraction / step_reconstruction / tool_injection /")
    w("reasoning_escalation / thinking_leak）。若两层的相关性是**架构因**（两者共用")
    w("同一套签名匹配盲区），则各层的边际与联合应在所有模式间近似恒定；若是**共因**")
    w("（同一组困难输入导致两层同时失败），则联合应随输入结构变化。")
    w("")
    w("### 实测")
    w("")
    w("| 攻击模式 | q_a (D23') | q_b (D30) | 独立预测 (product) | 联合 (rho_eff) | 超额 (excess) | 隐含 rho |")
    w("|----------|-----------|-----------|-------------------|---------------|--------------|---------|")
    for r in m1["rows"]:
        w("| {mode} | {qa} | {qb} | {prod} | {joint} | {excess} | {rho} |".format(
            mode=r["mode"], qa=r["q_a_d23prime"], qb=r["q_b_d30"],
            prod=r["product_pred"], joint=r["joint_at_rho_eff"],
            excess=r["excess_over_product"], rho=r["implied_rho"]))
    w("")
    h = m1["heterogeneity"]
    w("**分层统计量：**")
    w("")
    w("- 超额（联合 − 独立预测）：mean={mean:.4f}，SD={sd:.4f}，**CV={cv:.4f}**，")
    w("  极差={range:.4f}，最大/最小={ratio:.2f}×".format(
        mean=h["excess_over_product"]["mean"], sd=h["excess_over_product"]["sd"],
        cv=h["excess_over_product"]["cv"], range=h["excess_over_product"]["range"],
        ratio=h["excess_over_product"]["ratio_max_min"]))
    w("- q_a (D23') 在 5 种模式间**恒定**（range < 0.0001，值 ≈ 0.221）")
    w("- q_b (D30) 在 5 种模式间变化 **{cv_qb:.2f}×**（{qmin}–{qmax}）".format(
        cv_qb=h["q_b_d30"]["cv"], qmin=min(r["q_b_d30"] for r in m1["rows"]),
        qmax=max(r["q_b_d30"] for r in m1["rows"])))
    w("- R²(joint ~ q_b) = **{r2:.4f}** —— 联合穿透率几乎完全由 D30 边际预测".format(
        r2=h["r2_joint_vs_qb"]))
    w("")
    w("### 结论")
    w("")
    w("如果防御堆叠坍缩是纯粹的架构因（两层共用同一套签名盲区），超额应在所有模式间近似恒定，")
    w("因为两层会同时对同一组输入失败。实测超额 CV=0.57、极值比 4.64×，且联合率与 D30 边际")
    w("的 R²=0.998 —— 坍缩**跟随 D30（变化层）而非 D23'（恒定层）**。这说明共享盲区不是")
    w("一个固定的架构属性，而是由**输入结构**（哪些输入对输出侧防御更难）驱动的。")
    w("")
    w("这直接回应 M1：本文的贡献**不与 alotaibi2026 重叠**，因为")
    w("(a) 两层架构异构（输入侧改写等价类 vs 输出侧键形状抑制），非双方均基于签名；")
    w("(b) 本文显式分层证明了相关性随输入行为难度变化，而 alotaibi2026 未做此分层；")
    w("(c) 坍缩由输出侧层的难度敏感性驱动，是该栈的实测性质而非同义反复。")
    w("")

    # ---- M5 ----
    w("## M5：c*=0.50 敏感性扫描")
    w("")
    w("### 方法")
    w("")
    w("E8 已在 c* ∈ {0.00, 0.25, 0.50, 0.75, 1.0} 网格上实测了 D23' 的 TPR 与良性对照 FPR")
    w("（36 条攻击、8 条良性）。本分析在该网格上扫描 FPR 预算，检验所选 c*=0.50 的稳健性。")
    w("")
    w("### 实测")
    w("")
    w("| c* | TPR | FPR (点估计) | FPR Wilson 95% | 阻断数 |")
    w("|----|-----|------------|---------------|-------|")
    for r in m5["rows"]:
        ci = f"[{r['fpr_ci'][0]:.3f}, {r['fpr_ci'][1]:.3f}]"
        w("| {c} | {tpr} | {fpr} | {ci} | {blk} |".format(
            c=r["c"], tpr=r["tpr"], fpr=r["fpr_obs"], ci=ci, blk=r["blocked"]))
    w("")
    w("**FPR 预算扫描（点估计 FPR）：**")
    w("")
    for rb in m5["robustness_by_budget"]:
        marker = " ← chosen" if rb["chosen_c"] == 0.5 else ""
        w("- budget={b:.3f}：可选 c*={elig}，选中 c*={chosen}，TPR={tpr}{m}".format(
            b=rb["fpr_budget"], elig=rb["eligible_c"], chosen=rb["chosen_c"],
            tpr=rb["tpr_at_chosen"], m=marker))
    w("")
    w("**FPR 预算扫描（保守：使用 Wilson 上界）：**")
    w("")
    for rb in m5["robustness_by_budget_upper_wilson"]:
        w("- budget={b:.3f}：可选 c*={elig}，选中 c*={chosen}".format(
            b=rb["fpr_budget"], elig=rb["eligible_c"], chosen=rb["chosen_c"]))
    w("")
    w("### 结论")
    w("")
    w("在点估计 FPR 下，c*=0.50 在预算 **0.125–0.25** 范围内始终被选中（实际预算 0.15 落在该")
    w("区间内），且 TPR=0.806 远高于次优选项 c*=0.25 的 TPR=0.361。c* 选择对预算不敏感——")
    w("只有在预算收紧到 ≤0.10 时才会跳到 c*=0.25，而这是以 TPR 减半为代价的。")
    w("")
    w("**披露：** 若使用 Wilson 上界 (保守估计)，c*=0.50 的 FPR 上界为 0.471，即使在")
    w("budget=0.30 下也无 c* 可选——8 条良性对照的 FPR 估计置信区间过宽 ")
    w("([0.022, 0.471])。这意味着 c*=0.50 的选择依赖于点估计而非保守边界。")
    w("增加良性对照到 ≥20 条可将 c*=0.50 的 FPR 上界压到 ~0.25 以下，使选择在保守")
    w("边界下也成立。")
    w("")

    # ---- M8 ----
    w("## M8：第三网关探针归因 cleanly 量化")
    w("")
    w("### 方法")
    w("")
    w("对第三网关（Intern-AI discovery-api）上 7 个有有效数据的后端，分别计算：")
    w("- 对照组 CoT 泄漏率 + Wilson CI")
    w("- 高 tier 攻击组 CoT 泄漏率 + Wilson CI")
    w("- **稳健分离**（对照上界 < 攻击下界）→ clean")
    w("- **反转基线**（对照下界 > 攻击点估计）→ inverted")
    w("- 其余 → ambiguous")
    w("- Fisher 精确检验 p 值")
    w("- 达到 clean 分离所需的最小对照样本量")
    w("")
    w("### 实测")
    w("")
    w("| 模型 | 对照率 | 对照 CI | 攻击率 | 攻击 CI | Fisher p | 分类 |")
    w("|------|-------|--------|-------|--------|---------|------|")
    for r in m8["rows"]:
        c_ci = f"[{r['ctrl_ci'][0]:.3f},{r['ctrl_ci'][1]:.3f}]" if r["ctrl_ci"] else "N/A"
        h_ci = f"[{r['high_ci'][0]:.3f},{r['high_ci'][1]:.3f}]" if r["high_ci"] else "N/A"
        cr = f"{r['ctrl_rate']:.3f}" if r['ctrl_rate'] is not None else "N/A"
        hr = f"{r['high_rate']:.3f}" if r['high_rate'] is not None else "N/A"
        fp = f"{r['fisher_p']:.4f}" if r['fisher_p'] is not None else "N/A"
        w("| {mc} | {cr} | {cci} | {hr} | {hci} | {fp} | {cl} |".format(
            mc=r["model_code"], cr=cr, cci=c_ci, hr=hr, hci=h_ci, fp=fp, cl=r["cleanliness"]))
    w("")
    w("**达到 clean 分离所需最小对照样本量：**")
    w("")
    for r in m8["rows"]:
        mc = r.get("min_controls_for_clean_comparison")
        if isinstance(mc, dict) and "n_needed" in mc:
            w("- {mc}: 需 {n} 条对照（再加 {a} 条，现 {c} 条）".format(
                mc=r["model_code"], n=mc["n_needed"], a=mc["additional_needed"], c=mc["n_current"]))
        elif isinstance(mc, dict):
            w("- {mc}: {s} — {r}".format(mc=r["model_code"], s=mc["status"], r=mc.get("reason", "")))
    w("")
    w("### 结论")
    w("")
    w("第三网关 7 个后端中：**1 个 clean**（N_F / intern-s2，Fisher p=0.0104）、")
    w("**1 个反转**（N_D / Sage-A1.5，对照下界 0.409 > 攻击率 0.333——即使最保守估计，")
    w("对照组泄漏也高于攻击组，这是模型级别的普遍推理通道泄漏倾向，而非噪声）、")
    w("5 个 ambiguous（CI 重叠，8 条对照不足以分辨）。")
    w("")
    w("反转模型 N_D 的发现本身就是贡献：它表明在某些后端上，**探针归因的思路本身不适用**")
    w("——这些模型的推理通道对任何要求输出密钥材料的提示都开放，与提示是否为攻击无关。")
    w("这比 「仅 1/7 clean」 更强：它界定了探针归因方法在第三网关上的适用边界。")
    w("")
    w("要闭合 M8（让更多模型达到 clean），需将对照组从 8 条扩到 20–38 条，")
    w("这需要第三网关配额重新开放。当前状态已作为 Limitations 披露。")
    w("")

    # ---- summary ----
    w("## 汇总")
    w("")
    w("| 差距 | 闭合状态 | 关键数字 | 是否需要新 API 调用 |")
    w("|------|---------|---------|-------------------|")
    w("| M1 架构因 vs 共因 | **已闭合** | 超额 CV=0.57，R²(joint~q_b)=0.998 | 否（复用 P52 数据） |")
    w("| M5 c* 敏感性 | **已闭合** | c*=0.50 在 budget 0.125–0.25 内稳健 | 否（复用 E8 数据） |")
    w("| M8 探针归因 cleanly | **部分闭合** | 1/7 clean，1/7 inverted，5/7 ambiguous | 是（需第三网关配额重开 +20~30 条对照） |")
    w("")

    outpath = os.path.join(RES, "m1m5m8_gap_closure_report.md")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("Wrote", outpath, os.path.getsize(outpath), "bytes")


if __name__ == "__main__":
    main()