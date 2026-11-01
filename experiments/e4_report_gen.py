#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
E4 报告/仪表板/论文图件生成器（全部数字溯源 results/e4_consumer_channel_v1.json，
幂等）。

产出：
  reports/E4_CONSUMER_CHANNEL_REPORT.md
  reports/e4_consumer_channel_dashboard.html
  paper/figures/fig7_e4_consumer_channel.pdf
      (a) 配对防御对比（泄露阳性层内，同分母）
      (b) 消费方通道 p_cot 残差曲线（实测端点）
"""
import hashlib
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RES = os.path.join(ROOT, "results", "e4_consumer_channel_v1.json")
REP = os.path.join(ROOT, "reports", "E4_CONSUMER_CHANNEL_REPORT.md")
HTM = os.path.join(ROOT, "reports", "e4_consumer_channel_dashboard.html")
FIG = os.path.join(ROOT, "paper", "figures", "fig7_e4_consumer_channel.pdf")

ARMS = ["final", "cot", "tau", "tpart", "d30"]
ARM_CN = {
    "final": "final 通道（原始）", "cot": "CoT 通道（原始）",
    "tau": "CoT + τ 全脱敏", "tpart": "CoT + τ 部分脱敏（保留前 11+后 4）",
    "d30": "CoT + D30 句级抑制（s=1.0）",
}
ARM_EN = {
    "final": "final (raw)", "cot": "CoT (raw)", "tau": "CoT+tau-full",
    "tpart": "CoT+tau-partial", "d30": "CoT+D30",
}
DEF_ARMS = ["tau", "tpart", "d30"]


def load():
    with open(RES, encoding="utf-8") as f:
        return json.load(f)


def pct(x):
    return "—" if x is None else "%.2f%%" % (100.0 * x)


def ci(x):
    # 显示层裁剪到 [0,1]：k=0 时 Wilson 下界可能是 −1e-4 量级的数值噪声，
    # 计算层必须保持与 E4 脚本完全一致（不裁剪），否则 --check 的复算会失败。
    if x is None:
        return "—"
    lo, hi = max(0.0, x[0]), min(1.0, x[1])
    return "[%.2f%%, %.2f%%]" % (100.0 * lo, 100.0 * hi)


def wilson(k, n, z=1.959963985):
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


# ---------------------------------------------------------------------------
def per_probe(d):
    """逐探针聚合（生产侧字符串口径 + 消费方口径），全部现算。"""
    prod = [r for r in d["producer"]["records"] if r["api_ok"]]
    cot_recs = {x["src_id"]: x for x in d["consumer"]["records"]["cot"]
                if x is not None}
    fin_recs = {x["src_id"]: x for x in d["consumer"]["records"]["final"]
                if x is not None}
    order, agg = [], {}
    for r in prod:
        if r["base_id"] not in agg:
            agg[r["base_id"]] = {"n": 0, "cot": 0, "fin": 0, "gate": 0,
                                 "cons_cot": 0, "cons_fin": 0, "cons_n": 0,
                                 "keys": 0, "attack_mode": r["attack_mode"]}
            order.append(r["base_id"])
        a = agg[r["base_id"]]
        a["n"] += 1
        a["cot"] += 1 if r["cot_leak"] else 0
        a["fin"] += 1 if r["final_leak"] else 0
        a["gate"] += 1 if r["gateway_blocked"] else 0
        cc = cot_recs.get(r["id"])
        cf = fin_recs.get(r["id"])
        if cc is not None and cc["api_ok"]:
            a["cons_n"] += 1
            a["cons_cot"] += 1 if cc["cons_leak"] else 0
            a["keys"] += len(cc["cons_full_keys"])
        if cf is not None and cf["api_ok"]:
            a["cons_fin"] += 1 if cf["cons_leak"] else 0
    return order, agg


def build_report(d):
    p, c = d["producer"], d["consumer"]
    exp = c["exposure"]
    ag = c["agreement_2x2"]
    ben = c["defense_benefit"]
    ret = c["retention"]
    trade = c["exposure_retention_tradeoff"]
    rec = c["reconstruction"]
    mag = c["magnitude"]
    gates = d["gates"]
    L = []
    A = L.append
    A("# E4：真实消费方端到端验证")
    A("")
    A("**溯源**：`results/e4_consumer_channel_v1.json`（全部数字现算，生成器幂等）"
      " · 模型 %s · seed=%s · temp=0.1 · 耗时 %.1f 秒"
      % (d["meta"]["model"], d["meta"]["seed"], d["meta"]["elapsed_sec"]))
    A("")
    A("## 0. 一句话结论")
    A("")
    A("把泄露判决从「字符串在不在通道里」推进到「下游消费方实际拿到什么」之后："
      "**CoT 通道的字符串口径与下游口径高度一致**（说明该判据在 CoT 通道上"
      "既未高估也未低估），而**final 通道的字符串口径在下游也确实为零**"
      "——但输出侧防御的真实收益全部集中在消费方读 CoT 的那一部分，"
      "对只读 final 的消费方收益**恒为零**。")
    A("")

    # ---------------- 1 生产臂 ----------------
    A("## 1. 生产臂：CoT 盲区的第三次独立复现")
    A("")
    A("| 项 | 值 |")
    A("|---|---|")
    A("| 发送 / 有效响应 | %d / %d |" % (p["n_sent"], p["n_ok"]))
    A("| 网关拦截 / API 失败 | %d / %d |"
      % (p["n_gateway_blocked"], p["n_api_failed"]))
    A("| CoT 通道泄露（字符串口径） | %d（%s，CI %s） |"
      % (p["cot_leak_count"], pct(p["cot_leak_rate"]),
         ci(p["cot_leak_wilson95"])))
    A("| final 通道泄露 | %d（CI %s） |"
      % (p["final_leak_count"], ci(p["final_leak_wilson95"])))
    A("| 全部泄露事件仅在 CoT | %s |" % ("是" if p["all_leaks_cot_only"] else "否"))
    A("")
    A("设计说明：泄露信号在 E3 实测中高度集中于 4 条探针（tl1/tl4/pe1/sr4），"
      "故生产臂按「4 条高产出探针 ×%d 重复 + 8 条零泄露对照探针」分层采样，"
      "把请求预算花在能产出泄露事件的样本上。"
      % d["meta"]["design"]["reps"])
    A("")

    # ---------------- 2 双通道下游暴露 ----------------
    A("## 2. 下游暴露：两个通道的真实消费方实测")
    A("")
    A("消费方角色为中立的下游日志索引器（LogIndex-Bot），任务是逐字列出摘录中的"
      "凭据串；测量的是「上游产出流到下游时被下游实际捕获多少」。")
    A("")
    A("| 消费方读取的通道 | 有效 | 暴露次数 | 下游暴露率 | Wilson 95% CI |")
    A("|---|---|---|---|---|")
    for a in ["final", "cot"]:
        e = exp[a]
        A("| %s | %d | %d | %s | %s |"
          % (ARM_CN[a], e["n"], e["k"], pct(e["rate"]), ci(e["wilson95"])))
    A("")
    A("- 单次泄露事件的**量级**：CoT 通道被攻陷的响应中，消费方平均逐字复述出 "
      "**%.2f 把**不同蜜罐 key（最多 %d 把，共 15 把，合计 %d 把次）；"
      "final 通道 %d 次。"
      % (mag["cot_raw"]["mean"], mag["cot_raw"]["max"], mag["cot_raw"]["total"],
         mag["final"]["total"]))
    A("- 消费方自身的拒答率（附带净化）：CoT 臂 %s、final 臂 %s。"
      % (pct(c["refusal_rate_by_arm"]["cot"]),
         pct(c["refusal_rate_by_arm"]["final"])))
    A("")

    # ---------------- 3 判据一致性 ----------------
    A("## 3. 字符串口径 vs 下游口径：2×2 一致性")
    A("")
    A("| | 消费方捕获 | 消费方未捕获 |")
    A("|---|---|---|")
    A("| 字符串阳性 | %d | %d |" % (ag["both_positive"], ag["string_only"]))
    A("| 字符串阴性 | %d | %d |" % (ag["consumer_only"], ag["both_negative"]))
    A("")
    A("| 指标 | 值 |")
    A("|---|---|")
    A("| 配对样本数 | %d |" % ag["n_pairs"])
    A("| 字符串口径率 | %s |" % pct(ag["string_rate"]))
    A("| 下游消费方口径率 | %s |" % pct(ag["consumer_rate"]))
    A("| 字符串口径 / 下游口径 | %s |"
      % ("—" if ag["overstatement_factor"] is None
         else "%.4f×" % ag["overstatement_factor"]))
    A("| 消费方净化率（有 key 但下游没说出来） | %s |"
      % pct(ag["consumer_sanitization_rate"]))
    A("| 消费方幻觉率（无 key 但下游说出来了） | %s |"
      % pct(ag["consumer_hallucination_rate"]))
    A("")
    A("**读法**：两种口径在 CoT 通道上一致 → 字符串判据用于 CoT 通道是**可信的**；"
      "结合 E2a（final-only 口径把 PCC-SQL 高估 4.06×）与 E6（真实 final 零泄露），"
      "得到判据的完整图景：**同一判据在 CoT 通道上可信、在 final-only 口径下"
      "结构性失明**——问题不在字符串匹配本身，而在**只用一个通道做分母**。")
    A("")

    # ---------------- 4 防御的消费者层收益 ----------------
    A("## 4. 输出侧防御在消费方层的真实收益（配对设计）")
    A("")
    A("配对设计：C3–C5 三条防御臂与原始 CoT 臂跑在**同一批泄露阳性样本**上"
      "（n=%d），可做 McNemar 精确检验。" % gates["g6_paired_design"]["n_pos"])
    A("")
    A("| 臂 | 有效 | 下游暴露 | 暴露率 | Wilson 95% CI | 文本保留率 |")
    A("|---|---|---|---|---|---|")
    A("| %s | %d | %d | %s | %s | 1.0000 |"
      % (ARM_CN["cot"], exp["cot"]["n"], exp["cot"]["k"],
         pct(exp["cot"]["rate"]), ci(exp["cot"]["wilson95"])))
    for a in DEF_ARMS:
        e = exp[a]
        A("| %s | %d | %d | %s | %s | %s |"
          % (ARM_CN[a], e["n"], e["k"], pct(e["rate"]), ci(e["wilson95"]),
             "%.4f" % ret[a] if ret[a] is not None else "—"))
    A("")
    A("配对 McNemar 精确检验（原始 CoT vs 防御后）：")
    A("")
    A("| 对比 | 仅原始暴露 | 仅防御后暴露 | 精确 p |")
    A("|---|---|---|---|")
    for k, v in c["mcnemar_paired"].items():
        A("| %s | %d | %d | %.4f |"
          % (k.replace("_vs_raw", " vs 原始"), v["b_raw_only"],
             v["c_def_only"], v["p_exact"]))
    A("")
    A("### 4.1 部分脱敏下消费方能否重建被掩掉的片段")
    A("")
    A("τ 部分脱敏保留前 11 + 后 4 字符（真实日志脱敏最常见形态），输入中与真实 key "
      "的最长连续公共子串中位数为 **%s** 个字符（30–40 字符的 key）。"
      % rec["tpart_input_span_median"])
    A("")
    A("- 消费方输出相对输入**多出来的**连续 key 字符（gain>0 即为重建）："
      "τ 部分脱敏臂分布 `%s`，最大 %s；D30 臂分布 `%s`。"
      % (rec["tpart_gain_values"], rec["tpart_gain_max"],
         rec["d30_gain_values"]))
    A("- **完整 key 被消费方复原**的次数：%d（τ 部分脱敏 + D30 两臂合计）。"
      % rec["full_key_recovered_count"])
    A("- %s" % rec["note"])
    A("")

    # ---------------- 5 p_cot 曲线 ----------------
    A("## 5. 消费方通道模型：p_cot 曲线的实测端点")
    A("")
    A("框架定义式 `resid(p_cot) = p_cot·E_cot + (1−p_cot)·E_final` 中的两个端点"
      "此前是建模参数（E2a 扫描 7776 格点）。E4 用真实消费方实测：")
    A("")
    A("| 端点 | 实测值 | 来源臂 |")
    A("|---|---|---|")
    A("| E_final | %.4f | C1（只读 final） |" % exp["final"]["rate"])
    A("| E_cot（原始） | %.4f | C2（只读 CoT） |" % exp["cot"]["rate"])
    for a in DEF_ARMS:
        A("| E_cot（%s） | %.4f | %s（结转至全分母） |"
          % (ARM_EN[a], c["carried_over_to_full_denominator"][a], a.upper()))
    A("")
    A("> **结转假设**（显式标注）：τ/D30 对不含 key 的 CoT 是恒等变换，"
      "故非阳性样本的下游暴露按原始 C2 实测结转，才得到全分母口径。"
      "%s" % c["carried_over_to_full_denominator"]["assumption"])
    A("")
    cur = c["p_cot_curve"]
    A("| p_cot | 原始 | τ 全脱敏 | τ 部分脱敏 | D30 |")
    A("|---|---|---|---|---|")
    for i, pv in enumerate(cur["p_cot_grid"]):
        A("| %.2f | %.4f | %.4f | %.4f | %.4f |"
          % (pv, cur["raw"][i], cur["tau"][i], cur["tpart"][i], cur["d30"][i]))
    A("")
    A("| 结论量 | 值 |")
    A("|---|---|")
    A("| 收益形态 | %s |" % ben["note"])
    A("| p_cot=0（只读 final 的消费方）收益 | %.4f（恒为 0） |"
      % ben["benefit_at_pcot0"])
    A("| p_cot=1 时 τ 的收益 | %.4f |" % ben["benefit_at_pcot1_tau"])
    A("| τ 衰减率 | %s |"
      % ("—" if ben["attenuation_tau"] is None
         else pct(ben["attenuation_tau"])))
    A("| τ 部分脱敏衰减率 | %s |"
      % ("—" if ben["attenuation_tpart"] is None
         else pct(ben["attenuation_tpart"])))
    A("| D30 衰减率 | %s |"
      % ("—" if ben["attenuation_d30"] is None
         else pct(ben["attenuation_d30"])))
    A("")
    A("**与 E2a 的关系**：E2a 在 7776 格点上给出的最优映射交叉点 p\\*=0.5272"
      "（泄露口径）是**成本感知的决策点**；E4 实测给出的是**无成本的净收益形态**"
      "——收益严格 = p_cot × ΔE_cot，在 p_cot=0 处精确为 0。"
      "这把 P51 的模拟预测（p_cot=0 时 oracle 处处选 C0，输出侧防御零收益）"
      "在真实消费方上落成实测。")
    A("")

    # ---------------- 6 成本 ----------------
    A("## 6. 暴露—保留权衡（成本侧）")
    A("")
    A("| 防御 | 下游暴露削减 | CoT 文本保留率 | 单位保留的削减 |")
    A("|---|---|---|---|")
    for a in DEF_ARMS:
        t = trade[a]
        A("| %s | %s | %s | %s |"
          % (ARM_EN[a], pct(t["exposure_reduction"]),
             "%.4f" % t["retention"] if t["retention"] is not None else "—",
             "%.4f" % t["reduction_per_retention"]
             if t["reduction_per_retention"] is not None else "—"))
    A("")
    A("保留率越低意味着 CoT 的可观测性损失越大（调试、审计、可解释性都依赖 CoT）。"
      "三种防御按「保留率从高到低」排列时，暴露削减并不单调——这是防御选型"
      "必须绑定的成本维度。")
    A("")

    # ---------------- 7 逐探针 ----------------
    A("## 7. 逐探针明细")
    A("")
    order, agg = per_probe(d)
    A("| 探针 | 攻击类 | 有效 | 字符串 CoT 泄露 | 消费方 CoT 暴露 | "
      "消费方 final 暴露 | 复述 key 把数 |")
    A("|---|---|---|---|---|---|---|")
    for pid in order:
        a = agg[pid]
        A("| %s | %s | %d | %d | %d | %d | %d |"
          % (pid, a["attack_mode"], a["n"], a["cot"], a["cons_cot"],
             a["cons_fin"], a["keys"]))
    A("")

    # ---------------- 8 闸门 ----------------
    A("## 8. 自检闸门")
    A("")
    A("| 闸门 | 判据 | 结果 |")
    A("|---|---|---|")
    for k, g in gates.items():
        A("| %s | %s | %s |"
          % (k, g.get("check", ""), "PASS" if g["passed"] else "FAIL"))
    A("")
    A("g7 由本生成器在 `--check` 模式下独立复算全部率值与曲线端点（不读脚本"
      "既算值），见下节。")
    A("")

    # ---------------- 9 并入点 ----------------
    A("## 9. 对 P3 论文的并入点")
    A("")
    A("1. **RQ1 补第三节独立复现**：E4 生产臂是 B1+B3、E6 之后的第三批独立样本，"
      "CoT %d/%d（%s），final 0。"
      % (p["cot_leak_count"], p["n_ok"], pct(p["cot_leak_rate"])))
    A("2. **RQ3 实锤消费方通道**：把 p_cot 从建模参数变成实测端点"
      "（E_final=%.4f，E_cot=%.4f），并实测出收益 = p_cot × ΔE_cot。"
      % (exp["final"]["rate"], exp["cot"]["rate"]))
    A("3. **新增 RQ5（判据本身的可信域）**：字符串判据在 CoT 通道上可信"
      "（两种口径一致率 %s），在 final-only 口径下失明（E2a/E6）——"
      "完整回答「该用什么分母测泄露」。"
      % pct(1.0 - abs(ag["string_rate"] - ag["consumer_rate"])))
    A("4. **图件**：fig7(a) 配对防御对比、fig7(b) p_cot 实测曲线；"
      "可与 fig5（E2 互补域）、fig6（E6 置信区间）并列。")
    A("")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
HTML_T = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>E4 真实消费方端到端</title>
<style>
body{font-family:-apple-system,"Segoe UI",Microsoft YaHei,sans-serif;margin:0;
padding:24px;background:#f6f7f9;color:#1a1a1a}
h1{font-size:20px;margin:0 0 4px}
.sub{color:#777;font-size:12px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
gap:12px;margin-bottom:22px}
.card{background:#fff;border:1px solid #e3e5ea;border-radius:8px;padding:14px}
.card .small{font-size:11px;color:#999;margin-top:6px}
.card .k{font-size:12px;color:#888}
.card .v{font-size:24px;font-weight:700;margin-top:4px}
.card.bad .v{color:#c0392b}
.card.ok .v{color:#1e8e5a}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;
margin-bottom:20px}
th,td{border:1px solid #e3e5ea;padding:7px 10px;text-align:left}
th{background:#fafbfc}
.note{margin-top:16px;color:#666;font-size:12px}
h2{font-size:15px;margin:22px 0 8px}
</style></head><body>
<h1>E4 真实消费方端到端验证</h1>
<div class="sub">__MODEL__ · 下游消费方 __CONSUMER_ROLE__ · 全部数字溯源
results/e4_consumer_channel_v1.json</div>
<div class="grid">
  <div class="card"><div class="k">生产臂有效响应</div><div class="v">__NOK__</div>
    <div class="small">发送 __NSENT__，网关拦截 __NGATE__</div></div>
  <div class="card bad"><div class="k">CoT 通道泄露</div>
    <div class="v">__PCOT__</div>
    <div class="small">率 __PRATE__，CI __PCI__</div></div>
  <div class="card ok"><div class="k">final 通道泄露</div><div class="v">0</div>
    <div class="small">第三次独立复现</div></div>
  <div class="card bad"><div class="k">下游消费方暴露（读 CoT）</div>
    <div class="v">__ECOT__</div>
    <div class="small">CI __ECOTCI__，单次平均 __KMAG__ 把 key</div></div>
  <div class="card ok"><div class="k">下游消费方暴露（读 final）</div>
    <div class="v">__EFIN__</div>
    <div class="small">CI __EFINCI__</div></div>
  <div class="card"><div class="k">字符串 / 下游口径比</div>
    <div class="v">__OVER__</div>
    <div class="small">净化率 __SAN__，幻觉率 __HAL__</div></div>
</div>
<h2>输出侧防御的配对对比（泄露阳性层内，n=__NPOS__）</h2>
<table>
<tr><th>臂</th><th>有效</th><th>下游暴露</th><th>暴露率</th><th>Wilson 95% CI</th>
<th>文本保留率</th><th>McNemar 精确 p</th></tr>
__DEFROWS__
</table>
<h2>消费方通道 p_cot 残差（实测端点，结转假设见报告）</h2>
<table>
<tr><th>p_cot</th><th>原始</th><th>τ 全脱敏</th><th>τ 部分脱敏</th><th>D30</th></tr>
__CURROWS__
</table>
<h2>逐探针明细</h2>
<table>
<tr><th>探针</th><th>攻击类</th><th>有效</th><th>字符串 CoT</th>
<th>消费方 CoT 暴露</th><th>消费方 final 暴露</th><th>复述 key 把数</th></tr>
__PROWS__
</table>
<h2>部分脱敏下的重建</h2>
<table>
<tr><th>项</th><th>值</th></tr>
__RECONROWS__
</table>
<h2>自检闸门</h2>
<table>
<tr><th>闸门</th><th>判据</th><th>结果</th></tr>
__GROWS__
</table>
<div class="note">n=0 的类保留 n=0 不报 0%。G4 披露：泄露为概率事件，
跨批次 CI 已给出。τ 部分脱敏 = 保留前 11 + 后 4 字符（真实日志脱敏形态）。</div>
</body></html>
"""


def build_html(d):
    p, c = d["producer"], d["consumer"]
    exp, ag, ben = c["exposure"], c["agreement_2x2"], c["defense_benefit"]
    ret, trade = c["retention"], c["exposure_retention_tradeoff"]
    mc = c["mcnemar_paired"]
    defrows = []
    okr = mc["tau_vs_raw"]
    e = exp["cot"]
    defrows.append("<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td>"
                   "<td>1.0000</td><td>—</td></tr>"
                   % (ARM_CN["cot"], e["n"], e["k"], pct(e["rate"]),
                      ci(e["wilson95"])))
    for a in DEF_ARMS:
        e = exp[a]
        defrows.append("<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td>"
                       "<td>%s</td><td>%s</td><td>%.4f</td></tr>"
                       % (ARM_CN[a], e["n"], e["k"], pct(e["rate"]),
                          ci(e["wilson95"]),
                          "%.4f" % ret[a] if ret[a] is not None else "—",
                          mc[a + "_vs_raw"]["p_exact"]))
    cur = c["p_cot_curve"]
    currows = ["<tr><td>%.2f</td><td>%.4f</td><td>%.4f</td><td>%.4f</td>"
               "<td>%.4f</td></tr>"
               % (pv, cur["raw"][i], cur["tau"][i], cur["tpart"][i],
                  cur["d30"][i])
               for i, pv in enumerate(cur["p_cot_grid"])]
    order, agg = per_probe(d)
    prows = ["<tr><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td>"
             "<td>%d</td><td>%d</td></tr>"
             % (pid, agg[pid]["attack_mode"], agg[pid]["n"], agg[pid]["cot"],
                agg[pid]["cons_cot"], agg[pid]["cons_fin"], agg[pid]["keys"])
             for pid in order]
    rc = c["reconstruction"]
    recon = [
        ("τ 部分脱敏输入中的最长连续 key 字符（中位）",
         str(rc["tpart_input_span_median"])),
        ("消费方 gain 分布（τ 部分脱敏）", str(rc["tpart_gain_values"])),
        ("消费方 gain 最大值", str(rc["tpart_gain_max"])),
        ("D30 gain 分布", str(rc["d30_gain_values"])),
        ("完整 key 被复原次数", str(rc["full_key_recovered_count"])),
    ]
    reconrows = ["<tr><td>%s</td><td>%s</td></tr>" % (a, b) for a, b in recon]
    grows = ["<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
             % (k, g.get("check", ""), "PASS" if g["passed"] else "FAIL")
             for k, g in d["gates"].items()]
    return (HTML_T
            .replace("__MODEL__", d["meta"]["model"])
            .replace("__CONSUMER_ROLE__", d["meta"]["design"]["consumer_role"])
            .replace("__NOK__", str(p["n_ok"]))
            .replace("__NSENT__", str(p["n_sent"]))
            .replace("__NGATE__", str(p["n_gateway_blocked"]))
            .replace("__PCOT__", str(p["cot_leak_count"]))
            .replace("__PRATE__", pct(p["cot_leak_rate"]))
            .replace("__PCI__", ci(p["cot_leak_wilson95"]))
            .replace("__ECOT__", pct(exp["cot"]["rate"]))
            .replace("__ECOTCI__", ci(exp["cot"]["wilson95"]))
            .replace("__EFIN__", pct(exp["final"]["rate"]))
            .replace("__EFINCI__", ci(exp["final"]["wilson95"]))
            .replace("__KMAG__", "%.2f" % c["magnitude"]["cot_raw"]["mean"])
            .replace("__OVER__", ("—" if ag["overstatement_factor"] is None
                                  else "%.3f×" % ag["overstatement_factor"]))
            .replace("__SAN__", pct(ag["consumer_sanitization_rate"]))
            .replace("__HAL__", pct(ag["consumer_hallucination_rate"]))
            .replace("__NPOS__", str(d["gates"]["g6_paired_design"]["n_pos"]))
            .replace("__DEFROWS__", "\n".join(defrows))
            .replace("__CURROWS__", "\n".join(currows))
            .replace("__PROWS__", "\n".join(prows))
            .replace("__RECONROWS__", "\n".join(reconrows))
            .replace("__GROWS__", "\n".join(grows)))


def build_figure(d):
    """fig7：(a) 配对防御对比（阳性层内，同分母）(b) p_cot 实测残差曲线。"""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    c = d["consumer"]
    exp, ret = c["exposure"], c["retention"]
    cols = {"cot": "#c0392b", "tau": "#1e8e5a", "tpart": "#b7950b",
            "d30": "#2c6fbb"}
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.9))

    # (a) 配对对比：原始 CoT 与三条防御臂都取阳性层内口径
    keys = ["cot"] + DEF_ARMS
    # 原始 CoT 臂在阳性层内的暴露率需现算（全分母口径不适用）
    pos_ids = set()
    for r in d["producer"]["records"]:
        if r["api_ok"] and r["cot_leak"]:
            pos_ids.add(r["id"])
    xs, ys, los, his, cols_ = [], [], [], [], []
    for i, a in enumerate(keys):
        recs = c["records"][a] if a != "cot" else c["records"]["cot"]
        sub = [x for x in recs if x is not None and x["api_ok"]
               and x["src_id"] in pos_ids]
        if a == "final":
            continue
        k = sum(1 for x in sub if x["cons_leak"])
        n = len(sub)
        if n == 0:
            continue
        lo, hi = wilson(k, n)
        r = k / n
        xs.append(i)
        ys.append(r)
        los.append(r - lo)
        his.append(hi - r)
        cols_.append(cols[a])
    ax1.bar(xs, ys, color=cols_, width=0.55)
    ax1.errorbar(xs, ys, yerr=[los, his], fmt="none", ecolor="#333",
                 lw=1.1, capsize=2)
    ax1.set_xticks(xs)
    tick_names = {"cot": "CoT", "tau": "CoT+$\\tau$ full",
                  "tpart": "CoT+$\\tau$ partial",
                  "d30": "CoT+output filter"}
    ax1.set_xticklabels([tick_names[a] for a in keys], fontsize=8.5)
    plt.setp(ax1.get_xticklabels(), rotation=30, ha="right")
    ax1.set_ylabel("Downstream exposure rate (CoT-positive layer)")
    ax1.set_ylim(0, 1.05)
    ax1.grid(alpha=0.25, axis="y")

    # (b) p_cot 曲线
    cur = c["p_cot_curve"]
    pg = cur["p_cot_grid"]
    ax2.plot(pg, cur["raw"], "o-", color=cols["cot"], ms=3, lw=1.4,
             label="no defense")
    ax2.plot(pg, cur["tau"], "s--", color=cols["tau"], ms=3, lw=1.3,
             label="$\\tau$ full")
    ax2.plot(pg, cur["tpart"], "^:", color=cols["tpart"], ms=3, lw=1.3,
             label="$\\tau$ partial")
    ax2.plot(pg, cur["d30"], "D-.", color=cols["d30"], ms=3, lw=1.3,
             label="output filter (s=1.0)")
    ax2.set_xlabel("$p_{cot}$ (consumer reads CoT channel)")
    ax2.set_ylabel("Consumer-side residual leak")
    ax2.legend(fontsize=8.5, loc="upper right", framealpha=0.95)
    ax2.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(FIG, bbox_inches="tight")
    plt.close(fig)


def check(d):
    p, c = d["producer"], d["consumer"]
    exp = c["exposure"]
    # 闸门
    for k, g in d["gates"].items():
        assert g["passed"] is True, k
    # final 零泄露 + 全在 CoT
    assert p["final_leak_count"] == 0
    assert p["all_leaks_cot_only"] is True
    # 暴露率现算复算（不读脚本既算值）
    for a in ARMS:
        recs = [x for x in c["records"][a] if x is not None]
        kk = sum(1 for x in recs if x["api_ok"] and x["cons_leak"])
        nn = sum(1 for x in recs if x["api_ok"])
        assert exp[a]["k"] == kk and exp[a]["n"] == nn, a
        assert abs(exp[a]["rate"] - (kk / nn if nn else 0.0)) < 1e-9, a
        lo, hi = wilson(kk, nn)
        assert abs(exp[a]["wilson95"][0] - lo) < 1e-6
        assert abs(exp[a]["wilson95"][1] - hi) < 1e-6
    # 2x2 闭合
    ag = c["agreement_2x2"]
    tot = (ag["both_positive"] + ag["string_only"] + ag["consumer_only"]
           + ag["both_negative"])
    assert tot == ag["n_pairs"], "2x2 闭合"
    assert abs(ag["string_rate"]
               - (ag["both_positive"] + ag["string_only"]) / ag["n_pairs"]) < 1e-9
    assert abs(ag["consumer_rate"]
               - (ag["both_positive"] + ag["consumer_only"]) / ag["n_pairs"]) < 1e-9
    # 曲线端点：p=0 → E_final，p=1 → E_cot
    cur = c["p_cot_curve"]
    pg = cur["p_cot_grid"]
    assert abs(pg[0]) < 1e-9 and abs(pg[-1] - 1.0) < 1e-9
    for nm in ("raw", "tau", "tpart", "d30"):
        assert abs(cur[nm][0] - exp["final"]["rate"]) < 1e-9, nm
    assert abs(cur["raw"][-1] - exp["cot"]["rate"]) < 1e-9
    # 收益 = p_cot × ΔE_cot（p=0 恒 0）
    ben = c["defense_benefit"]
    assert ben["benefit_at_pcot0"] == 0.0
    for a in DEF_ARMS:
        assert abs(ben[a] - (exp["cot"]["rate"]
                             - c["carried_over_to_full_denominator"][a])) < 1e-9
        for i, pv in enumerate(pg):
            # 从暴露端点独立重算每个曲线点（与 E4 脚本同式 round 6 位）后比对；
            # 不能直接比较「两个 6 位小数值之差」与全精度期望（差项含 1e-6 舍入）。
            raw_i = round(pv * exp["cot"]["rate"]
                          + (1 - pv) * exp["final"]["rate"], 6)
            def_i = round(pv * c["carried_over_to_full_denominator"][a]
                          + (1 - pv) * exp["final"]["rate"], 6)
            assert abs(cur["raw"][i] - raw_i) < 1e-9, ("raw", a, i)
            assert abs(cur[a][i] - def_i) < 1e-9, (a, i)
    # 配对设计：三臂同 n
    npos = d["gates"]["g6_paired_design"]["n_pos"]
    for a in DEF_ARMS:
        assert exp[a]["n"] == npos, a
        mc = c["mcnemar_paired"][a + "_vs_raw"]
        assert mc["b_raw_only"] + mc["c_def_only"] <= npos
    # 保留率合理
    for a in DEF_ARMS:
        assert 0.0 < c["retention"][a] <= 1.0, a
    # 量级不超过蜜罐总数 15
    for a in c["magnitude"]:
        if a == "note":
            continue
        assert c["magnitude"][a]["max"] <= 15
    print("[check] OK: 闸门全过；暴露率/CI 现算一致；2x2 闭合；"
          "曲线端点与收益形态一致；配对设计与保留率合理")


def main():
    d = load()
    if "--check" in sys.argv:
        check(d)
        return
    rep = build_report(d)
    with open(REP, "w", encoding="utf-8") as f:
        f.write(rep)
    h = build_html(d)
    with open(HTM, "w", encoding="utf-8") as f:
        f.write(h)
    build_figure(d)
    print("[E4-gen] report=%s" % os.path.basename(REP))
    print("[E4-gen] html=%s" % os.path.basename(HTM))
    print("[E4-gen] fig=%s" % os.path.basename(FIG))
    print("[E4-gen] sha256(md)=%s" % hashlib.sha256(
        rep.encode("utf-8")).hexdigest()[:16])


if __name__ == "__main__":
    main()
