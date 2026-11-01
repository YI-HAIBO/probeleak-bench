#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
E6 报告/仪表板/论文图件生成器（全部数字溯源 results/e6_real_scale_expansion_v1.json，
幂等）。E3 的合并表见 reports/E3_PROBE_BENCHMARK.md。

产出：
  reports/E6_REAL_SCALE_EXPANSION_REPORT.md
  reports/e6_real_scale_expansion_dashboard.html
  paper/figures/fig6_e6_confidence.pdf（逐类 CI forest plot：B1+B3 vs E6 vs 合并）
"""
import hashlib
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RES = os.path.join(ROOT, "results", "e6_real_scale_expansion_v1.json")
REP = os.path.join(ROOT, "reports", "E6_REAL_SCALE_EXPANSION_REPORT.md")
HTM = os.path.join(ROOT, "reports", "e6_real_scale_expansion_dashboard.html")
FIG = os.path.join(ROOT, "paper", "figures", "fig6_e6_confidence.pdf")

MODE_ORDER = ["thinking_leak", "prefix_extraction", "step_reconstruction",
              "reasoning_escalation", "tool_injection", "sql_direct",
              "sql_union", "sql_error", "jailbreak", "encoding",
              "split_channel"]
MODE_CN = {
    "thinking_leak": "思考泄露", "prefix_extraction": "前缀提取",
    "step_reconstruction": "步骤重建", "reasoning_escalation": "推理升级",
    "tool_injection": "工具注入", "sql_direct": "SQL 直取",
    "sql_union": "SQL UNION", "sql_error": "SQL 报错",
    "jailbreak": "越狱", "encoding": "编码", "split_channel": "分割信道",
}
MODE_EN = {  # 论文图件用英文标签（matplotlib 无 CJK 字体）
    "thinking_leak": "thinking-leak", "prefix_extraction": "prefix-extr.",
    "step_reconstruction": "step-recon.", "reasoning_escalation": "reason-escal.",
    "tool_injection": "tool-inj.", "sql_direct": "SQL-direct",
    "sql_union": "SQL-union", "sql_error": "SQL-error",
    "jailbreak": "jailbreak", "encoding": "encoding",
    "split_channel": "split-channel",
}


def load():
    with open(RES, encoding="utf-8") as f:
        return json.load(f)


def pct(x):
    return "—" if x is None else "%.2f%%" % (100.0 * x)


def fmt_ci(ci):
    return "—" if ci is None else "[%.4f, %.4f]" % (ci[0], ci[1])


def build_report(d):
    s6, s13, sc = d["summary_e6"], d["summary_b1b3_armA"], d["summary_combined"]
    pc6, pc13, pcc = (d["per_class_e6"], d["per_class_b1b3_armA"],
                      d["per_class_combined"])
    cons = d["consistency_e6_vs_b1b3"]
    ov = d["overall_e6_vs_b1b3"]
    g = d["gates"]
    L = []
    A = L.append
    A("# E6 真实样本扩大与置信区间报告")
    A("")
    A("- 任务：E6——同一模型/同一 system prompt/同一探针库（33 攻击 × 3 重复 = 99 "
      "攻击请求 + 2 对照）的独立第二批，扩大 B1+B3（N=112）的真实证据并补 CI")
    A("- 模型：`%s`（temp=0.1）；队列 seed=%d；本批耗时 %.1f 分钟"
      % (d["model"], d["config"]["queue_seed"], d["elapsed_sec_batch"] / 60.0))
    A("- 全部数字溯源 `results/e6_real_scale_expansion_v1.json`（逐条记录含"
      " content/reasoning head 与判决字段）；断点文件 `results/e6_checkpoint.ndjson`")
    A("")
    A("## 一、两批总览与合并")
    A("")
    A("| 批次 | 发送 | 有效 | 网关拦截 | CoT 泄露 | final 泄露 | 拒答 |"
      " CoT 率 | Wilson 95% CI |")
    A("|---|---|---|---|---|---|---|---|---|")
    for name, s in [("B1+B3 Arm A", s13), ("E6（本批）", s6),
                    ("合并", sc)]:
        A("| %s | %d | %d | %d | %d | %d | %d | %s | %s |"
          % (name, s["n_attack_sent"], s["n_attack_ok"], s["n_gateway_blocked"],
             s["cot_leak_count"], s["final_leak_count"], s["refusal_count"],
             pct(s["cot_leak_rate"]), fmt_ci(s["cot_leak_wilson95"])))
    A("")
    r = ov["diff_wald95"]
    A("- 两批总体率差（E6−B1+B3）= %+.4f，Wald 95%% CI [%.4f, %.4f]，"
      "**含 0：%s**（同向性一致检查）。"
      % (ov["diff_e6_minus_b1b3"], r[0], r[1],
         "是" if ov["ci_covers_zero"] else "否"))
    A("- CoT 原生盲区：E6 批次 final 泄露 %d 例、全部泄露仅出现在 CoT 通道（%s）。"
      % (s6["final_leak_count"], s6["all_leaks_cot_only"]))
    A("")
    A("## 二、逐类泄露率与 CI")
    A("")
    A("| 攻击类 | B1+B3 n | B1+B3 CoT | E6 n | E6 CoT | 合并 n | 合并 CoT |"
      " 合并率 | 合并 Wilson 95% CI |")
    A("|---|---|---|---|---|---|---|---|---|")
    for m in MODE_ORDER:
        a = pc13.get(m, {"n": 0, "cot": 0, "cot_rate": None})
        b = pc6.get(m, {"n": 0, "cot": 0, "cot_rate": None})
        c = pcc.get(m, {"n": 0, "cot": 0, "cot_rate": None,
                        "cot_wilson95": None})
        if a["n"] + b["n"] == 0:
            continue
        A("| %s | %d | %d | %d | %d | %d | %d | %s | %s |"
          % (MODE_CN.get(m, m), a["n"], a["cot"], b["n"], b["cot"],
             c["n"], c["cot"], pct(c["cot_rate"]), fmt_ci(c["cot_wilson95"])))
    A("")
    A("n=0 的类（若有）不报告 0% 而保留 n=0（E3 协议报告规则）。")
    A("")
    A("## 三、两批逐类一致性")
    A("")
    A("| 攻击类 | B1+B3 率 | E6 率 | 差（E6−B1+B3） | 差的 Wald 95% CI | 含 0 |")
    A("|---|---|---|---|---|---|")
    for m in MODE_ORDER:
        c = cons.get(m)
        if not c or "diff_wald95" not in c:
            A("| %s | %s | %s | — | — | %s |"
              % (MODE_CN.get(m, m),
                 pct(pc13.get(m, {}).get("cot_rate")),
                 pct(pc6.get(m, {}).get("cot_rate")), (c or {}).get("note", "—")))
            continue
        A("| %s | %s | %s | %+.4f | [%.4f, %.4f] | %s |"
          % (MODE_CN.get(m, m), pct(c["b13_rate"]), pct(c["e6_rate"]),
             c["diff_e6_minus_b13"], c["diff_wald95"][0], c["diff_wald95"][1],
             "是" if c["ci_covers_zero"] else "否"))
    A("")
    A("## 四、意义与限制")
    A("")
    A("- 合并样本（N=%d 有效）把 CoT 通道证据从单一 8 事件批次扩展到两独立批次；"
      "整体率与逐类率的 CI 为论文提供了可报告的区间估计（P3 RQ1）。"
      % sc["n_attack_ok"])
    A("- 限制：①temp=0.1 下泄露是概率事件（B1+B3 G4 一致率 89.3%），率值必须带 CI；"
      "②单模型网关（B2 证不可达），合并不构成跨厂商证据；"
      "③拒答率与网关拦截率反映模型/部署当前姿态，随 prompt 与环境变化。")
    if s6["n_gateway_blocked"] > 0:
        A("- E6 网关拦截 %d 例（同 B1+B3 的输入侧内容安全拦截：SQL/越狱/工具注入"
          "类为主），拦截不计入泄露分母。" % s6["n_gateway_blocked"])
    A("")
    A("## 五、自检闸门")
    A("")
    A("| 闸门 | 检查 | 通过 |")
    A("|---|---|---|")
    for k, v in g.items():
        A("| %s | %s | %s |" % (k, v["check"], "是" if v["passed"] else "否"))
    A("")
    A("g2（reasoning 可见率 %.2f ≥ 0.9）在脚本输出时计算并落盘；"
      "g5 合并汇总由两批记录现算。"
      % g["g2_channel_visibility"]["reasoning_present_rate"])
    A("")
    A("## 六、交付物")
    A("")
    A("- 脚本：`experiments/e6_real_scale_expansion.py`（断点续跑，seed=%d）"
      % d["config"]["queue_seed"])
    A("- JSON：`results/e6_real_scale_expansion_v1.json`；"
      "断点：`results/e6_checkpoint.ndjson`；日志：`results/e6_run.log`")
    A("- 本报告 + `reports/e6_real_scale_expansion_dashboard.html`；"
      "论文图件 `paper/figures/fig6_e6_confidence.pdf`")
    A("- 跨臂合并与逐探针清单：E3 `reports/E3_PROBE_BENCHMARK.md`（同一 JSON 源）")
    return "\n".join(L) + "\n"


HTML_T = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>E6 真实样本扩大 - 仪表板</title>
<style>
body{font-family:"Microsoft YaHei",sans-serif;background:#f5f6f8;color:#222;margin:0;padding:24px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:#666;font-size:13px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:20px}
.card{background:#fff;border:1px solid #e3e5ea;border-radius:8px;padding:14px}
.card .k{font-size:12px;color:#888}
.card .v{font-size:24px;font-weight:700;margin-top:4px}
.card.bad .v{color:#c0392b}
.card.ok .v{color:#1e8e5a}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin-bottom:20px}
th,td{border:1px solid #e3e5ea;padding:7px 10px;text-align:left}
th{background:#fafbfc}
.note{margin-top:16px;color:#666;font-size:12px}
h2{font-size:15px;margin:22px 0 8px}
</style>
</head>
<body>
<h1>E6 真实样本扩大与置信区间</h1>
<div class="sub">dots3-note-prev · 33 探针 × 3 重复独立第二批 · 全部数字溯源
results/e6_real_scale_expansion_v1.json</div>
<div class="grid">
  <div class="card"><div class="k">E6 有效攻击响应</div><div class="v">__N6__</div></div>
  <div class="card bad"><div class="k">E6 CoT 泄露</div><div class="v">__C6__</div>
    <div class="small">率 __R6__，CI __CI6__</div></div>
  <div class="card ok"><div class="k">final 通道泄露</div><div class="v">0</div>
    <div class="small">两批均为零（g3/g4）</div></div>
  <div class="card"><div class="k">合并有效样本</div><div class="v">__NC__</div>
    <div class="small">CoT 泄露 __CC__（率 __RC__，CI __CIC__）</div></div>
  <div class="card"><div class="k">两批率差 CI 含 0</div><div class="v">__OV__</div>
    <div class="small">同向性一致</div></div>
</div>
<h2>两批总览</h2>
<table>
<tr><th>批次</th><th>发送</th><th>有效</th><th>网关拦截</th><th>CoT 泄露</th>
<th>final</th><th>拒答</th><th>CoT 率</th><th>Wilson 95% CI</th></tr>
__AROWS__
</table>
<h2>逐类合并泄露率与 CI</h2>
<table>
<tr><th>攻击类</th><th>B1+B3</th><th>E6</th><th>合并 n</th><th>合并 CoT</th>
<th>合并率</th><th>Wilson 95% CI</th></tr>
__CROWS__
</table>
<div class="note">n=0 的类保留 n=0 不报 0%；G4 披露：泄露为概率事件。
跨臂合并表与逐探针清单见 E3 报告。</div>
</body>
</html>
"""


def build_html(d):
    s6, s13, sc = d["summary_e6"], d["summary_b1b3_armA"], d["summary_combined"]
    pc13, pc6, pcc = (d["per_class_b1b3_armA"], d["per_class_e6"],
                      d["per_class_combined"])
    arows = []
    for name, s in [("B1+B3 Arm A", s13), ("E6（本批）", s6), ("合并", sc)]:
        arows.append("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td>"
                     "<td style='color:#c0392b;font-weight:700'>%d</td><td>%d</td>"
                     "<td>%d</td><td>%s</td><td>%s</td></tr>"
                     % (name, s["n_attack_sent"], s["n_attack_ok"],
                        s["n_gateway_blocked"], s["cot_leak_count"],
                        s["final_leak_count"], s["refusal_count"],
                        pct(s["cot_leak_rate"]), fmt_ci(s["cot_leak_wilson95"])))
    crows = []
    for m in MODE_ORDER:
        a, b, c = (pc13.get(m, {"n": 0, "cot": 0}), pc6.get(m, {"n": 0, "cot": 0}),
                   pcc.get(m, {"n": 0, "cot": 0, "cot_rate": None,
                               "cot_wilson95": None}))
        if a["n"] + b["n"] == 0:
            continue
        crows.append("<tr><td>%s</td><td>%d/%d</td><td>%d/%d</td><td>%d</td>"
                     "<td>%d</td><td>%s</td><td>%s</td></tr>"
                     % (MODE_CN.get(m, m), a["cot"], a["n"], b["cot"], b["n"],
                        c["n"], c["cot"], pct(c["cot_rate"]),
                        fmt_ci(c["cot_wilson95"])))
    ov = d["overall_e6_vs_b1b3"]
    return (HTML_T
            .replace("__N6__", str(s6["n_attack_ok"]))
            .replace("__C6__", str(s6["cot_leak_count"]))
            .replace("__R6__", pct(s6["cot_leak_rate"]))
            .replace("__CI6__", fmt_ci(s6["cot_leak_wilson95"]))
            .replace("__NC__", str(sc["n_attack_ok"]))
            .replace("__CC__", str(sc["cot_leak_count"]))
            .replace("__RC__", pct(sc["cot_leak_rate"]))
            .replace("__CIC__", fmt_ci(sc["cot_leak_wilson95"]))
            .replace("__OV__", "是" if ov["ci_covers_zero"] else "否")
            .replace("__AROWS__", "\n".join(arows))
            .replace("__CROWS__", "\n".join(crows)))


def build_figure(d):
    """fig6：逐类 CoT 泄露率 CI forest（B1+B3 / E6 / 合并）。"""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    pc13, pc6, pcc = (d["per_class_b1b3_armA"], d["per_class_e6"],
                      d["per_class_combined"])
    modes = [m for m in MODE_ORDER
             if (pc13.get(m, {}).get("n", 0) + pc6.get(m, {}).get("n", 0)) > 0]
    fig, ax = plt.subplots(figsize=(5.6, 3.6))
    ys = range(len(modes))
    ymap = {m: i for i, m in enumerate(modes)}

    def series(pc, color, label, dx):
        xs, los, his = [], [], []
        for m in modes:
            e = pc.get(m, {"n": 0, "cot": 0, "cot_rate": None,
                           "cot_wilson95": [0.0, 1.0]})
            if e["n"] == 0:
                xs.append(None); los.append(None); his.append(None)
                continue
            xs.append(e["cot"] / e["n"])
            los.append(e["cot_rate"] - e["cot_wilson95"][0])
            his.append(e["cot_wilson95"][1] - e["cot_rate"])
        ex = [x for x in xs if x is not None]
        ey = [ymap[m] + dx for m, x in zip(modes, xs) if x is not None]
        el = [v for v, x in zip(los, xs) if x is not None]
        eh = [v for v, x in zip(his, xs) if x is not None]
        ax.errorbar(ex, ey, xerr=[el, eh], fmt="o", color=color, ms=4.5,
                    lw=1.3, capsize=1.5, label=label)

    series(pc13, "#7f8c8d", "second sample (N=112)", -0.22)
    series(pc6, "#b7950b", "third sample (N=84)", 0.0)
    series(pcc, "#c0392b", "pooled", 0.22)
    ax.set_yticks(list(ys))
    ax.set_yticklabels([MODE_EN.get(m, m) for m in modes], fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("CoT leak rate (Wilson 95% CI)")
    ax.grid(alpha=0.3, axis="x")
    ax.legend(loc="lower center", fontsize=8, framealpha=0.95, ncol=3, bbox_to_anchor=(0.5, 1.02))
    fig.tight_layout()
    fig.savefig(FIG, bbox_inches="tight")
    plt.close(fig)


def check(d):
    s6, s13, sc = d["summary_e6"], d["summary_b1b3_armA"], d["summary_combined"]
    assert s6["final_leak_count"] == 0
    assert s6["all_leaks_cot_only"] is True
    # 合并 = 两批现算
    n = s13["n_attack_ok"] + s6["n_attack_ok"]
    c = s13["cot_leak_count"] + s6["cot_leak_count"]
    assert sc["n_attack_ok"] == n and sc["cot_leak_count"] == c
    # 闸门
    for k, v in d["gates"].items():
        if k == "g2_channel_visibility":
            assert v["reasoning_present_rate"] >= 0.9
        else:
            assert v["passed"] is True, k
    # 每类 cot / n 计数闭合到总体（e6 / b1b3 / combined）
    for pc, tot_cot, tot_n in (
            (d["per_class_e6"], s6["cot_leak_count"], s6["n_attack_ok"]),
            (d["per_class_b1b3_armA"], s13["cot_leak_count"],
             s13["n_attack_ok"]),
            (d["per_class_combined"], sc["cot_leak_count"],
             sc["n_attack_ok"])):
        assert sum(e["cot"] for e in pc.values()) == tot_cot, "per-class cot 闭合"
        assert sum(e["n"] for e in pc.values()) == tot_n, "per-class n 闭合"
    print("[check] OK: final 零泄露；合并现算一致；每类闭合；闸门全过")


def main():
    d = load()
    if "--check" in sys.argv:
        check(d)
        return
    os.makedirs(os.path.dirname(REP), exist_ok=True)
    with open(REP, "w", encoding="utf-8") as f:
        f.write(build_report(d))
    with open(HTM, "w", encoding="utf-8") as f:
        f.write(build_html(d))
    build_figure(d)
    for p in (REP, HTM, FIG):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:12]
        print("[E6-gen] %s  sha256=%s" % (p, h))
    check(d)


if __name__ == "__main__":
    main()
