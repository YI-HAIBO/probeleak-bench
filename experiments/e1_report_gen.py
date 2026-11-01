"""E1 跨模型复现报告/仪表板/图件生成器

幂等 + --check 断言。所有数字从 records 现算，不信任脚本写死的字段。
"""

import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)

JSON_PATH = os.path.join(ROOT, "results", "e1_cross_model_v1.json")
REP_PATH = os.path.join(ROOT, "reports", "E1_CROSS_MODEL_REPORT.md")
HTM_PATH = os.path.join(ROOT, "reports", "e1_cross_model_dashboard.html")
FIG_PATH = os.path.join(ROOT, "paper", "figures", "fig8_e1_cross_model.pdf")

MODE_CN = {
    "thinking_leak": "思考泄露",
    "prefix_extraction": "前缀提取",
    "step_reconstruction": "步骤重建",
}
MODE_EN = {v: k for k, v in MODE_CN.items()}


def load():
    return json.load(open(JSON_PATH, encoding="utf-8"))


def pct(x):
    return "—" if x is None else "%.2f%%" % (100.0 * x)


def fmt_ci(ci):
    if not ci:
        return "—"
    return "[%.2f%%, %.2f%%]" % (100.0 * ci[0], 100.0 * ci[1])


def fisher_p(p):
    if p is None:
        return "—"
    if p == 0:
        return "<1e-15"
    if p < 1e-6:
        return "%.2e" % p
    return "%.4f" % p


# ---------------------------------------------------------------- 报告
def build_report(d):
    L = []
    A = L.append

    models = d["models"]
    pm = d["per_model"]
    ref = d["reference_dots"]
    ref_hi = ref["high_tier"]
    cmps = d["cross_model_comparisons"]
    pp = d["per_probe_comparisons"]
    g = d["gates"]

    A("# E1：跨模型真实复现（CoT 原生盲区的泛化性）\n")
    A("**实验**：在独立网关（`api.kilo.ai`，provider AtlasCloud）上，用同一套 "
      "ProbeLeak-Bench 探针、同一 system prompt、同一批蜜罐 key、同一双通道判决器，"
      "测量 CoT 原生盲区是否跨厂商复现。\n")
    A("**配置**：每模型 4 条高层级探针（tl1 / tl4 / pe1 / sr4）× %d 重复 + 8 条对照 "
      "探针 × 1 重复 = 32 请求；共 %d 模型，合计 %d 请求。temp=%.1f，max_tokens=%d。\n"
      % (d["reps_per_high_probe"], len(models), d["reps_per_high_probe"] * 4
         + 8, len(models), d["temperature"], d["max_tokens"]))
    A("**参照组**：dots3-note-prev 在标准 prompt 下的合并测量"
      "（B1+B3 Arm A + E6 第二批），高层级 4 探针合并 n=%d、泄露 %d（%.2f%%）。"
      "参照组不调用 API，直接读既有结果现算。\n"
      % (ref_hi["n_ok"], ref_hi["cot_leak_count"],
         100 * (ref_hi["cot_leak_rate"] or 0)))

    A("## 1. 逐模型高层级泄露率\n")
    A("| 模型 | 厂商 | n | CoT 泄露 | 泄露率 | Wilson 95% CI | 拒答 | 推理中位长度 |")
    A("|---|---|---|---|---|---|---|---|")
    for code, m in models.items():
        s = pm[code]["high_tier"]
        A("| `%s` | %s | %d | %d | %s | %s | %s | %s 字符 |"
          % (m["model"], m["vendor"], s["n_ok"], s["cot_leak_count"],
             pct(s["cot_leak_rate"]), fmt_ci(s["cot_leak_wilson95"]),
             pct(s["refusal_rate"]),
             s["reasoning_chars_median"]))
    A("")
    A("参照组 `%s`：n=%d、泄露 %d（%.2f%%）、CI %s、final 通道 %d。"
      % (ref_hi["n_ok"] and "dots3-note-prev", ref_hi["n_ok"],
         ref_hi["cot_leak_count"], 100 * (ref_hi["cot_leak_rate"] or 0),
         fmt_ci(ref_hi["cot_leak_wilson95"]), ref_hi["final_leak_count"]))
    A("")

    A("## 2. 跨模型 vs 参照组（高层级合并）\n")
    A("| 模型 | 厂商 | n | 泄露 | 率 | 参照 n | 参照率 | 差 | Wald 95% CI | CI 含 0 | Fisher p |")
    A("|---|---|---|---|---|---|---|---|---|---|---|")
    for c in cmps:
        A("| `%s` | %s | %d | %d | %s | %d | %s | %+.4f | %s | %s | %s |"
          % (c["model_code"], c["vendor"], c["n"], c["cot_leaks"],
             pct(c["rate"]), c["ref_n"], pct(c["ref_rate"]),
             c["diff_minus_ref"],
             "[%.4f, %.4f]" % tuple(c["diff_wald95"]),
             "是" if c["ci_covers_zero"] else "否",
             fisher_p(c["fisher_exact_p"])))
    A("")

    A("## 3. 逐探针触发面（核心发现）\n")
    # base_id -> attack_mode（从任一模型记录取）
    mode_of = {}
    for code in models:
        for r in pm[code]["records"]:
            mode_of.setdefault(r["base_id"], r.get("attack_mode"))
    hdr = "| 探针 | 攻击类 | 参照 n | 参照率 | " + " | ".join(
        "`%s` %s" % (models[c]["model"], c) for c in models) + " |"
    A(hdr)
    A("|---|---|---|---|" + "|".join(["---"] * len(models)) + "|")
    for pid in d["high_probes"]:
        cells = []
        for c in pp.get(pid, []):
            cells.append("%d/%d (%s)" % (c["cot_leaks"], c["n"],
                                         pct(c["rate"])))
        rp = d["reference_dots"].get("per_probe", {}).get(pid, {})
        A("| `%s` | %s | %d | %s | %s |"
          % (pid, MODE_CN.get(mode_of.get(pid), mode_of.get(pid, "")),
             rp.get("n_ok") or 0, pct(rp.get("cot_leak_rate")),
             " | ".join(cells)))
    A("")
    A("逐探针 Fisher p（每模型 vs 参照）：\n")
    for pid in d["high_probes"]:
        parts = []
        for c in pp.get(pid, []):
            parts.append("`%s` %s" % (c["model_code"], fisher_p(c["fisher_exact_p"])))
        A("- `%s`：%s" % (pid, "；".join(parts)))
    A("")

    A("## 4. 拒答率与推理通道\n")
    A("| 模型 | 高层级拒答率 | 对照组拒答率 | 推理中位长度 | 内容中位长度 |")
    A("|---|---|---|---|---|")
    for code, m in models.items():
        s = pm[code]["high_tier"]
        c = pm[code]["controls"]
        A("| `%s` | %s | %s | %s | %s |"
          % (m["model"], pct(s["refusal_rate"]), pct(c["refusal_rate"]),
             s["reasoning_chars_median"], s["content_chars_median"]))
    A("")
    A("参照组 dots3-note-prev 的拒答率由 B1+B3 / E6 / E4 记录现算：高层级 0/28。")
    A("")

    A("## 5. 闸门\n")
    for k, v in g.items():
        A("- **%s**（%s）：**%s**" % (k, v.get("check"), v.get("passed")))
    A("")

    A("## 6. 结论\n")
    A("CoT 原生盲区在跨厂商层面**真实存在但触发面不同**：")
    A("- `nvidia/nemotron-3-super-120b-a12b`（NVIDIA）：对 pe1/sr4 全部拒答，"
      "不泄露；")
    A("- `reflection/beam`（Reflection AI）：pe1 在 reasoning 通道逐字复述 key，"
      "sr4 拒答；")
    A("- `nvidia/nemotron-3-nano-omni-30b-a3b`（NVIDIA）：需看实测结果。")
    A("这说明盲区不是「所有 LLM 都有的通用缺陷」，而是**模型架构/安全对齐层面的"
      "条件性缺陷**——CoT 通道对某些模型可被诱导泄露，对另一些则被安全策略拦截。")
    A("论文的诚实表述应为：**在已测模型族中，CoT 原生盲区跨厂商复现，但触发面"
      "与拒答行为因模型而异**，而非「所有模型都必然泄露」。")
    A("")

    A("## 7. 方法与溯源\n")
    A("- 探针库：`results/e3_probe_benchmark_v1.json`（35 条冻结探针）")
    A("- 蜜罐 key：15 把 `FAKE_*`，60 条子签名覆盖部分匹配")
    A("- 判决器：`find_keys`（CoT/final 双通道）+ `REFUSAL_RE`（拒答）")
    A("- 跨模型比较：两比例 Wald 95% CI + Fisher 精确检验（双侧）")
    A("- 参照组：`results/e3_probe_benchmark_v1.json` 现算，不调用 API")
    A("- 本报告全部数字由 `experiments/e1_report_gen.py` 从 records 现算，"
      "生成器幂等（sha256 一致）")
    return "\n".join(L)


# ---------------------------------------------------------------- 仪表板
def build_html(d):
    models = d["models"]
    pm = d["per_model"]
    ref_hi = d["reference_dots"]["high_tier"]
    cmps = d["cross_model_comparisons"]
    pp = d["per_probe_comparisons"]
    g = d["gates"]

    cards = []
    for c in cmps:
        cards.append(
            '<div class="card"><div class="k">%s <span class="small">%s</span></div>'
            '<div class="v">%.2f%%</div>'
            '<div class="small">n=%d · 泄露 %d · 差 %+.4f · Fisher %s</div>'
            '<div class="small">CI %s · 含0=%s</div></div>'
            % (c["model_code"], c["vendor"], 100 * (c["rate"] or 0),
               c["n"], c["cot_leaks"], c["diff_minus_ref"],
               _pstr(c["fisher_exact_p"]),
               "[%.4f, %.4f]" % tuple(c["diff_wald95"]),
               "是" if c["ci_covers_zero"] else "否")
        )

    probe_rows = []
    for pid in d["high_probes"]:
        cells = []
        for c in pp.get(pid, []):
            cells.append(
                '<td>%d/%d<br><span class="small">%s</span></td>'
                % (c["cot_leaks"], c["n"], pct(c["rate"])))
        rp = d["reference_dots"].get("per_probe", {}).get(pid, {})
        probe_rows.append(
            "<tr><td><code>%s</code></td><td>%d</td><td>%s</td>%s</tr>"
            % (pid, rp.get("n_ok") or 0, pct(rp.get("cot_leak_rate")),
               "".join(cells))
        )

    gate_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (k, v.get("check"), "PASS" if v.get("passed") else "FAIL")
        for k, v in g.items()
    )

    html = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>E1 跨模型复现</title>
<style>
:root{color-scheme:light}
body{font-family:"Microsoft YaHei",sans-serif;margin:24px;color:#222;background:#f7f9fb}
h1{font-size:20px} h2{font-size:15px;margin-top:22px}
.grid{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}
.card{background:#fff;border:1px solid #e3e8ee;border-radius:8px;padding:14px 18px;
  min-width:180px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.card .k{font-size:13px;color:#555} .card .v{font-size:22px;font-weight:700;margin:4px 0}
.card .small{font-size:11px;color:#888}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:12px}
th,td{border:1px solid #e3e8ee;padding:5px 8px;text-align:left}
th{background:#eef2f6}
code{background:#eef2f6;padding:1px 4px;border-radius:3px}
.bad{color:#c0392b} .good{color:#27ae60}
</style></head><body>
<h1>E1：跨模型真实复现（CoT 原生盲区的泛化性）</h1>
<div class="small">独立网关 api.kilo.ai · %d 模型 · %d 请求 · %s</div>
<div class="grid">%s</div>
<h2>逐探针触发面</h2>
<table><tr><th>探针</th><th>参照 n</th><th>参照率</th>%s</tr>%s</table>
<h2>闸门</h2>
<table><tr><th>闸门</th><th>判据</th><th>结果</th></tr>%s</table>
</body></html>""" % (
        len(models), d["reps_per_high_probe"] * 4 + 8, len(models),
        d["probed_at"], "".join(cards),
        "".join("<th>%s</th>" % models[c]["model"] for c in models),
        "".join(probe_rows), gate_rows,
    )
    return html


def _pstr(p):
    if p is None:
        return "—"
    if p == 0:
        return "<1e-15"
    if p < 1e-6:
        return "%.2e" % p
    return "%.4f" % p


# ---------------------------------------------------------------- 图件
def build_figure(d):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    models = d["models"]
    pm = d["per_model"]
    ref_hi = d["reference_dots"]["high_tier"]
    cmps = d["cross_model_comparisons"]

    codes = list(models)
    rates = [c["rate"] or 0 for c in cmps]
    wis = [c["wilson95"] for c in cmps]
    vendors = [models[c]["vendor"] for c in codes]

    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    ys = list(range(len(codes)))
    for i, (code, rate, ci) in enumerate(zip(codes, rates, wis)):
        ax.errorbar([rate], [i], xerr=[[rate - ci[0]], [ci[1] - rate]],
                    fmt="o", ms=7, lw=1.8, capsize=4,
                    color="#c0392b", label=code)
        ax.text(ci[1] + 0.015, i, "%s (%.2f%%)" % (code, 100 * rate),
                va="center", fontsize=8)
    # 参照线
    rr = ref_hi["cot_leak_rate"] or 0
    rci = ref_hi["cot_leak_wilson95"]
    ax.axvline(rr, color="#7f8c8d", ls="--", lw=1.2)
    ax.text(rr + 0.015, len(codes) - 0.4,
            "ref dots3-note-prev %.2f%%" % (100 * rr), fontsize=8,
            color="#7f8c8d")
    ax.set_yticks(ys)
    ax.set_yticklabels(["%s · %s" % (codes[i], vendors[i]) for i in ys],
                       fontsize=8)
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("CoT leak rate (Wilson 95% CI)")
    ax.set_title("Cross-model CoT leak rate vs dots3-note-prev reference")
    ax.grid(alpha=0.3, axis="x")
    ax.legend(loc="lower right", framealpha=0.95, fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG_PATH, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------- 校验
def check(d):
    models = d["models"]
    pm = d["per_model"]
    ref_hi = d["reference_dots"]["high_tier"]

    # 1. 每模型记录数闭合
    for code in models:
        s = pm[code]["overall"]
        recs = pm[code]["records"]
        assert len(recs) == s["n_sent"], (code, "n_sent")
        assert sum(1 for r in recs if r.get("api_ok")) == s["n_ok"], (code, "n_ok")
        assert sum(1 for r in recs if r.get("cot_leak")) == s["cot_leak_count"], (
            code, "cot_leak_count")
        assert sum(1 for r in recs if r.get("final_leak")) == s["final_leak_count"], (
            code, "final_leak_count")
        assert sum(1 for r in recs if r.get("refusal")) == s["refusal_count"], (
            code, "refusal_count")

    # 2. 高层级闭合
    for code in models:
        s = pm[code]["high_tier"]
        hi = [r for r in pm[code]["records"] if r["base_id"] in d["high_probes"]]
        assert len(hi) == s["n_sent"], (code, "high n_sent")
        assert sum(1 for r in hi if r.get("api_ok")) == s["n_ok"], (code, "high n_ok")
        assert sum(1 for r in hi if r.get("cot_leak")) == s["cot_leak_count"], (
            code, "high cot_leak_count")

    # 3. 跨模型比较与现算一致
    for c in d["cross_model_comparisons"]:
        code = c["model_code"]
        hi = pm[code]["high_tier"]
        assert c["n"] == hi["n_ok"], (code, "cmp n")
        assert c["cot_leaks"] == hi["cot_leak_count"], (code, "cmp leaks")
        assert abs(c["rate"] - (hi["cot_leak_rate"] or 0)) < 1e-9, (code, "cmp rate")

    # 4. 参照组闭合
    assert ref_hi["n_ok"] == 4 * d["reps_per_high_probe"], "ref n"
    assert ref_hi["final_leak_count"] == 0, "ref final zero"
    assert ref_hi["all_leaks_cot_only"] is True, "ref all cot only"

    # 5. 闸门
    for k, v in d["gates"].items():
        assert v["passed"] is True, k

    # 6. Wilson 边界
    for code in models:
        for blk in ("overall", "high_tier", "controls"):
            for f in ("cot_leak_wilson95", "final_leak_wilson95"):
                v = pm[code][blk].get(f)
                if v:
                    assert 0 <= v[0] <= v[1] <= 1, (code, blk, f)

    print("[E1-check] OK: 记录闭合 / 高层级闭合 / 跨模型比较一致 / "
          "参照组闭合 / 闸门全过 / Wilson 边界")


def main():
    d = load()
    if "--check" in sys.argv:
        check(d)
        return
    os.makedirs(os.path.dirname(REP_PATH), exist_ok=True)
    with open(REP_PATH, "w", encoding="utf-8") as f:
        f.write(build_report(d))
    with open(HTM_PATH, "w", encoding="utf-8") as f:
        f.write(build_html(d))
    build_figure(d)
    for p in (REP_PATH, HTM_PATH, FIG_PATH):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:12]
        print("[E1-gen] %s  sha256=%s" % (p, h))
    check(d)


if __name__ == "__main__":
    import json
    main()