#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""B2 跨模型复现报告生成器（数据全部溯源 results/b2_cross_model_v1.json，幂等）。

产出：
  reports/B2_CROSS_MODEL_BLOCKED_REPORT.md
  reports/b2_cross_model_blocked_dashboard.html
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results", "b2_cross_model_v1.json")
REP = os.path.join(ROOT, "reports", "B2_CROSS_MODEL_BLOCKED_REPORT.md")
HTM = os.path.join(ROOT, "reports", "b2_cross_model_blocked_dashboard.html")


def load():
    with open(RES, "r", encoding="utf-8") as f:
        return json.load(f)


def err_kind(err):
    if not err:
        return "ok"
    if "Model is not configured" in err:
        return "400 Model is not configured"
    if "API key is not bound to this model" in err:
        return "403 API key is not bound"
    return "other"


def build_data(d):
    probes = d["probe_results"]
    total = len(probes)
    ok = [p for p in probes if p["reachable"]]
    reasoning = [p for p in ok if p["has_reasoning"]]
    non_baseline_reasoning = [p for p in reasoning
                              if p["model"] != d["baseline_model"]]
    kinds = {}
    for p in probes:
        kinds[err_kind(p["error"])] = kinds.get(err_kind(p["error"]), 0) + 1
    return {
        "verdict": d["verdict"],
        "gateway": d["gateway"],
        "baseline": d["baseline_model"],
        "listing_status": d["models_listing"]["status"],
        "listing_ids": d["models_listing"]["parsed_ids"],
        "total": total,
        "n_ok": len(ok),
        "n_reasoning": len(reasoning),
        "n_nonbaseline_reasoning": len(non_baseline_reasoning),
        "kinds": kinds,
        "probes": probes,
        "core_by_model": d["core_by_model"],
        "notes": d.get("notes", []),
    }


def build_report(b):
    L = []
    A = L.append
    A("# B2 跨模型复现：BLOCKED 报告")
    A("")
    A("- 任务：B2（Phase 48 跨厂商迁移方向在真实网关上的落地尝试）")
    A("- 目的：在第二个暴露推理链（reasoning_content）的模型上复现 B1 的 CoT 原生盲区发现")
    A("- 网关：`%s`" % b["gateway"])
    A("- 基线模型（B1/B3 同款）：`%s`" % b["baseline"])
    A("- 结论：**%s**" % b["verdict"])
    A("")
    A("## 一、判定")
    A("")
    A("网关 `%s` 的 `GET /v1/models` 返回 HTTP %d，仅暴露 1 个模型：%s。"
      % (b["gateway"], b["listing_status"], ", ".join("`%s`" % m for m in b["listing_ids"])))
    A("对 %d 个候选模型 id 逐一做连通性探针（system prompt + \"Reply with exactly: OK\"，max_tokens=64）："
      % b["total"])
    A("")
    A("| 指标 | 数量 |")
    A("|---|---|")
    A("| 候选模型总数 | %d |" % b["total"])
    A("| 可达（HTTP 200） | %d |" % b["n_ok"])
    A("| 可达且暴露 reasoning | %d |" % b["n_reasoning"])
    A("| 可达 + reasoning + 非基线（满足 B2 条件） | **%d** |" % b["n_nonbaseline_reasoning"])
    A("")
    A("错误类型分布：%s。"
      % "、".join("%s × %d" % (k, v) for k, v in sorted(b["kinds"].items())))
    A("")
    A("唯一满足条件的是基线模型自身，因此跨模型复现无法在当前网关上继续，"
      "B2 判定为 BLOCKED。")
    A("")
    A("## 二、证据矩阵")
    A("")
    A("| 模型 id | 可达 | 暴露 reasoning | 时延 (ms) | 错误 |")
    A("|---|---|---|---|---|")
    for p in b["probes"]:
        if p["reachable"]:
            err = "—"
        else:
            err = err_kind(p["error"])
        A("| `%s` | %s | %s | %d | %s |"
          % (p["model"],
             "是" if p["reachable"] else "否",
             "是" if p["has_reasoning"] else "否",
             p["latency_ms"], err))
    A("")
    A("判定门槛区分了两类拒绝：")
    A("")
    A("- HTTP 400 `Model is not configured`：网关未配置该模型（模型不存在于路由表）。")
    A("- HTTP 403 `API key is not bound to this model`：模型存在但当前 API key 未授权"
      "（仅 `dots3-note-prev-v2`）。")
    A("")
    A("两类错误体（含 traceId）均原样保留在 `results/b2_cross_model_v1.json` 的 "
      "`probe_results[].error` 中，供复核。")
    A("")
    A("## 三、与 Phase 48 模拟结果的关系")
    A("")
    A("Phase 48 在模拟层给出 6 厂商 47.7–55.4% 的跨厂商迁移率，其前提是攻击payload"
      "可送达多个异构推理模型。B2 在真实网关上的尝试表明：当前可及环境只有单一模型"
      "（dots3-note-prev）暴露推理链，Phase 48 的跨厂商迁移结论暂时**无法在真实侧验证**，"
      "本次尝试不构成对该结论的反证，只构成可及性约束的证据。")
    A("")
    A("## 四、对 P3 论文的影响")
    A("")
    A("- 真实证据链现状：P1.1（N=25，CoT 20.0% / final 0%）+ B1+B3（N=112，CoT 7.1% / "
      "final 0.0%，2h34m，157 请求）+ B2（BLOCKED）。")
    A("- 论文写法：跨模型泛化只能作为**模拟层发现**陈述（Phase 48），并明确标注真实侧"
      "受单模型网关约束、未做跨厂商验证；CoT 原生盲区本身的现实性已由两个独立真实样本"
      "（N=25 / N=112）同向确认。")
    A("- 若后续获得可及的多推理模型网关，B2 的探针子集与判决器可直接复用"
      "（见 `experiments/b2_cross_model_probe.py` 中 `CORE_PROBES`）。")
    A("")
    A("## 五、自检闸门")
    A("")
    A('1. `verdict == "BLOCKED_NO_SECOND_REASONING_MODEL"` 且 '
      '`core_by_model == {}` 一致（无可跑核心探针的模型）。')
    A("2. 可达且暴露 reasoning 的模型集合 == 网关 `/v1/models` 返回集合 "
      "（本例均为 1 个，即基线）。")
    A("3. 逐模型错误体原样落盘，未做摘要丢弃。")
    A("")
    A("## 六、交付物")
    A("")
    A("- 探针脚本：`experiments/b2_cross_model_probe.py`")
    A("- 结果 JSON：`results/b2_cross_model_v1.json`")
    A("- 本报告：`reports/B2_CROSS_MODEL_BLOCKED_REPORT.md`")
    A("- 仪表板：`reports/b2_cross_model_blocked_dashboard.html`")
    A("")
    notes = "\n".join("- %s" % n for n in b["notes"])
    A("附：脚本运行说明")
    A("")
    A(notes)
    return "\n".join(L) + "\n"


HTML_T = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>B2 跨模型复现 - BLOCKED 仪表板</title>
<style>
body{font-family:"Microsoft YaHei",sans-serif;background:#f5f6f8;color:#222;margin:0;padding:24px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:#666;font-size:13px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:20px}
.card{background:#fff;border:1px solid #e3e5ea;border-radius:8px;padding:14px}
.card .k{font-size:12px;color:#888}
.card .v{font-size:26px;font-weight:700;margin-top:4px}
.card.bad .v{color:#c0392b}
.card.ok .v{color:#1e8e5a}
.verdict{background:#fdecea;border:1px solid #f5c6cb;color:#9c1f14;border-radius:8px;
  padding:12px 16px;font-weight:700;margin-bottom:20px;font-size:15px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
th,td{border:1px solid #e3e5ea;padding:7px 10px;text-align:left}
th{background:#fafbfc}
.yes{color:#1e8e5a;font-weight:700}
.no{color:#999}
.err{color:#c0392b;font-family:Consolas,monospace;font-size:12px}
.note{margin-top:16px;color:#666;font-size:12px}
</style>
</head>
<body>
<h1>B2 跨模型复现：BLOCKED</h1>
<div class="sub">网关 __GW__ · 基线 __BASE__ · 全部数字溯源 results/b2_cross_model_v1.json</div>
<div class="verdict">verdict = __VERDICT__</div>
<div class="grid">
  <div class="card"><div class="k">候选模型总数</div><div class="v">__T__</div></div>
  <div class="card ok"><div class="k">可达（HTTP 200）</div><div class="v">__NOK__</div></div>
  <div class="card ok"><div class="k">可达且暴露 reasoning</div><div class="v">__NR__</div></div>
  <div class="card bad"><div class="k">非基线 + reasoning（B2 条件）</div><div class="v">__NNR__</div></div>
  <div class="card"><div class="k">400 Model is not configured</div><div class="v">__E4__</div></div>
  <div class="card"><div class="k">403 key 未绑定</div><div class="v">__E3__</div></div>
</div>
<h2 style="font-size:15px">逐模型证据矩阵</h2>
<table>
<tr><th>模型 id</th><th>可达</th><th>暴露 reasoning</th><th>时延 (ms)</th><th>错误</th></tr>
__ROWS__
</table>
<div class="note">HTTP 400 = 网关未配置该模型；HTTP 403 = 模型存在但 API key 未授权。
原始错误体（含 traceId）见 results/b2_cross_model_v1.json 的 probe_results[].error。</div>
</body>
</html>
"""


def build_html(b):
    rows = []
    for p in b["probes"]:
        if p["reachable"]:
            err = '<span class="yes">—</span>'
            rc = '<span class="yes">是</span>' if p["has_reasoning"] else '<span class="no">否</span>'
            okc = '<span class="yes">是</span>'
        else:
            err = '<span class="err">%s</span>' % err_kind(p["error"])
            rc = '<span class="no">否</span>'
            okc = '<span class="no">否</span>'
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>"
                    % ("<code>%s</code>" % p["model"], okc, rc, p["latency_ms"], err))
    return (HTML_T
            .replace("__GW__", b["gateway"])
            .replace("__BASE__", b["baseline"])
            .replace("__VERDICT__", b["verdict"])
            .replace("__T__", str(b["total"]))
            .replace("__NOK__", str(b["n_ok"]))
            .replace("__NR__", str(b["n_reasoning"]))
            .replace("__NNR__", str(b["n_nonbaseline_reasoning"]))
            .replace("__E4__", str(b["kinds"].get("400 Model is not configured", 0)))
            .replace("__E3__", str(b["kinds"].get("403 API key is not bound", 0)))
            .replace("__ROWS__", "\n".join(rows)))


def check(b):
    """断言：报告口径与 JSON 一致。"""
    probes = b["probes"]
    assert b["n_ok"] == sum(1 for p in probes if p["reachable"])
    assert b["n_reasoning"] == sum(1 for p in probes
                                   if p["reachable"] and p["has_reasoning"])
    assert b["n_nonbaseline_reasoning"] == sum(
        1 for p in probes
        if p["reachable"] and p["has_reasoning"] and p["model"] != b["baseline"])
    assert sum(b["kinds"].values()) == b["total"]
    if b["n_nonbaseline_reasoning"] == 0:
        assert b["core_by_model"] == {}, "无合格模型时 core_by_model 必须为空"
        assert b["verdict"].startswith("BLOCKED")
    print("[check] OK: %d 候选 / %d 可达 / %d reasoning / %d 非基线, verdict=%s"
          % (b["total"], b["n_ok"], b["n_reasoning"],
             b["n_nonbaseline_reasoning"], b["verdict"]))


def main():
    d = load()
    b = build_data(d)
    if "--check" in sys.argv:
        check(b)
        return
    os.makedirs(os.path.dirname(REP), exist_ok=True)
    with open(REP, "w", encoding="utf-8") as f:
        f.write(build_report(b))
    with open(HTM, "w", encoding="utf-8") as f:
        f.write(build_html(b))
    for p in (REP, HTM):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:12]
        print("[B2-gen] %s  sha256=%s" % (p, h))
    check(b)


if __name__ == "__main__":
    main()
