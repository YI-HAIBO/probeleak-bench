"""Correct the E10 conclusion in project memory.

Conclusion 4 previously read as if D30b were a strict substitute for the
oracle rule. The per-trace comparison (e10_redaction_compare.py) shows the
corpus-level gap is 0.0 but the two rules remove different text, so the
claim is overstated and has to be narrowed. Also fixes a stale note in the
Pass-39 bullet and records the window_watch counts.
"""
import io
import os

P = os.path.join(
    r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43",
    ".workbuddy", "memory", "MEMORY.md")

EDITS = (
    # 1. E10 conclusion 4 -- narrow the oracle claim
    (
        "④ **D30b（键形状、非 oracle）oracle gap=0.0，在本语料上替代 D30 成立**，"
        "部分解除 E8 的 oracle 上界 caveat。",
        "④ **D30b（键形状、非 oracle）语料级 oracle gap=0.0，但两条规则做的是"
        "不同的工作**：20 条泄漏 trace 上 17 条红action 输出逐字相同，"
        "2 条键形状更宽（模型把 key 逐字符拼出再重组为引用前缀，key 从不连续"
        "出现，字面 key 列表结构上匹配不到，5 vs 7 / 3 vs 7 段），"
        "1 条 key 列表更宽（24 vs 15 段，模型列出无 `_sk-` 前缀的裸 key 后缀）。"
        "两条规则都删净 15/15 完整 key，但 D30b 放弃了碎片覆盖 → "
        "**E8 的 oracle caveat 在碎片级泄漏上仍然成立，未被闭合**；"
        "能说是「窄化了」而不是「解除了」。",
    ),

    # 2. E10 artifact line -- add the comparison script
    (
        "产物：`results/e10_coevo_vs_adaptive_defense_v1.json` + "
        "`results/e10_report.md`（生成器 `experiments/e10_report_gen.py` 幂等，"
        "纯 JSON 函数）。",
        "产物：`results/e10_coevo_vs_adaptive_defense_v1.json`（含 "
        "`redaction_comparison` 块）+ `results/e10_report.md`（生成器 "
        "`experiments/e10_report_gen.py` 幂等、纯 JSON 函数；per-trace 比较由 "
        "`experiments/e10_redaction_compare.py` 写入 JSON，不联网）。",
    ),

    # 3. stale note -- Pass-39 already replaced the truncation wording
    (
        "② B2 补满 40/40：CoT 26/38=68.4%、首漏 ep1、thinking-leak 18/21、"
        "final 0（论文现版本仍是「9/40 截断 7 usable」，必须更新）；",
        "② B2 补满 40/40：CoT 26/38=68.4%、首漏 ep1、thinking-leak 18/21、"
        "final 0（Pass-39 已把「9/40 截断 7 usable」旧口径替换掉）；",
    ),

    # 4. window_watch bullet -- add the measured counts
    (
        "- **experiments/window_watch.py（2026-10-25，#118）**：配额窗口哨兵"
        "——一次性探活全部已知 operator/后端，输出 results/window_watch_v1.json，"
        "把「等窗口」的待跑项收成单一入口。",
        "- **experiments/window_watch.py（2026-10-25，#118）**：配额窗口哨兵"
        "——每个后端一条 8-token 探针，全部已知 operator/后端，append 到 "
        "history 以便跨次对比，输出 results/window_watch_v1.json，"
        "把「等窗口」的待跑项收成单一入口。首跑（2026-10-25 11:52）："
        "15 后端中 10 应答、10/10 暴露推理通道；5 个不应答 = 2 个 404"
        "（model id 已轮换：M_Q nemotron-3-super-120b、M_B nano omni）+"
        "2 个 429（M_R laguna-xs-2.1、M_S xing4.0-29b）+1 个 45s 超时"
        "（N_A Agents-A1）。主靶 M0 dots3-note-prev 与 B2 用的 M_E "
        "nemotron-3.5-lightning 均在线。",
    ),
)


def main() -> int:
    raw = io.open(P, encoding="utf-8").read()
    before = len(raw)
    for i, (old, new) in enumerate(EDITS, 1):
        n = raw.count(old)
        if n != 1:
            print("ABORT: edit %d matched %d times" % (i, n))
            print("  anchor: %r" % old[:70])
            return 1
        raw = raw.replace(old, new)
    tmp = P + ".tmp"
    io.open(tmp, "w", encoding="utf-8").write(raw)
    os.replace(tmp, P)
    print("applied %d edits (%d -> %d chars)" % (len(EDITS), before, len(raw)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
