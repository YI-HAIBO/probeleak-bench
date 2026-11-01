import os

p = os.path.join(".workbuddy", "memory", "2026-10-24.md")
note = """

## E1d/B3 第三网关实验启动（15:58）

- 用户选择「两个都跑（先 E1d 后复测）」。
- 新脚本 `experiments/e1d_third_gateway.py`（7 响应模型 × 32 = 224 请求，
  复用 e1b 的 api_call/judge/summarize 结构但独立 endpoint/key/CKPT，
  失败重试 4 次退避）与 `experiments/b3_third_gateway.py`（E5 12 臂
  Thompson bandit，目标 Sage-A1.5，40 集预算，独立种子流）。
- 报告生成器 `experiments/e1d_b3_report_gen.py`（数字全部现读 JSON，
  幂等）；已修 fmt_ci/pct 的 % 格式化陷阱。
- E1d 已在后台启动（task Xe0rXd）；Agents-A1 早期信号：tl1 6/6 CoT
  泄漏、tl4 2/6、pe1_r1 泄漏（16k 推理字符），final 全 0；延迟偏高
  （平均约 30s/请求，预计总时长 ~2h）。
"""
with open(p, "a", encoding="utf-8") as f:
    f.write(note)
print("ok")
