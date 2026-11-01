#!/usr/bin/env python3
"""Append the Pass-39 record to results/p3_18point_audit.md."""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
P = os.path.join(ROOT, "results", "p3_18point_audit.md")
CRLF = chr(13) + chr(10)
NL = chr(10)

SEC = """

## Pass-39（2026-10-25）第三窗口漂移 + B2 补齐 + 共进化臂 + D23'/D30 真实测量

### 背景与数据（任务 #103 / #104）

kilo 匿名免费池第三次开放（快照 `results/kilo_window3_pool.json`：401 模型 /
13 free；**`reflection/beam-free` 已轮换出池**）。

- **E1e 第三窗口**（`experiments/e1e_third_window.py`，5 后端 × 32 请求 =
  160，`results/e1e_third_window_v1.json`）。脚本内 `collect_history()`
  重扫 e1_cross_model / e1b / e1c 三个 artifact 现算窗口序列，杜绝手抄数字。
  - M_P Nano 14/24 = 58.3%（与窗口二**逐位相同**，w2 vs w3 Fisher p=1.000；
    w0 vs w3 p=0.002）⇒ 漂移是**阶跃后稳定**，不是持续噪声。
  - M_R Laguna XS 1/12 = 8.3%（窗口二 0/13，p=0.48）。
  - M_T 主家族仅 2/24 可用（1 leak）；M_Q Super-120B、M_S Xing 32/32 全锁。
- **B2 补齐**（`experiments/b2_adaptive_replication.py`，从 9 集断点跑满
  **40/40**，`results/b2_adaptive_replication_v1.json`）：CoT **26/38 =
  68.4%**、final 0、拒答 4、首漏 ep1、thinking-leak 18/21、末三分位 tl-c
  占 58.3%（均匀 8.3%）、5 闸门全过。
- **E7 共进化臂**（40 集，第 13 臂 `co` 由第二真实模型按「领先臂文本 +
  上一轮目标反馈」现生成措辞）：co 8 次拉臂 / 7 次泄漏，固定臂 17/32。
  **诚实问题**：Thompson 把 18 次给了 tl-c，co 只分到 8 次，其中 5 次因
  attacker 失败回退成种子文本、1 次 attacker 拒答 ⇒ 真生成措辞仅 2 次。
- **E7b 固定配对**（`experiments/e7b_coevo_headtohead.py`，12 co vs 12 tl-c
  交替；attacker 换到 kilo 后 12/12 成功、12/12 提示互异）：**co 9/12 =
  75.0% vs tl-c 12/12 = 100%，Fisher p=0.217**，臂内 4/6 → 5/6。
- **E8 真实防御**（36 攻击提示 = 4 基线 + 2×16 真模型改写，+ 8 对照；
  对同一批真实响应评估）：无防御 14/36 = 38.9%；**D23 精确指纹 12/36**
  （只挡住 4 条已知模板，32 条改写全部通过）；**D23′(c=0.5) 4/36 = 11.1%
  @ FPR 12.5%**，c≥0.75 时 FPR 87.5%/100%（退化）；**D30 覆盖曲线
  s=0.25/0.5/0.75/1.0 → 36.1/33.3/8.3/0%**（key 集中在推理尾段）；
  堆叠相对 D30 单独**无可测净收益**。6 闸门全过。

### tex 编辑（`experiments/_p3_merge_wave4.py`，8 对 + `_p39_termfix.py` 2 对）

1. Adaptive Attacker「Cross-model replication」：B2 由「9/40 截断、7 usable、
   4 of 4 pulls、0 of 3」改写为完整 40 集口径（38 usable、26/38 = 68.4%、
   thinking-leak 18/21 vs 其余 8/17、final 0/38、末三分位 58%）。
2. Extension cohort 新增「Third quota window」段（Nano 14/24 复现、p=1.0 vs
   w2 / p=0.002 vs w1、Laguna 0/13→1/12、主家族仅 2/24 可用、Beam 轮换出池、
   两后端全锁）。
3. 术语消歧：第三网关行原文「wave-3 rows」→「third-gateway rows」，新增的
   第三窗口行标「(window 3)」，避免与「窗口序列」混淆。
4. tab:e1b 加 4 行 window-3（Nano 14/24、Laguna 1/12、主家族 1/2、
   Super-120B blocked）。
5. Limitations 漂移句补第三窗口（14/24 again, p=1.0）；截断句补「第三窗口
   两后端全锁 + 一个后端仅 2/24 有效」。
6. Adaptive Attacker 结尾新增「Co-evolving attacker」段（E7 8/40 拉臂 →
   E7b 固定交替 12 vs 12，9/12 vs 12/12，p=0.22；无防御目标上改写相对重排
   无可测增益）。
7. sec:corr 末尾新增「Measured against a rewriting attacker」段（36 提示语料、
   精确指纹 12/36、等价类 4/36@FPR 12.5%、无半径能兼顾、输出侧覆盖曲线、
   堆叠无净收益 + oracle 红action 与词袋余弦两条 caveat）。

### 验收

- 3 遍 rc=0，**16 页 567,666 B**（Pass-38 为 15 页 563,770 B；正文
  13,622 词 +620）。TIFS 定位文档注明接受 20+ 页 measurement study，
  故不回压 15 页。
- audit 全过：摘要 200 词（硬约束不变）、7 图 7 表 1 式、44 引 44/44 cite
  闭合、fatal/overfull/undef 全 0、caption 14 条 ≤12、图/表 0 孤儿。
- 内部代号扫描：E1e/E7/E7b/E8/M_P…/kilo/Intern-AI/dots3 全 0 命中；
  表中 Sage-A1.5/Atria/Agents-A1/deepseek-v4/qwen3.8 为第三网关公开模型名
  （Pass-38 已有，同级描述性）。
- 投稿包同步：tex/pdf + 7 图 + README 加 Pass-39 段落（页数 15→16）。

### 修复记录

- `e1e_third_window.py` g3 闸门**自引用正在构造的键**导致 KeyError
  （恢复跑时才暴露）→ 先算局部变量 `g3_models` 再进字典字面量。
- E8 首版 c* 选「最小 bypass」得到退化点 c=0.75（FPR 87.5%）→ 改为
  **FPR 预算（≤15%）下取最强** + 同时记录无约束最优点；ckpt 齐全，重跑
  秒级出结果。
- attacker 侧模型：Intern-AI 的 Sage-A1.5/intern-s2 为 reasoning-first，
  `content` 恒空；改用 kilo 链（lightning/north-mini-code/ultra-550b/flint）
  后 12/12 成功。曾尝试 reasoning-tail 兜底，产物是推理碎片，已删除。
- 提示词去掉 red-team/secret/leak 措辞后不再触发安全拒答。
"""


def main():
    s = open(P, encoding="utf-8", errors="replace").read()
    crlf = s.count(CRLF) > 0
    sep = CRLF if crlf else NL
    if "## Pass-39" in s:
        print("Pass-39 record already present; nothing appended")
        return
    add = SEC.replace(NL, sep) if crlf else SEC
    tmp = P + ".tmp"
    open(tmp, "w", encoding="utf-8").write(s.rstrip("\r\n") + sep + add)
    os.replace(tmp, P)
    print("audit ->", len(open(P, encoding="utf-8").read()), "chars")


if __name__ == "__main__":
    main()
