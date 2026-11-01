# -*- coding: utf-8 -*-
"""Append Pass-12 execution record to today's memory log."""
import io

P = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\.workbuddy\memory\2026-10-20.md'

ADD = '''
## 第六轮修复落地（Pass-12，2026-10-20 深夜，25 对原子替换）
- 脚本 `experiments/_p3_tifs_cleanup12.py`（verify-then-apply，全匹配后一次写入）；
  另 L1184 单点 `5.4pp` 补刀。备份 `paper/p3_tifs.BAK-pass12.tex`。
- **三个硬错误（均有一手 JSON 反证，落地前已回读核实）**：
  1. census 段：`on the production gateway` → `on the second gateway of
     Section~\\ref{sec:e1}`（e1_model_survey_v2.json endpoint=api.kilo.ai）；
     补第三可用模型名 `openrouter/free`（usable_models 三成员：M-A/M-B/openrouter/free，
     各 2/2 泄露，探针 ii2+ci2）；错误形态 `model not configured` → HTTP 401
     paid-model auth required / HTTP 404 / empty（64+2+2+10 条实证）；
     Limitations 对应句同步改（E6 对）。
  2. E4 归属：`distinct from the 268/103 cohorts` → `part of the diverse cohort
     ($N=268$)`（pooled_sample_reconciliation_v1.json diverse_cohort.members 含
     E4 consumer producer n_ok=32；25+112+15+32+84=268），consumer-stage 判定
     才是独立测量层。
  3. sec:output 内自引用 `(Section~\\ref{sec:output})` 删除。
- **术语/逻辑 12 处**：G1→`Gate I (isolation)`（与 per-experiment g1--g4 解耦，
  仅 L339/L466 两处）；τ/key_value 的 `since it appears in the final answer`
  矛盾从句改为 `since $\\tau$ matches verbatim credential strings and the
  refusal text contains none`；calibrated world 不称 measured；v≈0.55 悬空
  `shown here only as a reference point` → `the value the real-probe arm below
  tests against`；探针 ID 承诺改为 class-code+index 说明；百万级预算改
  `broader research program ... 本文 tens to a few hundred requests per arm`；
  tier 分母点明 4/35 records + 0 of 168；补 11 modes/5 classes/7 表行/5 fig 类
  的映射句；M-A 三事句拆分；Fig7 脚注删重复 Right 句；`more probative evidence`
  补比较对象 than real-credential findings。
- **缩写 3 处**：摘要 LLM→`Large language model (LLM)`（+3 词，195/200）；
  Wald→`Wald (normal-approximation)`；pp 两处+Table VI 脚注+L1184 共 4 处
  `pp`→`percentage points`（仅剩参考文献 pp. 页码区间）。
- **Table VI 脚注**：补 τ/C0 同为 0% 不同因（τ 无 final 命中可删 vs C0 无机制）。
- **自爆其短收敛 5 处**：Reproducibility 第三处 byte-exact 陈述改交叉引用
  Limitations；结论条件句去重复的 aggressive/public-benchmark 分句；
  Limitations 删防御性收尾 `This limits independent verification but does not
  weaken the measurements themselves`；三个孤儿重算数字（149/491 等）改
  `disagreed by up to 5.2 percentage points`；47.7--55.4% 孤儿转移率删数字
  仅留 simulation-only 标注。
- **终态**：15 页 / PDF 597,507 B / abstract 195 词 / body 12,394 词 /
  7 图 6 表 1 公式 / 53/53 cite / fatal 0 overfull 0 undef 0 /
  双词 0 重复短语 0 括号 -2（枚举符，同修改前）。
- 教训 30：多个 patch 对同一区域相邻句时，前一对的 NEW 会成为后一对 OLD 的
  上下文——本批把 `5.4pp→percentage points`（Table VI 脚注对）与正文 L1184 的
  同一写法拆成两对，扫尾 grep `\\bpp\\b` 才发现正文那处漏网；**成对替换后必须
  按主题词（而非按区域）做全文残留 grep**。
'''

t = io.open(P, encoding='utf-8').read()
if 'Pass-12' not in t:
    io.open(P, 'w', encoding='utf-8').write(t + ADD)
    print('appended', len(ADD), 'chars; total', len(t) + len(ADD))
else:
    print('already present')
