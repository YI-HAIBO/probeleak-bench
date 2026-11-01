import os, sys

P = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\results\p3_14point_audit.md'
REC = """

---

## P1/P2 修复记录（2026-10-22，Pass-33）

P1（影响读者理解，必须改）3 项 + P2（打磨）若干，共 45 条原子编辑，脚本
`experiments/_p3_p1p2fix.py`（44 条）+ `experiments/_p3_residuefix.py`（1 条残留）。

**P1-1 Limitations 压缩**：原为引言 + 6 条 enumerate（73 行），压缩为 3 段
散文——「Disclosure and reproducibility」「One primary real reasoning model」
「Further boundary conditions」。删除内容并入正文已有讨论处，未丢失任何
限制条件（披露约束、单一推理模型、自适应层用模拟、无第二真实推理模型、
世界模型固定 false-positive 率、单调前提、CoT 通道仅文本等全部保留）。

**P1-2 四张图的独立 note 并入正文**：fig:e1cross / fig:corr / fig:output /
fig:e4consumer 的图下注解删除，内容并入图题或前导正文（图题词数全部
<=15：最长 14 词）。图题总数 13，全部通过 <=15 词检查。

**P1-3 双网关命名**：全文统一为 primary gateway / cross-vendor gateway
（定义处、blocked-model 段、cross-vendor 段、census 段、结论处），残留的
一处「second gateway」在命名约定段一并改掉。

**P2 批次**：
- AI 味/自述去除：「The question is whether...」->「We test whether...」；
  「Two conclusions follow:」删除；「stated separately because they follow
  from the measurements rather than from analogy」删除；模拟世界免责声明的
  五处对冲缩为两处；cohort 段口号式改写。
- 工程细节清理：HTTP 400/403/401/404/502 括号状态码删除；网关错误字符串
  删除；response-identifiers 表述删除；「idempotent generators」/
  「dashboard」术语删除；「repetition-v2 run」->「expanded repetition run」；
  naive-recomputations 反例段改为方法论一句。
- 缩写首展：JSON 首次可见处展开为「JSON (JavaScript Object Notation)」，
  Reproducibility 处「JSON record」->「structured record」。
- g1--g4 内部编号：定义处及正文三处改为描述性表述
  （pre-registered ... gate / stress-test reduction gate / zero-final-leak
  gate）。
- 其余：behaviour -> behavior（2 处）；census 处补缺失冒号；
  forensics 第 2 条 judge-ratio 句拆分；探针索引约定补充「verbatim text
  of every indexed probe is part of the released library」；删除悬空的
  「four evaluation waves」定义与「broader research program」/「far smaller」
  自贬表述。

**验收**：tifs_build.py 3 遍 pdflatex 0 错误，14 页 539,858 B（P0 版
544,419 B）；tifs_audit.py 全过——摘要 199 词、正文 11,025 词（P0 版
11,756，压缩 731 词主要来自 Limitations 与图注合并）、7 图 6 表 1 式、
参考文献 44/44 闭合、fatal/overfull/undef 全 0。13 个图题全部 <=15 词。
残留扫描：behaviour / g1--g4 / second gateway / naive recomputation /
pandey / HTTP 4xx / dashboard / idempotent / repetition-v2 /
JSON record / first|second|third cross-vendor 全部 0 命中。
submission_2026-10-21/ 已同步 tex（93,506 B）+ pdf（539,858 B）。
"""

data = open(P, encoding='utf-8', newline='').read()
assert 'P1/P2 修复记录' not in data, 'record already appended'
tmp = P + '.tmp'
open(tmp, 'w', encoding='utf-8', newline='').write(data + REC)
os.replace(tmp, P)
print('OK audit record appended, new len', len(data + REC))
