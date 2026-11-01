import io

p = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\.workbuddy\memory\2026-10-20.md'
t = io.open(p, encoding='utf-8').read()

start = t.find('## 第六轮审稿')
assert start >= 0, 'section not found'
# keep everything before the corrupted section
head = t[:start]

fixed = """## 第六轮审稿（2026-10-20 晚，review-only，未改文件）
- 通读 1--1665 行 + 回读一手 JSON。三个硬错误（均有 JSON 反证）：
  1. L746 「A 39-model census on the production gateway (E1-v2)」——e1_model_survey_v2.json
     的 endpoint 是 api.kilo.ai（第二网关 AtlasCloud）；生产网关（note3-prev-api）
     只暴露 dots3-note-prev（b2_cross_model_v1.json verdict=BLOCKED）。L748 的
     「both on the second gateway」在 census 同属第二网关的事实下构成误导对比。
     且 census 第 3 个 usable 模型 openrouter/free 全文未列名。
  2. L967-968 「E4 consumer-arm responses, distinct from the 268/103 cohorts」——
     pooled_sample_reconciliation_v1.json diverse_cohort.members 含
     E4 consumer producer（n_ok=32；25+112+15+32+84=268），与 L1316 直接矛盾；
     独立的是 consumer-stage 判定而非 producer 响应。
  3. L898 节内自引用 (Section~ref{sec:output}) 身处 sec:output。
- 其余：G1/g1 仅大小写双轨（L339/466 vs L342/444/924/1229）；L916-919 的
  「since it appears in the final answer」与 L912（τ redact final answer）矛盾；
  L1096「Measured residual leakage in the calibrated world」用词相反；L1200-1202
  「v≈0.55 ... shown here only as a reference point」全文无着落；pp 两处无定义；
  Wald 未展开；探针 ID 未兑现 expanded-where-first-used；Fig7 脚注与图注重复；
  L566-573 三个自述从未出现的数字；L370 百万级预算与本文实验规模无可对性。
- AI 腔/非学术内容本轮清零（grep 全文仅剩 stand out/are notable 等中性词）。
- 教训 28：论文里的网关/实验归属措辞必须回读 JSON 的 endpoint/cohort 字段核对，
  「production gateway」这类简称在文内有专指（dots3-note-prev 网关），不能凭印象写。
- 教训 29：Bash 内联 python -c 的双引号串里禁放反引号——bash 会做命令替换把
  反引号内容当命令执行并吞掉（本次记忆笔记被吃掉 8 段）。长文本写文件用 Write 工具，
  或 heredoc；memory 写入后必须回读校验。
"""

io.open(p, 'w', encoding='utf-8').write(head + fixed)
print('rewritten; total chars', len(head + fixed))
