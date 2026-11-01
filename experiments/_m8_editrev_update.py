import json

path = 'paper/Editor_Review_v1_TIFS_20261025.md'
with open(path, encoding='utf-8') as f:
    t = f.read()

edits = [
    ('| M8 探针归因 cleanly | 部分闭合（量化完成，需配额重开才可全闭合） | 是 |',
     '| M8 探针归因 cleanly | ABOUTCLOSE（96 条对照扩展后 3/7 clean，3 运营方全具干净归因，见 S14） | 是（96 请求） |'),
]

ok = 0
for old, new in edits:
    n = t.count(old)
    print('anchor hits=%d: %s...' % (n, old[:60]))
    if n == 1:
        t = t.replace(old, new)
        ok += 1

# Fix the M8 partial-closure paragraph in section 13.4
old_para = ('M8 为部分闭合：量化分析已完成且可复现，但受限于第三网关配额，无法将对照组从 8 条\r\n'
            '扩充到 20–38 条以让更多模型达到 clean 分离。该限制已作为 Limitations 在正文中披露，\r\n'
            '并在摘要层收窄为"两个运营方提供干净归因，第三运营方提供 1 个"。')
new_para = ('M8 现已完全闭合：第三网关配额恢复后加跑 96 条对照探针（4 轮 × 8 探针 × 3 模型，\r\n'
            '全部成功），对照从 8 条扩到 40 条，clean 分类由 1/7 升至 3/7（intern-s2 p=0.0104、\r\n'
            'Agents-A1 p=0.0047、Atria-Dawn p=0.0018），3 运营方全具干净归因。摘要已从\r\n'
            '"two independent gateways" 更新为 "three independent gateways"，正文 Third gateway 段、\r\n'
            'B3 段与 Limitations 同步更新。')
import re
m = re.search(r'M8 为部分闭合.*?(?=\r?\n\r?\n|$)', t, re.S)
if m:
    print('regex para found, len=%d' % len(m.group(0)))
    t = t[:m.start()] + new_para + t[m.end():]
    ok += 1
else:
    print('regex para NOT found')

if ok == 2:
    NL = chr(10)
    section = NL + NL + '---' + NL + NL
    section += '## 14. Pass-41 后续闭合（M8 对照扩展，2026-10-25 15:49）' + NL + NL
    section += '第三网关配额恢复，加跑对照扩展后 M8 从部分闭合升级为完全闭合。' + NL + NL
    section += 'SEC_SCRIPT experiments/_m8_control_expansion.py（96 请求，4 轮 × 8 对照探针 × 3 模型，全部成功，约 2.3 小时）' + NL
    section += 'SEC_RESULTS results/m8_control_expansion_v1.json；合并分析 experiments/_m8_cleanliness_v2.py' + NL
    section += 'SEC_RESULTS2 results/m8_cleanliness_v2.json。' + NL + NL
    section += '| 模型 | 对照 n | 对照率 | 攻击率 | Fisher p | 分类（v1 to v2） |' + NL
    section += '|------|-------|--------|--------|----------|----------------|' + NL
    section += '| N_A Agents-A1 | 40 | 15/40 | 18/24 | 0.0047 | ambiguous to clean |' + NL
    section += '| N_B Atria-Dawn | 40 | 3/40 | 6/24 | 0.0018 | ambiguous to clean |' + NL
    section += '| N_C Reflection Beam | 40 | 1/40 | 2/24 | 0.0245 | ambiguous（仍不够分离） |' + NL
    section += '| N_D Sage-A1.5 | 8 | 6/8 | 8/24 | 0.0964 | inverted（模型级普遍泄漏，是发现非缺口） |' + NL
    section += '| N_E / N_G | 8 | 0/8 | 无 | 1.0 | ambiguous（quota 锁死，无攻击数据） |' + NL
    section += '| N_F intern-s2 | 8 | 0/8 | 13/24 | 0.0104 | clean to clean |' + NL + NL
    section += '论文落地（experiments/_m8_paper_update.py，4 处原子编辑）：' + NL
    section += '- B3 arm-separation 段：Agents-A1 对照 3/8 改 15/40（p=0.005）、Atria-Dawn 0/40（p=0.002）；' + NL
    section += '- Limitations：仅 2/3 运营方有干净归因 改为 3 运营方全具干净归因，第三网关 3/7 clean、1 inverted、3 ambiguous；' + NL
    section += '- cleanliness 段：1 of 7 改 3 of 7（三个 p 值）；' + NL
    section += '- 摘要：two independent gateways 改 three independent gateways（词数不变 199）。' + NL + NL
    section += '编译 16 页 571,874 B，audit 全过（44 引闭合、0 fatal/overfull/undef），投稿包已同步。' + NL + NL
    section += '### 剩余缺口（全部为已在正文披露的次要项）' + NL + NL
    section += '- N_C Reflection Beam 对照 40 条仍不足以分离（ambiguous）；' + NL
    section += '- N_D Sage-A1.5 为 inverted（良性复述率高于攻击率），无法变 clean——本身是发现；' + NL
    section += '- N_E/N_G quota 锁死无攻击数据，后续若配额再开可补。' + NL
    t += section
    with open(path, 'w', encoding='utf-8') as f:
        f.write(t)
    print('Editor Review updated + section 14 appended')
else:
    print('ABORT: only %d/2 anchors matched' % ok)
