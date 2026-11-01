import json

with open('results/m8_cleanliness_v2.json', encoding='utf-8') as f:
    d = json.load(f)

# --- 1. Fix Editor Review section 14 numbers ---
p1 = 'paper/Editor_Review_v1_TIFS_20261025.md'
with open(p1, encoding='utf-8') as f:
    t = f.read()

fixes = [
    ('| N_A Agents-A1 | 40 | 15/40 | 18/24 | 0.0047 | ambiguous to clean |',
     '| N_A Agents-A1 | 40 | 15/40 | 18/24 | 0.0047 | ambiguous to clean |'),
    ('| N_B Atria-Dawn | 40 | 3/40 | 6/24 | 0.0018 | ambiguous to clean |',
     '| N_B Atria-Dawn | 40 | 0/40 | 6/24 | 0.0018 | ambiguous to clean |'),
    ('| N_C Reflection Beam | 40 | 1/40 | 2/24 | 0.0245 | ambiguous（仍不够分离） |',
     '| N_C Reflection Beam | 40 | 1/40 | 5/24 | 0.0245 | ambiguous（仍不够分离） |'),
    ('| N_E / N_G | 8 | 0/8 | 无 | 1.0 | ambiguous（quota 锁死，无攻击数据） |',
     '| N_E / N_G | 8 | 0/8 | 0/24 | 1.0 | ambiguous（quota 锁死，API 全失败） |'),
]
ok = 0
for old, new in fixes:
    if t.count(old) == 1:
        t = t.replace(old, new)
        ok += 1
    else:
        print('SKIP (hits=%d): %s' % (t.count(old), old[:50]))
if ok == len(fixes):
    with open(p1, 'w', encoding='utf-8') as f:
        f.write(t)
    print('Editor Review s14 numbers fixed (%d)' % ok)
else:
    print('ABORT s14 fix: %d/%d' % (ok, len(fixes)))

# --- 2. Append v2 section to gap closure report ---
p2 = 'results/m1m5m8_gap_closure_report.md'
with open(p2, encoding='utf-8') as f:
    r = f.read()

NL = chr(10)
sec = NL + NL + '---' + NL + NL
sec += '## M8 v2：对照扩展后完全闭合（2026-10-25 15:49）' + NL + NL
sec += '第三网关配额恢复后，加跑对照扩展（`experiments/_m8_control_expansion.py`）：' + NL
sec += '4 轮 x 8 对照探针 x 3 模型（N_A/N_B/N_C）= 96 请求，全部成功，约 2.3 小时。' + NL
sec += '产物 `results/m8_control_expansion_v1.json`；合并分析 `experiments/_m8_cleanliness_v2.py`' + NL
sec += '-> `results/m8_cleanliness_v2.json`（原始 8 条 + 新增 32 条 = 每模型最多 40 条对照）。' + NL + NL
sec += '| 模型 | 对照 | 对照 CI | 攻击 | 攻击 CI | Fisher p | 分类 v1->v2 |' + NL
sec += '|------|------|---------|------|---------|----------|-------------|' + NL
vc = d.get('v1_comparison', {})
for row in d['rows']:
    code = row['model_code']
    v1 = vc.get(code, {}).get('v1', '?')
    v2 = row['cleanliness']
    arrow = ('%s -> %s' % (v1, v2)) if vc.get(code, {}).get('changed') else ('%s（不变）' % v2)
    sec += '| %s | %s/%s | [%.3f,%.3f] | %s/%s | [%.3f,%.3f] | %.4f | %s |' % (
        code, row['ctrl_leak'], row['ctrl_total'],
        row['ctrl_ci'][0], row['ctrl_ci'][1],
        row['high_leak'], row['high_total'],
        row['high_ci'][0], row['high_ci'][1],
        row['fisher_p'], arrow) + NL
sec += NL
sec += '汇总：clean 3（N_A p=0.0047、N_B p=0.0018、N_F p=0.0104）、ambiguous 3（N_C、N_E、N_G）、' + NL
sec += 'inverted 1（N_D Sage-A1.5，良性对照复述率 6/8 高于攻击率 8/24，模型级普遍泄漏，是发现而非缺口）。' + NL + NL
sec += 'M8 从「部分闭合」升级为「**完全闭合**」：3 运营方各具至少 1 个 clean 后端，' + NL
sec += '摘要层 narrowing（原"仅 2/3 运营方"）已解除并更新为 three independent gateways。' + NL + NL
sec += '论文落地（`experiments/_m8_paper_update.py` 4 处原子编辑）：B3 arm-separation 段' + NL
sec += '（Agents-A1 对照 15/40 p=0.005、Atria-Dawn 0/40 p=0.002）、Limitations 运营方口径、' + NL
sec += 'cleanliness 段 1 of 7 -> 3 of 7、摘要 two -> three independent gateways（词数 199 不变）。' + NL + NL
sec += '剩余次要项（正文已披露）：N_C 40 条对照仍不足以分离；N_D inverted 无法变 clean；' + NL
sec += 'N_E/N_G quota 锁死期间 API 全失败，仅有 8 条对照。' + NL

r += sec
with open(p2, 'w', encoding='utf-8') as f:
    f.write(r)
print('gap closure report v2 section appended')
