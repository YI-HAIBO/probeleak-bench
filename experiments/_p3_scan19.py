import re

p = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(p, encoding='utf-8').read()
print('size', len(s))

# 8: abstract math
ab = re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}', s, re.S)
abt = ab.group(1) if ab else ''
print('ABSTRACT math tokens:', bool(re.search(r'\\\$|\\\(|\\\[|\\eqref|\\mathrm|\\times|\\cdot|\\text', abt)))
print('ABSTRACT word count:', len(re.sub(r'\{[^}]*\}', '', abt).split()))

# 6+7: captions
print('--- CAPTIONS ---')
for m in re.finditer(r'\\caption\{(.*?)\}', s, re.S):
    cap = m.group(1).replace(chr(10), ' ').strip()
    words = re.sub(r'\{[^}]*\}', '', cap).split()
    wc = len(words)
    has_math = bool(re.search(r'\\\(|\\\$|\\\[|\\\]|\\eqref|\\mathrm|\\times|\\cdot|\\text|\\%|\\sigma|\\tau|\\rho|\\lambda|\\phi|\\varphi|\\Delta', cap))
    has_note = bool(re.search(r'\\emph\{|Note that|note:|Notes:|\\textit\{|\\textbf\{|\\footnote', cap, re.I))
    flag = []
    if wc > 15:
        flag.append('LONG')
    if has_math:
        flag.append('MATH')
    if has_note:
        flag.append('NOTE')
    label = 'OK' if not flag else ','.join(flag)
    print('  [%s] wc=%2d  %s' % (label, wc, cap[:200]))

# 9-12: refs, figs, tables
print('--- REFS ---')
refs = re.findall(r'\\bibitem\{(.*?)\}', s)
print('total bibitems:', len(refs))
cites = re.findall(r'\\cite\{(.*?)\}', s)
allc = set()
for c in cites:
    for x in c.split(','):
        allc.add(x.strip())
print('unique cites:', len(allc))
missing = [r for r in refs if r not in allc]
unused = [r for r in allc if r not in refs]
print('refs never cited:', missing)
print('cited but no bibitem:', unused)

print('--- FIGURES ---')
figs = re.findall(r'\\label\{fig:(.*?)\}', s)
print('fig labels:', figs)
figrefs = re.findall(r'\\ref\{fig:(.*?)\}', s)
print('fig refs:', figrefs)
print('figs never referenced:', [f for f in figs if f not in figrefs])

print('--- TABLES ---')
tabs = re.findall(r'\\label\{tab:(.*?)\}', s)
print('tab labels:', tabs)
tabrefs = re.findall(r'\\ref\{tab:(.*?)\}', s)
print('tab refs:', tabrefs)
print('tabs never referenced:', [t for t in tabs if t not in tabrefs])