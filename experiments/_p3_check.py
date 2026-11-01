import re, sys

P = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
d = open(P, encoding='utf-8').read()

caps = re.findall(r'\\caption\{(.*?)\}', d, re.S)
print('captions:', len(caps))
for c in caps:
    c2 = re.sub(r'\\[a-zA-Z]+|[\{\}\$]', ' ', c)
    c2 = re.sub(r'[^ \nA-Za-z]', ' ', c2)
    w = [x for x in c2.split() if x]
    flag = 'OVER' if len(w) > 15 else 'ok'
    print(len(w), flag, c[:80].replace('\n', ' '))

for pat in ['behaviour', 'g1--g4', 'second gateway', 'naive recomputation',
            'pandey', 'Pandey', 'HTTP 4', 'dashboard', 'idempotent',
            'repetition-v2', 'JSON record', 'the first cross-vendor',
            'the second cross-vendor', 'the third cross-vendor']:
    print('RESIDUE', repr(pat), d.count(pat))
print('done')
