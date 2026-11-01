import re
p='C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s=open(p,encoding='utf-8').read()

print('=== rbac2026 bibitem ===')
i = s.find('rbac2026')
while i != -1:
    print('---')
    print(repr(s[max(0,i-100):i+600]))
    i = s.find('rbac2026', i+1)

print('\n=== forensic section numbering ===')
i = s.find('Forensic Implications')
print(repr(s[i:i+1500]))