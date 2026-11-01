import re
p='C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s=open(p,encoding='utf-8').read()

print('=== no-defense variants (context) ===')
for m in re.finditer(r'no-defense[a-z\-]*', s):
    print(m.start(), repr(s[max(0,m.start()-50):m.end()+50]))

print('\n=== output-side variants (context) ===')
for m in re.finditer(r'output-side[a-z\-]*', s):
    print(m.start(), repr(s[max(0,m.start()-40):m.end()+40]))

print('\n=== literal scrub variants (context) ===')
for m in re.finditer(r'literal[a-z\- ]*scrub[a-z\-]*', s):
    print(m.start(), repr(s[max(0,m.start()-40):m.end()+40]))

print('\n=== rbac2026 bibitem ===')
i = s.find('rbac2026')
print(repr(s[i-50:i+400]))