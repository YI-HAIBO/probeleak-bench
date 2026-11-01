import re
p='C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s=open(p,encoding='utf-8').read()
print('=== duplicate words ===')
for m in re.finditer(r'\b(\w+)\s+\1\b', s, re.I):
    print(m.start(), repr(s[max(0,m.start()-40):m.end()+40]))
print()
print('=== section titles ===')
for m in re.finditer(r'\\section\{[^}]*\}', s):
    t=m.group()
    if 'The Theoretical' in t or 'The The' in t:
        print(m.start(), repr(t))
print()
print('=== no-defense variants ===')
for m in re.finditer(r'no-defense[a-z\-]*', s):
    print(m.start(), repr(s[max(0,m.start()-30):m.end()+30]))
print()
print('=== output-side variants ===')
for m in re.finditer(r'output-side[a-z\-]*', s):
    print(m.start(), repr(s[max(0,m.start()-30):m.end()+30]))
print()
print('=== literal scrub variants ===')
for m in re.finditer(r'literal[a-z\- ]*scrub[a-z\-]*', s):
    print(m.start(), repr(s[max(0,m.start()-30):m.end()+30]))