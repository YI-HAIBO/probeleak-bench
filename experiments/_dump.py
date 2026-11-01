import io, re, sys
p = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
s = io.open(p, encoding='utf-8').read()
lines = s.split('\n')
print('TOTAL LINES', len(lines))
pat = re.compile(r'\\label\{((?:fig|tab):[A-Za-z0-9]+)\}')
for m in pat.finditer(s):
    ln = s[:m.start()].count('\n') + 1
    print(m.group(1), ln)
print('=' * 40)
a, b = int(sys.argv[1]), int(sys.argv[2])
for i in range(a - 1, min(b, len(lines))):
    print(i + 1, repr(lines[i]))
