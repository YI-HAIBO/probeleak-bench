"""Pass-20 scan: locate all actionable items from rules 1-5."""
import re

p = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s = open(p, encoding='utf-8').read()
NL = chr(10)
lines = s.split(NL)

print('=== RULE 2: we-verb sentence starts ===')
for i, line in enumerate(lines, 1):
    m = re.match(r'^\s*We (measure|ask|report|show|demonstrate|find|observe)\b', line)
    if m:
        print('L%d: %s' % (i, line.strip()[:120]))

print()
print('=== RULE 2: "in this paper" ===')
for i, line in enumerate(lines, 1):
    if 'in this paper' in line.lower():
        print('L%d: %s' % (i, line.strip()[:150]))

print()
print('=== RULE 2: "essentially" ===')
for i, line in enumerate(lines, 1):
    if 'essentially' in line.lower():
        print('L%d: %s' % (i, line.strip()[:150]))

print()
print('=== RULE 3: "real-world" ===')
for i, line in enumerate(lines, 1):
    if 'real-world' in line.lower() or 'real world' in line.lower():
        print('L%d: %s' % (i, line.strip()[:150]))

print()
print('=== RULE 4: abbreviations to expand ===')
abbrs = ['OWASP', 'PII', 'RLHF', 'WMDP', 'APPA', 'GIF', 'UNION', 'EWA', 'NOTE']
for a in abbrs:
    for i, line in enumerate(lines, 1):
        if re.search(r'\b' + a + r'\b', line):
            print('L%d [%s]: %s' % (i, a, line.strip()[:150]))
            break  # first occurrence only

print()
print('=== RULE 1: key terms first occurrence ===')
terms = ['verdict triple', 'naive recomputation', 'five-strategy ladder',
         'boundary condition', 'honeypot', 'stacking', 'joint residual',
         'leak-equivalent', 'literal scrubbing', 'channel visibility',
         'effective attack', 'consumer arm', 'real-trace defense test',
         'security audit run', 'co-evolution', 'contextual bandit',
         'Jeffreys prior', 'McNemar', 'discount factor']
for t in terms:
    idx = s.find(t)
    if idx >= 0:
        line_no = s[:idx].count(NL) + 1
        # get the line
        line_start = s.rfind(NL, 0, idx) + 1
        line_end = s.find(NL, idx)
        line = s[line_start:line_end].strip()
        print('L%d: %s' % (line_no, line[:150]))