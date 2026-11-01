import re
p='C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s=open(p,encoding='utf-8').read()

print('=== all captions ===')
for m in re.finditer(r'\\caption\{(.+?)\}', s, re.DOTALL):
    cap = m.group(1)
    # count words (approximate)
    words = len(re.findall(r'\b\w+\b', cap))
    if words > 15:
        print(f'\n--- {words} words at {m.start()} ---')
        print(repr(cap[:300]))

print('\n=== self-deprecation patterns ===')
patterns = [
    'we do not claim', 'we cannot', 'we do not know', 'we did not',
    'we have not', 'we have not yet', 'we leave', 'we omit',
    'not yet', 'has not been', 'has not been measured',
    'has not been established', 'remains unknown', 'remains an open',
    'is not known', 'are not known', 'we do not attempt',
    'we do not try', 'we do not aim', 'we do not seek',
    'limitation', 'limitations', 'caveat', 'weakness',
    'does not settle', 'does not resolve', 'does not answer',
    'we do not', 'we can not', 'cannot be', 'is unable',
    'falls short', 'falls outside', 'is beyond the scope',
    'we have not addressed', 'we have not considered',
    'not definitive', 'not conclusive', 'not fully',
    'incomplete', 'incompleteness', 'gap in',
    'we recognize', 'we acknowledge', 'we concede',
    'we are limited', 'we are constrained',
]
for pat in patterns:
    cnt = s.lower().count(pat.lower())
    if cnt > 0:
        print(f'{pat}: {cnt}')