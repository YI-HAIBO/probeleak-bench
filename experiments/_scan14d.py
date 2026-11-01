import re
p='C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
s=open(p,encoding='utf-8').read()

terms = ['production', 'SHA-256', 'idempotency', 'byte comparison', 'byte-level',
         'harness', 'FAKE', '429', 'tokens per minute', 'TPM', 'pipeline',
         'checkpoint', 'hard-coded', 'hardcoded', 'off-the-shelf', 'state-of-the-art',
         'SOTA', 'benchmark', 'real-world', 'real world', 'deploy', 'deployment',
         'in the wild', 'live', 'production log', 'log sink', 'orchestrat',
         'red-team', 'red team', 'honeypot', 'key signature', 'key_value',
         'reasoning_content', 'content field', 'openrouter', 'ANSWER:']

for t in terms:
    cnt = s.count(t)
    if cnt > 0:
        print(f'{t}: {cnt}')
        for m in re.finditer(re.escape(t), s):
            print(f'  {m.start()}: {repr(s[max(0,m.start()-40):m.end()+40])}')
    else:
        print(f'{t}: 0')