import json
base = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\results'
d = json.load(open(base + r'\e4_consumer_channel_v1.json', encoding='utf-8'))
prod = d['producer']
print(type(prod), len(prod) if hasattr(prod, '__len__') else '')
if isinstance(prod, dict):
    print('producer keys:', list(prod.keys())[:10])
    recs = None
    for k in prod:
        if isinstance(prod[k], list) and prod[k] and isinstance(prod[k][0], dict):
            recs = prod[k]
            print('list under', k, len(recs))
            break
    if recs:
        leaks = [r for r in recs if r.get('cot_leak') or r.get('reasoning_leak')]
        print('n', len(recs), 'leaks', len(leaks))
        print('leak ids:', sorted(str(r.get('id') or r.get('probe_id')) for r in leaks))
else:
    leaks = [r for r in prod if r.get('cot_leak') or r.get('reasoning_leak')]
    print('n', len(prod), 'leaks', len(leaks))
    print('leak ids:', sorted(str(r.get('id') or r.get('probe_id')) for r in leaks))
