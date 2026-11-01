import os, sys

P = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
EDITS = [
    (r"the cross-vendor replication and the 39-model census run on the second gateway are named as such",
     r"the cross-vendor replication and the 39-model census run on the cross-vendor gateway are named as such"),
]

data = open(P, encoding='utf-8', newline='').read()
for i, (old, new) in enumerate(EDITS):
    n = data.count(old)
    if n != 1:
        print('FAIL edit %d: %d hits' % (i, n)); sys.exit(1)
    data = data.replace(old, new)
tmp = P + '.tmp'
open(tmp, 'w', encoding='utf-8', newline='').write(data)
os.replace(tmp, P)
print('OK: %d edits applied' % len(EDITS))
