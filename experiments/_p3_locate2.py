import os
p = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
data = open(p, 'rb').read()
lines = data.split(b'\r\n')
def show(a, b, tag):
    print('---', tag)
    for i in range(a - 1, min(b, len(lines))):
        print(i + 1, repr(lines[i]))
show(71, 73, '3-1 pentesting')
show(81, 87, '2-5 hedge')
show(135, 137, '1-6 7.63')
show(324, 327, '2-6a as such')
show(373, 378, '1-5 tier')
show(544, 549, '1-7a headline + 2-7')
show(593, 596, '2-2 criticism')
show(645, 648, '2-4 precisely')
show(677, 681, '1-9 third entry')
show(836, 842, '2-3 direct test + 2-6b')
show(874, 882, '1-8 consumer')
show(1083, 1088, '1-10 parenthetical')
show(1207, 1211, '1-7b headline')
show(1323, 1332, 'bib bessemer/microsoft')
show(1431, 1434, 'bib owasp')
show(1442, 1446, 'bib promptkeeper')
