import re
P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
d = open(P, encoding="utf-8", newline="").read()
BS = chr(92)
i0 = d.find(BS + "begin{thebibliography}")
bib = d[i0:]
entries = re.split(r"\\bibitem\{", bib)[1:]
for e in entries:
    head = e[:400].replace("\n", " ")
    m = re.search(r", (\d{4})\.", head)
    if m and m.group(1) in ("2022", "2027", "2023"):
        print(m.group(1), "|", head[:150])
