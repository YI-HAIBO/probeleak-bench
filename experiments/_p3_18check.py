import re, io, os

P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
d = open(P, encoding="utf-8", newline="").read()
lines = d.split("\n")

# 1) bibliography year histogram
bib = d[d.find(r"\begin{thebibliography}"):]
years = {}
for m in re.finditer(r", (\d{4})\.", bib):
    years[m.group(1)] = years.get(m.group(1), 0) + 1
print("bib year histogram:", dict(sorted(years.items())))
old = [y for y in years if int(y) <= 2015]
print("refs >=10 years old (<=2015):", sum(years[y] for y in old), old)
print("total bibitem:", bib.count(r"\bibitem"))

# 2) CI abbreviation definition
for i, ln in enumerate(lines, 1):
    if "confidence interval" in ln.lower():
        print("CI expanded at line", i, ":", ln.strip()[:90])
print("CI usages:", len(re.findall(r"\bCI\b", d)))

# 3) abstract bounds + math check
a_beg = d.find("\\begin{abstract}")
a_end = d.find("\\end{abstract}")
ab = d[a_beg:a_end]
print("abstract chars:", len(ab))
for tok in ["$", "\\[", "\\(", "\\frac", "\\times", "\\%", "_", "^"]:
    print("  abstract contains", repr(tok), ":", tok in ab)

# 4) standalone notes near figures/tables
for i, ln in enumerate(lines, 1):
    if re.search(r"\\note|\\textnote|\\small\s*Note|Fig\..*Note|Table.*Note", ln):
        print("possible note line", i, ":", ln.strip()[:100])

# 5) captions list with word counts
caps = re.findall(r"\\caption\{(.*?)\}", d, re.S)
print("caption count:", len(caps))
for c in caps:
    w = len(re.sub(r"[^A-Za-z0-9 ]", " ", c).split())
    print(" ", w, "words:", " ".join(c.split())[:95])

# 6) figure/table refs vs labels
fig_labels = set(re.findall(r"\\label\{(fig:[^}]+)\}", d))
tab_labels = set(re.findall(r"\\label\{(tab:[^}]+)\}", d))
refs = set(re.findall(r"\\(?:ref|autoref)\{((?:fig|tab):[^}]+)\}", d))
print("fig labels:", len(fig_labels), "referenced:", len(fig_labels & refs), "orphan:", sorted(fig_labels - refs))
print("tab labels:", len(tab_labels), "referenced:", len(tab_labels & refs), "orphan:", sorted(tab_labels - refs))

# 7) orphan figure files on disk
FD = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\figures"
used = set()
for m in re.finditer(r"\\includegraphics\[.*?\]\{([^}]+)\}", d):
    used.add(os.path.basename(m.group(1)))
on_disk = [f for f in os.listdir(FD) if f.lower().endswith(".pdf")]
print("includegraphics targets:", sorted(used))
print("orphan pdfs:", sorted(set(on_disk) - used))
