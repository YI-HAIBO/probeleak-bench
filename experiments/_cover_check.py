"""Verify every numeric claim in the new COVER_LETTER.md against p3_tifs.tex."""
import os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tex = open(os.path.join(ROOT, "paper", "p3_tifs.tex"), "rb").read().decode("utf-8")
let = open(os.path.join(ROOT, "paper", "COVER_LETTER.md"),
           encoding="utf-8").read()

flat = re.sub(r"\s+", " ", re.sub(r"\\[a-zA-Z]+", " ", tex))
flat = flat.replace(r"\%", "%").replace("{,}", ",")


def variants(s):
    """Numbers as they may appear in LaTeX vs plain text."""
    out = set()
    for x in [s, s.replace(",", "{,}"), s.replace(",", ""),
              s.replace(" ", r"\ " )]:
        out.add(x)
    out.add(s.replace(",", "{,}"))
    if "%" in s:
        for x in list(out):
            out.add(x.replace("%", r"\%"))
    return out


CLAIMS = [
    "371 attack responses", "268 fresh-probe", "14.55", "[10.83, 19.27]",
    "0/268", "1.1", "39-model census", "three models", "8%", "402-model",
    "62.5", "53.6", "0.581", "54.2", "1.0", "0 of 60", "4.48", "4.51",
    "0/32", "11.2 of 15", "three output-side", "42.4", "26.7", "1.59",
    "+0.0286", "+0.0128", "0.0018", "38.27", "39 of 268", "103 of 103",
    "7.63", "12.5% \u2192 58.3% \u2192 58.3%", "35 probes", "33 attack",
    "11 modes", "100,000 probes", "FAKE_", "16 pages", "200-word",
    "7 figures", "7 tables", "44 IEEE-formatted", "36-prompt",
    "8 benign", "14 of 36", "38.9", "12 of 36", "4 of 36", "12.5%",
    "0 of 36", "87.5%", "30B", "ProbeLeak-Bench",
]
bad = []
print("%-26s | tex | letter" % "claim")
print("-" * 46)
for c in CLAIMS:
    in_tex = any(v in flat for v in variants(c))
    in_let = c in let
    if not in_tex:
        bad.append(c)
    print("%-26s | %-4s | %s" % (c, "OK" if in_tex else "MISS",
                                 "yes" if in_let else "-"))

print()
print("claims in the letter not found in the paper:", bad or "none")

# scan for numbers in the letter that appear nowhere in the paper
body = let
nums = sorted(set(re.findall(r"\d[\d,]*\.?\d*", body)))
missing = []
for n in nums:
    cands = {n, n.replace(",", ""), n.replace(",", "{,}")}
    if n.isdigit():
        cands.add(n.replace(",", ""))
    if not any(c in flat.replace("{,}", ",").replace(",", ",") for c in cands):
        missing.append(n)
print("letter numbers absent from the paper:", missing or "none")
print()
print("letter size:", len(body), "chars,", body.count("\n") + 1, "lines")
