"""P2-3b: second compression pass -- cut verbose enumeration and redundancy
in Limitations / Reproducibility / Forensic Implications to return to 16 pages.
"""
P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
s = open(P, encoding="utf-8").read()

edits = []

# Cut 1: quota enumeration (Limitations) -- 110 words -> ~50
# (anchor spans the hard line wraps as they actually appear in the file)
edits.append((
    "the gateway's\nanonymous free-tier quota is a shared rotating budget that locked each usable\n"
    "set within roughly 250 requests, two extension models were truncated by quota\n"
    "exhaustion (19 and 9 valid high-tier responses), one was fully blocked, and\n"
    "the second wave truncated three further models (24, 17, and 13 valid\n"
    "high-tier responses) and blocked a fourth, and the third aggregator gateway\n"
    "blocked two further models on all attempts, and a third quota window\n"
    "blocked two further entries on all attempts and left one backend with 2 of\n"
    "24 valid high-tier responses. A",
    "the gateway's anonymous free-tier quota is a shared rotating budget of roughly 250 requests\n"
    "per usable set: quota exhaustion truncated two extension models (19 and 9 valid responses),\n"
    "fully blocked one, truncated a second wave of three (24, 17, 13) and blocked a fourth, and the\n"
    "third aggregator gateway blocked two further models on all attempts while a third quota window\n"
    "blocked two more and left one backend with 2 of 24 valid responses. A"
))

# Cut 2: redundant verification sentence (Reproducibility) -- delete
edits.append((
    "Report and figure generators expose a verification mechanism that signals failure if a "
    "regenerated artifact differs from the stored one.",
    ""
))

# Cut 3: c* sensitivity sentence (Limitations)
edits.append((
    "A sensitivity\nsweep over the measured $c$ grid $\\{0, 0.25, 0.5, 0.75, 1.0\\}$ shows "
    "$c^{*}=0.50$ is\nchosen for all FPR budgets in $[0.125, 0.25]$ (the actual budget 0.15 lies "
    "inside),\nand the only alternative at a tighter budget is $c^{*}=0.25$ with TPR dropping from\n"
    "0.806 to 0.361.",
    "A sensitivity sweep over the measured $c$ grid $\\{0, 0.25, 0.5, 0.75, 1.0\\}$ selects "
    "$c^{*}=0.50$ for all FPR budgets in $[0.125, 0.25]$ (the actual budget 0.15 lies inside); "
    "the only tighter alternative, $c^{*}=0.25$, drops TPR from 0.806 to 0.361."
))

# Cut 4: Forensic Implication 4 -- attribution sentence
edits.append((
    "All 15 keys carry a synthetic-marker prefix, so an attribution chain from a leaked string to "
    "a specific probe response is directly attributable and carries no exposure of real\n"
    "credentials.",
    "All 15 keys carry a synthetic-marker prefix, so a leaked string is directly attributable to a "
    "probe response with no exposure of real credentials."
))

# Cut 5: Reflection Beam sentence (Limitations)
edits.append((
    "Reflection Beam is\nstatistically indistinguishable from the primary model's baseline (62.5\\%\n"
    "versus 53.6\\%, Fisher $p=0.581$), the primary model's own family under separate\n"
    "hosting is likewise indistinguishable (54.2\\% versus 53.6\\%, $p=1.0$), and\n"
    "measured rates across the fifteen backends range from 0\\% to 100\\%.",
    "Reflection Beam is statistically indistinguishable from the primary model's baseline "
    "(62.5\\% versus 53.6\\%, Fisher $p=0.581$), as is the primary model's own family under "
    "separate hosting (54.2\\% versus 53.6\\%, $p=1.0$); measured rates across the fifteen backends "
    "range from 0\\% to 100\\%."
))

for old, new in edits:
    c = s.count(old)
    assert c == 1, "anchor count=%d: %r" % (c, old[:70])
    s = s.replace(old, new, 1)

open(P, "w", encoding="utf-8").write(s)
print("P2-3b applied 5 cuts; file chars:", len(s))