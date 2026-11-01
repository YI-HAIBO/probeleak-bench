"""Pass-34 P0 tex fixes (atomic): three edits, count==1 assertions, CRLF preserved."""
import os, sys

P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
CR = chr(13) + chr(10)

data = open(P, "rb").read().decode("utf-8")
assert data.count("\r\n") > 100, "expected CRLF file"

EDITS = [
    # P0-1 (L350-351): unclosed parenthesis after "tokens per minute".
    ("1{,}500--3{,}000 tokens per" + CR + "minute.",
     "1{,}500--3{,}000 tokens per" + CR + "minute)."),
    # P0-2 (L636-638): step-reconstruction probe contradiction. Ground truth from
    # results/e1_cross_model_v1.json: sr4 = M_A (Nemotron-3-Super) 0/6,
    # M_B (Beam) 0/6, M_C (Nemotron-3-Nano) 1/6, primary-model baseline 2/7.
    ("while the fourth step-reconstruction probe" + CR +
     "stays at zero in all models---triggerability is probe-dependent even where" + CR +
     "the channel-level phenomenon recurs.",
     "while the fourth step-reconstruction probe" + CR +
     "stays at zero on Nemotron-3-Super and Beam (0/6 each; the primary-model baseline" + CR +
     "is 2/7 and Nemotron-3-Nano leaks once in six)---triggerability is probe-dependent" + CR +
     "even where the channel-level phenomenon recurs."),
    # P0-3 (L838): internal gate code g2 -> descriptive name (L321-323 wording).
    ("(g2 did not hold because $\\tau$ has zero reduction on this probe set)",
     "(the stress-test reduction gate did not" + CR +
     "hold, because $\\tau$ has zero reduction on this probe set)"),
]

for i, (old, new) in enumerate(EDITS, 1):
    n = data.count(old)
    if n != 1:
        sys.exit("ABORT: edit %d matched %d times (expected 1)" % (i, n))
    data = data.replace(old, new)

tmp = P + ".tmp"
with open(tmp, "wb") as f:
    f.write(data.encode("utf-8"))
os.replace(tmp, P)
print("OK: %d edits applied" % len(EDITS))
print("g2 residue:", data.count("g2"))
print("minute). present:", "minute)." in data)
