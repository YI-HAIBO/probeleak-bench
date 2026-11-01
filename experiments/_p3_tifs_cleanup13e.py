#!/usr/bin/env python3
"""Pass-13 cleanup E: Rule 4 -- experiment campaign codes and model aliases.

1. Rewrite the "Notation for experiments" legend in prose (no codes).
2. Exact full-line / full-phrase replacements (count must be exactly 1).
3. Ordered regex substitutions: specific phrases first (to avoid double
   articles and duplicated replacement words), then generic word-boundary
   codes longest-first.
4. Post-processing: collapse any double article ("The the", "the the", ...)
   introduced by a replacement phrase that begins with "the".
5. Verify no campaign code, model alias, dots3-note-prev, D30, C0, RAW,
   reverse-effective, or \\texttt survives.
"""
import os, sys, re

PATH = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"
t = open(PATH, encoding="utf-8").read()

# ---------------------------------------------------------------- 1. legend
LEGEND_START = "\\textbf{Notation for experiments.} Experiments are identified by short codes"
LEGEND_END = "this form is used throughout."
ls = t.find(LEGEND_START)
le = t.find(LEGEND_END, ls)
if ls == -1 or le == -1:
    sys.exit("legend markers not found")
le += len(LEGEND_END)

NEW_LEGEND = (
    "\\textbf{Notation for experiments.} The campaigns reported here are described "
    "in place, in Sections~\\ref{sec:cot}--\\ref{sec:adaptive}; where a campaign is "
    "referred to again it is named by what it is rather than by an internal label. "
    "Thus the three samples of Section~\\ref{sec:cot} are the first, second, and third "
    "sample; the cross-vendor replication and the 39-model census run on the second "
    "gateway are named as such; the schema-hiding arm, the consumer arm, the real-trace "
    "defense test, the red-team run, the production-baseline probe set, the stress test, "
    "the public-benchmark probe set, and the repetition-v2 run are each named by their "
    "purpose. Pooled totals refer to the union of specified campaigns. The probe classes "
    "are thinking leak, prefix extraction, step reconstruction, translation-exfiltration, "
    "role-play, stress key-extraction, indirect injection, code interpretation, and "
    "refusal cliff; a trailing index selects the individual probe (the first "
    "translation-exfiltration probe), and this form is used throughout."
)

# ------------------------------------------------- 2. exact full-line/phrase
specials = [
    ("Reference row: dots3-note-prev pooled (B1+B3 arm A + E6)",
     "Reference row: the primary model's pooled estimate (the first and second samples, arm A, plus the third sample)"),
    (" & B1 & B3 & E6 \\\\",
     " & Sample 1 & Sample 2 & Sample 3 \\\\"),
    ("\\subsection{Cross-Vendor Replication (E1)}",
     "\\subsection{Cross-Vendor Replication}"),
    ("B1, B3, E2b, E6,\n      E4",
     "the first, second, schema-hiding, third, and consumer samples"),
]

# ------------------------------------------------- 3. regex substitutions
# Phase 3a: specific phrases that, if left to the generic regex, would produce
# double articles ("the the stress test") or duplicated replacement words
# ("the repetition-v2 run repetition-v2 run").
phrase_regex = [
    (r"The\s*E10\s+stress\s+test", "The stress test"),
    (r"the\s+E10\s+stress\s+test", "the stress test"),
    (r"The\s*E12\s+repetition-v2\s+run", "The repetition-v2 run"),
    (r"The\s*E11\s+gate", "The public-benchmark probe set gate"),
    (r"The\s*E10\s+gate", "The stress test gate"),
    (r"the\s+E8\s+attacker", "the red-team run attacker"),
    (r"the\s+E7\s+measurement", "the real-trace defense test measurement"),
    (r"the\s+B1\+B3\s+campaign", "the first and second samples"),
    (r"B3\s+and\s+E6", "the second and third samples"),
    (r"B3,\s+E6,\s+and", "the second, third, and"),
    (r"E4\s+producer\s+arm", "the consumer arm"),
    (r"E4\s+producer\s+responses", "consumer-arm responses"),
    (r"M-A\s+Nemotron-3-Super", "Nemotron-3-Super"),
    (r"M-B\s+Beam", "Beam"),
    (r"M-C\s+Nemotron-3-Nano", "Nemotron-3-Nano"),
]

# Phase 3b: generic word-boundary codes, longest-first so E12/E11/E10/E1-v2
# are consumed before E1.
generic_regex = [
    (r"\bE12\b", "the repetition-v2 run"),
    (r"\bE11\b", "the public-benchmark probe set"),
    (r"\bE10\b", "the stress test"),
    (r"\bE1-v2\b", "the census run"),
    (r"\bE9\b", "the production-baseline probe set"),
    (r"\bE8\b", "the red-team run"),
    (r"\bE7\b", "the real-trace defense test"),
    (r"\bE2b\b", "the schema-hiding arm"),
    (r"\bE6\b", "the third sample"),
    (r"\bE4\b", "the consumer arm"),
    (r"\bE1\b", "the cross-vendor replication"),
    (r"\bB3\b", "the second sample"),
    (r"\bB1\b", "the first sample"),
    (r"\bM-A\b", "the first cross-vendor model"),
    (r"\bM-B\b", "the second cross-vendor model"),
    (r"\bM-C\b", "the third cross-vendor model"),
]

# ---------------------------------------------------------------- apply
# 1. legend
new = t[:ls] + NEW_LEGEND + t[le:]

# 2. specials
for old, rep in specials:
    n = new.count(old)
    if n != 1:
        sys.exit("special %r: expected 1, found %d" % (old, n))
    new = new.replace(old, rep, 1)

# 3a. phrase regex
for pat, rep in phrase_regex:
    new, k = re.subn(pat, rep, new)
    if k == 0:
        sys.exit("phrase regex %r matched 0 times" % pat)
    print("phrase %-45s -> %d" % (pat, k))

# 3b. generic regex
for pat, rep in generic_regex:
    new, k = re.subn(pat, rep, new)
    if k == 0:
        sys.exit("generic regex %r matched 0 times" % pat)
    print("generic %-40s -> %d" % (pat, k))

# 4. collapse double articles introduced by replacement phrases
for pat, rep in [
    (r"The\s+the\b", "The"),
    (r"\bthe\s+the\b", "the"),
    (r"\ba\s+the\b", "a"),
    (r"\ban\s+the\b", "an"),
    (r"\bA\s+the\b", "A"),
    (r"\bAn\s+the\b", "An"),
]:
    new, k = re.subn(pat, rep, new)
    if k:
        print("collapse %-25s -> %d" % (pat, k))

# ---------------------------------------------------------------- verify
left = [c for c in ["B1", "B3", "E1", "E1-v2", "E2b", "E4", "E6", "E7", "E8", "E9",
                    "E10", "E11", "E12", "M-A", "M-B", "M-C", "dots3-note-prev",
                    "D30", "C0", "RAW", "reverse-effective", "\\texttt"]
        if new.count(c) > 0]
if left:
    sys.exit("VERIFY: still present: %s" % left)

# also verify no double-artifact phrases survived
for bad in ["the the stress test", "the repetition-v2 run repetition-v2 run",
            "the the repetition-v2 run", "the the public-benchmark probe set",
            "the the red-team run", "the the real-trace defense test",
            "the the consumer arm", "the the first and second samples",
            "the the second and third samples", "the the third sample",
            "the the first sample", "the the cross-vendor replication",
            "the the schema-hiding arm", "the the stress test",
            "the the census run", "the the production-baseline probe set"]:
    if new.count(bad) > 0:
        sys.exit("VERIFY: double-artifact phrase survived: %r" % bad)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(new)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("APPLIED %d specials + %d phrase + %d generic regex groups; new size %d (was %d)"
      % (len(specials), len(phrase_regex), len(generic_regex), os.path.getsize(PATH), len(t)))