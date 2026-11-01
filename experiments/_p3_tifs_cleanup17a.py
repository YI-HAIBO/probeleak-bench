#!/usr/bin/env python3
"""Pass-17a: residual first-person ("We..."/"our...") and hedging ("exactly")
phrases that survived Pass-16a.  Objective academic prose.
verify-then-apply, atomic write."""

import os, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
NL = chr(10)

EDITS = []

# --- "our observation" -> "the observation" (L263) ---------------------------
EDITS.append((
    "our observation that the same reasoning capabilities that improve backbone",
    "the observation that the same reasoning capabilities that improve backbone",
    1,
))

# --- "agent stack our threat model targets" -> "targeted by the threat model" --
EDITS.append((
    "surveys describe the tool-using agent stack our threat model targets~\\cite{agentsurvey}.",
    "surveys describe the tool-using agent stack targeted by the threat model~\\cite{agentsurvey}.",
    1,
))

# --- "We use the primary model's high-tier pooled estimate" -> passive --------
EDITS.append((
    "Nemotron-3-Nano. We use the primary model's high-tier pooled estimate (15/28, where 28 is the total",
    "Nemotron-3-Nano. The primary model's high-tier pooled estimate is used (15/28, where 28 is the total",
    1,
))

# --- "our sentence-level output-side filter" -> "the ..." (L830) --------------
EDITS.append((
    "An output-side filter (our sentence-level output-side filter) that detects and",
    "An output-side filter (the sentence-level output-side filter) that detects and",
    1,
))

# --- "We measured exactly this in / simulation." -> "This was measured in ..." --
EDITS.append((
    "may simply re-emit the material in its final answer. We measured exactly this in" + NL + "simulation.",
    "may simply re-emit the material in its final answer. This was measured in" + NL + "simulation.",
    1,
))

# --- "follows exactly" -> "follows" (L939) ------------------------------------
EDITS.append((
    "recovered. The benefit therefore follows exactly",
    "recovered. The benefit therefore follows",
    1,
))

# --- "in our sample," -> "in the sample," (L1057) ----------------------------
EDITS.append((
    "through CoT still cannot deliver it to a final-only consumer in our sample,",
    "through CoT still cannot deliver it to a final-only consumer in the sample,",
    1,
))

# --- "within our threat model the" -> "within the threat model the" (L1165) ---
EDITS.append((
    "deployed-side mechanisms that do not observe it, so within our threat model the",
    "deployed-side mechanisms that do not observe it, so within the threat model the",
    1,
))

# --- "within our threat model they give" -> "within the threat model they give"
EDITS.append((
    "observe the reasoning channel, so within our threat model they give an adaptive",
    "observe the reasoning channel, so within the threat model they give an adaptive",
    1,
))


def main():
    if not os.path.exists(SRC):
        print("FATAL: source missing", file=sys.stderr)
        return 2
    s = open(SRC, encoding="utf-8").read()
    orig = s
    for i, (old, new, exp) in enumerate(EDITS):
        c = s.count(old)
        if c != exp:
            print(f"VERIFY FAIL edit#{i}: count={c} expected={exp}  OLD={old[:90]!r}", file=sys.stderr)
            return 1
    for i, (old, new, exp) in enumerate(EDITS):
        s = s.replace(old, new, exp)
    if s == orig:
        print("NO CHANGE", file=sys.stderr)
        return 1
    if s.count("{") != s.count("}"):
        print(f"BRACE UNBALANCED: {{={s.count('{')} }}={s.count('}')}", file=sys.stderr)
        return 1
    tmp = SRC + ".tmp17a"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 17a: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())