#!/usr/bin/env python3
"""Pass-18a: mechanical grammar errors found on first-read -- four sentences
that begin with a lowercase "the" after a float/blank line, plus one spurious
"the" in "One benign the schema-hiding arm response".
verify-then-apply, atomic write."""

import os, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
NL = chr(10)

EDITS = []

# --- L404: "artifact. the repetition-v2 run" -> capitalize -------------------
EDITS.append((
    "artifact. the repetition-v2 run (the first to third translation-exfiltration probes",
    "artifact. The repetition-v2 run (the first to third translation-exfiltration probes",
    1,
))

# --- L667-668: "the second cross-vendor model leaks / at 62.5%..." -----------
EDITS.append((
    "the second cross-vendor model leaks" + NL + "at 62.5\\%, statistically indistinguishable from the baseline (Fisher",
    "The second cross-vendor model leaks" + NL + "at 62.5\\%, statistically indistinguishable from the baseline (Fisher",
    1,
))

# --- L678: "the first cross-vendor model (8.3%) and the third ... are both" ---
EDITS.append((
    "the first cross-vendor model (8.3\\%) and the third cross-vendor model (12.5\\%) are both",
    "The first cross-vendor model (8.3\\%) and the third cross-vendor model (12.5\\%) are both",
    1,
))

# --- L1052: "the security audit run establishes the attacker's side:" --------
EDITS.append((
    "the security audit run establishes the \\emph{attacker's} side:",
    "The security audit run establishes the \\emph{attacker's} side:",
    1,
))

# --- L1263: "One benign the schema-hiding arm response" -> drop spurious "the"
EDITS.append((
    "One benign the schema-hiding arm response carries a CoT leak by",
    "One benign schema-hiding arm response carries a CoT leak by",
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
    tmp = SRC + ".tmp18a"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 18a: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())