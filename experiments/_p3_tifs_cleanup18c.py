#!/usr/bin/env python3
"""Pass-18c: "reported as a boundary condition" repeated four times after the
definition at L341 -- vary the third and fourth occurrences to "reported as
such".  Also drop the software-engineering parenthetical "(by a non-zero
exit status)".
verify-then-apply, atomic write."""

import os, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

EDITS = []

# --- L883: third use of "reported as a boundary condition" -> "as such" ------
EDITS.append((
    "is reported as a boundary condition: $\\tau$ is effective against verbatim",
    "is reported as such: $\\tau$ is effective against verbatim",
    1,
))

# --- L1154: fourth use -> "as such" -----------------------------------------
EDITS.append((
    "did not hold, and this is reported as a boundary condition: deployed-side paradigms defend the final-answer and prompt",
    "did not hold, and this is reported as such: deployed-side paradigms defend the final-answer and prompt",
    1,
))

# --- L1307: drop "(by a non-zero exit status)" engineering parenthetical ------
EDITS.append((
    "expose a check mode that signals failure (by a non-zero exit status) if a regenerated artifact differs",
    "expose a check mode that signals failure if a regenerated artifact differs",
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
    tmp = SRC + ".tmp18c"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 18c: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())