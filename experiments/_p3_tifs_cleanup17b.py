#!/usr/bin/env python3
"""Pass-17b: collapse repeated verbose HTTP-status-code parentheticals into
prose.  First occurrences with a gloss (B2 blocked section, census section,
502 case) keep their codes because they are load-bearing evidence; the two
redundant repeats are rewritten so the engineering shorthand does not double.
verify-then-apply, atomic write."""

import os, sys, shutil

SRC = r"C:\Users/Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

EDITS = []

# --- L420: repeat of HTTP 403 with verbose gloss -> prose --------------------
EDITS.append((
    "by the gateway with HTTP 403 (Forbidden; the upstream content-safety layer rejects the request before it reaches the model, for tool-use side-effect, instruction-conflict,",
    "by the gateway's content-safety layer (which rejects the request before it reaches the model, for tool-use side-effect, instruction-conflict,",
    1,
))

# --- L1251: repeat of HTTP 400/403 in the operational-baseline summary --------
EDITS.append((
    "      others return HTTP 400 (Bad Request) or HTTP 403 (Forbidden) with response bodies that distinguish",
    "      others return rejection errors, with response bodies that distinguish",
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
    tmp = SRC + ".tmp17b"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 17b: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())