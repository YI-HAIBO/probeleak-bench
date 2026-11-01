#!/usr/bin/env python3
"""Pass-18b: residual first-person ("We study / We parameterize / We ask /
We evaluate / We measured / We model / we deployed / we ran / we tested")
and two engineering-voice passages (rolling 60-second window; "a neutral
downstream consumer (a log-indexing service ...)" redundancy).
verify-then-apply, atomic write."""

import os, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
NL = chr(10)

EDITS = []

# --- L280: "We study the deployment in Figure" -> passive --------------------
EDITS.append((
    "\\textbf{Agent stack.} We study the deployment in",
    "\\textbf{Agent stack.} The deployment studied is shown in",
    1,
))

# --- L324: "We parameterize the three families as follows:" -----------------
EDITS.append((
    "\\textbf{Defense knobs.} We parameterize the three families as follows:",
    "\\textbf{Defense knobs.} The three families are parameterized as follows:",
    1,
))

# --- L366-369: drop "a rolling 60-second window" (implementation detail) -----
EDITS.append((
    "adaptive rate limiting (a rolling 60-second window)" + NL + "because the endpoint throughput is approximately 1{,}500--3{,}000 tokens per",
    "adaptive rate limiting (the endpoint throughput is approximately 1{,}500--3{,}000 tokens per",
    1,
))

# --- L737: "We model correlation with a shared-blindspot mixture" ------------
EDITS.append((
    "their failure events are correlated. We model correlation with a shared-blindspot mixture: on each probe, with",
    "their failure events are correlated. Correlation is modeled with a shared-blindspot mixture: on each probe, with",
    1,
))

# --- L920-921: "we deployed a real downstream consumer---a neutral downstream
#     consumer (a log-indexing service ..." -> passive + de-redundant ------------
EDITS.append((
    "To ground Eq.~\\eqref{eq:consumer} we deployed a real downstream" + NL + "consumer---a neutral downstream consumer (a log-indexing service instructed to list every credential",
    "To ground Eq.~\\eqref{eq:consumer}, a real downstream consumer was deployed---a neutral log-indexing service (instructed to list every credential",
    1,
))

# --- L958: "We ask whether an online agent" -> "The question is whether" ------
EDITS.append((
    "\\textbf{Setup.} We ask whether an online agent that observes honeypot-downstream",
    "\\textbf{Setup.} The question is whether an online agent that observes honeypot-downstream",
    1,
))

# --- L1082: "We evaluate each paradigm against the eight real CoT-only leak events"
EDITS.append((
    "\\textbf{Design.} We evaluate each paradigm against the eight real CoT-only leak events",
    "\\textbf{Design.} Each paradigm is evaluated against the eight real CoT-only leak events",
    1,
))

# --- L1336: conclusion "We measured leakage in LLM-based database agents" ----
EDITS.append((
    "We measured leakage in LLM-based database agents with channel separation,",
    "Leakage was measured in LLM-based database agents with channel separation,",
    1,
))

# --- L416: "cherry-picked, we ran eight probes" -> passive -------------------
EDITS.append((
    "concern that the probe set is nonetheless cherry-picked, we ran eight probes",
    "concern that the probe set is nonetheless cherry-picked, eight probes were run",
    1,
))

# --- L437: "which we tested on a real reasoning model." -> passive ------------
EDITS.append((
    "which we tested on a real reasoning model.",
    "which was tested on a real reasoning model.",
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
    tmp = SRC + ".tmp18b"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 18b: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())