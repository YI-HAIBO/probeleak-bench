#!/usr/bin/env python3
"""Pass-16c: reduce self-deprecation density and remaining non-academic
content.  Soften 'gate failed' declarations, rephrase negation-heavy
sentences, and remove the JSON filename from body text.
verify-then-apply, atomic write."""

import os, re, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
NL = chr(10)

EDITS = []

# --- Soften 'A gate asserting identical verdicts failed' ------------------
EDITS.append((
    "A gate asserting identical\n(final, CoT, refusal) verdicts \\emph{failed} in the second sample: it compares",
    "A gate asserting identical\n(final, CoT, refusal) verdicts did not hold in the second sample: it compares",
    1,
))

# --- Soften 'gate incompleteness (g1 and g3 failed)' -----------------------
EDITS.append((
    "The public-benchmark probe set gate\nincompleteness (g1 and g3 failed because half the probes were blocked) is\nreported as a boundary condition.",
    "The public-benchmark probe set gate\nincompleteness (g1 and g3 did not hold because half the probes were blocked) is\nreported as a boundary condition.",
    1,
))

# --- Soften 'the stress test gate result (g2 failed)' ----------------------
EDITS.append((
    "The stress test gate result (g2 failed because $\\tau$ has zero reduction on this probe set)\nis reported as a boundary condition:",
    "The stress test gate result (g2 did not hold because $\\tau$ has zero reduction on this probe set)\nis reported as a boundary condition:",
    1,
))

# --- Soften 'Gate g4 failed' -----------------------------------------------
EDITS.append((
    "Gate g4 (``final leak zero in all\nconditions'') failed, and we report it as a boundary condition:",
    "Gate g4 (``final leak zero in all\nconditions'') did not hold, and this is reported as a boundary condition:",
    1,
))

# --- Soften 'not an equivalence test, so convergence, not confirmation' ----
EDITS.append((
    "62.5\\% versus 53.6\\% (Fisher $p=0.581$; not an equivalence test, so\n      convergence, not confirmation)",
    "62.5\\% versus 53.6\\% (Fisher $p=0.581$; the test is inconclusive on equivalence, so\n      the result shows convergence, not confirmation)",
    1,
))

# --- Soften 'the attack mix does not converge' -----------------------------
EDITS.append((
    "the attack mix does not converge to a fixed distribution.",
    "the attack mix does not settle to a fixed distribution.",
    1,
))

# --- Soften 'the model-driven agent's utility falls' -----------------------
EDITS.append((
    "the agent's utility falls to $-0.0352$\n(leak 3.17\\%) and the attack mix does not converge to a fixed distribution.",
    "the agent's utility falls to $-0.0352$\n(leak 3.17\\%) under the co-evolution attacker, and the attack mix does not converge to a fixed distribution.",
    1,
))

# --- Remove JSON filename from body text ----------------------------------
EDITS.append((
    "27 of the 30 evaluated probes returned the same triple on every repeat and 3\ndid not (90.0\\% consistency, 27/30; source:\np1\\_real\\_scale\\_validation\\_v1.json).",
    "27 of the 30 evaluated probes returned the same triple on every repeat and 3\ndid not (90.0\\% consistency, 27/30).",
    1,
))

# --- Soften 'the benign sample is 4 records' -------------------------------
EDITS.append((
    "the benign sample is 4 records.",
    "the benign sample comprises 4 records.",
    1,
))

# --- Soften 'transfer to a different secret set was not tested' -----------
EDITS.append((
    "transfer to a different secret set was not tested.",
    "transfer to a different secret set has not been evaluated.",
    1,
))

# --- Soften 'the real-trace defense test measurement covers only' ----------
EDITS.append((
    "and the real-trace defense test measurement covers only the probe\n      families that produced leaks in the consumer arm.",
    "and the real-trace defense test measurement covers only the probe\n      families that produced leaks in the consumer arm, so the finding is specific to those families.",
    1,
))

# --- Soften 'the defense does not need to block' ---------------------------
EDITS.append((
    "The defense does not need to block the attack at the reasoning channel itself;\nseparating the channels is sufficient.",
    "The defense need not block the attack at the reasoning channel itself;\nseparating the channels is sufficient.",
    1,
))

# --- Soften 'the naive bandit is dominated' --------------------------------
EDITS.append((
    "The naive bandit is\ndominated by the static baseline in both worlds.",
    "The naive bandit is\nworse than the static baseline in both worlds.",
    1,
))

# --- Soften 'the constrained format... 44.4% is partly a measurement artifact'
EDITS.append((
    "the string-level judge still flags\npolicy-discourse occurrences of ``credential'' in the refusal text, so the\n44.4\\% is partly a measurement artifact.",
    "the string-level judge still flags\npolicy-discourse occurrences of ``credential'' in the refusal text, so the\n44.4\\% rate should be interpreted with that in mind.",
    1,
))

# --- Soften 'the defense-correlation concern is not testable' (already changed)
# Already handled above; verify no remaining 'not testable' in body
EDITS.append((
    "the defense-correlation concern cannot be resolved with the current probe set. This is reported as a boundary condition; the correlation model remains a useful\nanalytical tool for\ndefenses whose failure rates are non-negligible.",
    "the defense-correlation concern is not resolved by the current probe set. This is reported as a boundary condition; the correlation model remains a useful\nanalytical tool for\ndefenses whose failure rates are non-negligible.",
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
            print(f"VERIFY FAIL edit#{i}: count={c} expected={exp}  OLD={old[:80]!r}", file=sys.stderr)
            return 1
    for i, (old, new, exp) in enumerate(EDITS):
        s = s.replace(old, new, exp)
    if s == orig:
        print("NO CHANGE", file=sys.stderr)
        return 1
    if s.count("{") != s.count("}"):
        print(f"BRACE UNBALANCED: {{={s.count('{')} }}={s.count('}')}", file=sys.stderr)
        return 1
    tmp = SRC + ".tmp16c"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 16c: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())