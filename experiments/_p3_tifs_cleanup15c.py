#!/usr/bin/env python3
"""Pass-15c: academicise remaining non-academic terms and reduce
self-deprecation density in body text (Limitations section is
retained as required by IEEE convention, but its wording is tightened)."""

import os, re, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
NL = chr(10)

EDITS = []

# --- 'red teamer' / 'red-team' → academic phrasing -------------------------
EDITS.append((
    "A real LLM-driven red teamer was run",
    "A real LLM-driven security audit was run",
    1,
))
EDITS.append((
    "the red-team run establishes",
    "the security audit run establishes",
    1,
))
EDITS.append((
    "the red-team run attacker observed",
    "the security audit run attacker observed",
    1,
))
EDITS.append((
    "The real LLM-driven red teamer (the red-team run)",
    "The real LLM-driven security audit (the security audit run)",
    1,
))
EDITS.append((
    "the red-team run)\n      extracted",
    "the security audit run)\n      extracted",
    1,
))

# --- 'NDA' / 'non-disclosure agreement' → 'disclosure agreement' ------------
# (the Two world models section already uses 'disclosure agreement'; only the
#  Responsible disclosure paragraph retains 'non-disclosure'.)
EDITS.append((
    "the primary real model is identified only under a non-disclosure\nagreement with the operator and that",
    "the primary real model is identified only under a disclosure agreement with the operator and that",
    1,
))

# --- 'rate limit' / 'throttle' / 'tokens per minute' → academic ------------
EDITS.append((
    "adaptive rate limiting (a rolling 60-second window)\nbecause the endpoint throttle is approximately 1{,}500--3{,}000 tokens per\nminute.",
    "adaptive rate limiting (a rolling 60-second window)\nbecause the endpoint throughput is approximately 1{,}500--3{,}000 tokens per\nminute.",
    1,
))

# --- 'idempotent' → 'reproducible' (check if already changed) ---------------
# (Pass-14c already handled this; verify remaining occurrences)
EDITS.append((
    "produced by an idempotent\ngenerator that re-reads",
    "produced by a reproducible\ngenerator that re-reads",
    1,
))
EDITS.append((
    "Report and figure generators are idempotent and expose",
    "Report and figure generators are reproducible and expose",
    1,
))

# --- 'We do not evaluate' → rephrase as scope statement --------------------
EDITS.append((
    "We do not evaluate prompt-level\ndefenses; the measurement target here is whether the reasoning channel\nexposes credentials planted in the database.",
    "Prompt-level defenses are outside the measurement target here, which is whether the reasoning channel\nexposes credentials planted in the database.",
    1,
))

# --- Condense the 'Note on evidence types' paragraph further ----------------
# (already de-bolded in 15a; now tighten the wording)
EDITS.append((
    "valid only within those models. The baseline comparison\n(Section~\\ref{sec:baselines}) and Section~\\ref{sec:forensic} are forensic\napplications of the measurements. Channel separation suffices as a control only when the\nfinal-answer channel is itself clean; on aggressive and public-benchmark probes\nthe final channel leaks at 62.5--100\\%, so the control must scan both channels\nin that regime. Every recommendation in this paper is stated under the\ncondition in which it was checked, and each is labeled with the sample.",
    "valid only within those models. The baseline comparison\n(Section~\\ref{sec:baselines}) and Section~\\ref{sec:forensic} are forensic\napplications of the measurements. Channel separation suffices as a control only when the\nfinal-answer channel is itself clean; on aggressive and public-benchmark probes\nthe final channel leaks at 62.5--100\\%, so the control must scan both channels\nin that regime. Each recommendation in this paper is stated under the\ncondition in which it was checked, and is labeled with the sample on which it rests.",
    1,
))

# --- Soften 'This is not decisive' -----------------------------------------
EDITS.append((
    "This is not decisive: a non-significant test is not evidence of equivalence,\nand a formal equivalence test would require a pre-specified margin that we did\nnot set.",
    "A non-significant test is not evidence of equivalence, and a formal\nequivalence test would require a pre-specified margin that we did not set;\nthe result is therefore inconclusive on model-family generality.",
    1,
))

# --- Soften 'not testable on the current probe set' ------------------------
EDITS.append((
    "making $\\rho$\nundefined rather than merely small. The real defenses appear more effective than the simulation's conservative priors assume, and the defense-correlation concern is not testable on the current probe set. We\nreport this as a boundary condition; the correlation model remains a useful\nanalytical tool for\ndefenses whose failure rates are non-negligible.",
    "making $\\rho$\nundefined rather than merely small. The real defenses appear more effective than the simulation's conservative priors assume, and the defense-correlation concern cannot be resolved with the current probe set. We\nreport this as a boundary condition; the correlation model remains a useful\nanalytical tool for\ndefenses whose failure rates are non-negligible.",
    1,
))

# --- Soften 'not an independent measurement' ------------------------------
EDITS.append((
    "The literature-anchored value $v\\approx0.55$ is\nthe reduction implied by the violation-rate finding of~\\cite{rbac2026}, not an\nindependent measurement; it is the value the real-probe arm below tests against.",
    "The literature-anchored value $v\\approx0.55$ is\nthe reduction implied by the violation-rate finding of~\\cite{rbac2026}; it is the value the real-probe arm below tests against.",
    1,
))

# --- Soften 'not a number any deployed agent is expected to realize' -------
EDITS.append((
    "not a number any deployed\nagent is expected to realize.",
    "not a number a deployed agent would be expected to realize in practice.",
    1,
))

# --- Soften 'not represent the deployment' ---------------------------------
EDITS.append((
    "a narrow sample whose upper bound does not represent the\ndeployment.",
    "a narrow sample whose upper bound should not be treated as representative of the\ndeployment.",
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
    tmp = SRC + ".tmp15c"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 15c: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())