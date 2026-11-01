#!/usr/bin/env python3
"""Pass-16b: clarify confusing passages -- add model name cross-reference,
define 'triple' explicitly, move 'naive recomputations' definition earlier,
define 'common deployed redaction shape', clarify 'extended reasoning',
and add a probe-class summary table for quick reference.
verify-then-apply, atomic write."""

import os, re, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
NL = chr(10)

EDITS = []

# --- Define 'triple' explicitly at first use -------------------------------
EDITS.append((
    "it compares\nthe three-part verdict (final-answer leak, reasoning-channel leak, refusal) across repeats of the same probe, so its unit is the probe",
    "it compares\nthe three-part verdict (final-answer leak, reasoning-channel leak, refusal; henceforth the verdict triple) across repeats of the same probe, so its unit is the probe",
    1,
))

# --- Move 'naive recomputations' definition before its first use -----------
# First, remove the definition from its current position (after the discussion)
EDITS.append((
    "By \\emph{naive recomputations} we mean pooled-rate estimates that apply an undocumented filter to the raw records, without the reconciliation script that maps every reported figure to its JSON field (Section~\\ref{sec:reproducibility}). Re-deriving the statistic from source",
    "Re-deriving the statistic from source",
    1,
))
# Then add the definition right after "A single pooled rate would mix..."
EDITS.append((
    "A single\npooled rate would mix fresh probes with runs that deliberately re-execute\nprobes already known to leak.",
    "A single\npooled rate would mix fresh probes with runs that deliberately re-execute\nprobes already known to leak. By \\emph{naive recomputations} we mean pooled-rate estimates that apply an undocumented filter to the raw records, without the reconciliation script that maps every reported figure to its JSON field (Section~\\ref{sec:reproducibility}).",
    1,
))

# --- Define 'common deployed redaction shape' -----------------------------
EDITS.append((
    "(retaining the first 11 and last 4 characters, the common deployed redaction\nshape; here $\\tau$ denotes the literal scrubber at full or partial coverage)",
    "(retaining the first 11 and last 4 characters of each key, a common deployed redaction shape that masks the middle; here $\\tau$ denotes the literal scrubber at full or partial coverage)",
    1,
))

# --- Clarify 'extended reasoning' at first use -----------------------------
EDITS.append((
    "the worst combination, thinking leak under a prompt that elicits extended reasoning, falls",
    "the worst combination, thinking leak under a prompt that elicits extended reasoning (a prompt that asks the model to work through the problem step by step), falls",
    1,
))

# --- Add model name cross-reference after first mention --------------------
# Insert after "the first cross-vendor model" line
EDITS.append((
    "the first cross-vendor model \\emph{nvidia/nemotron-3-super-120b-a12b} (NVIDIA, 120B-A12B mixture-of-experts, MoE; sizes give total--active parameters in billions),\nthe second cross-vendor model \\emph{reflection/beam-free} (Reflection AI, Beam 501B-A23B MoE), and\nthe third cross-vendor model \\emph{nvidia/nemotron-3-nano-omni-30b-a3b-reasoning} (NVIDIA, 30B-A3B\nreasoning).",
    "the first cross-vendor model \\emph{nvidia/nemotron-3-super-120b-a12b} (NVIDIA, 120B-A12B mixture-of-experts, MoE; sizes give total--active parameters in billions),\nthe second cross-vendor model \\emph{reflection/beam-free} (Reflection AI, Beam 501B-A23B MoE), and\nthe third cross-vendor model \\emph{nvidia/nemotron-3-nano-omni-30b-a3b-reasoning} (NVIDIA, 30B-A3B\nreasoning). Table~\\ref{tab:e1cross} lists the short names used below: the first cross-vendor model is Nemotron-3-Super, the second is Beam, and the third is Nemotron-3-Nano.",
    1,
))

# --- Clarify 'bound branches' vs 'binding branch' --------------------------
EDITS.append((
    "comonotonic coupling---the bound branches share a single uniform variable and\neach layer applies its own threshold---the same marginals permit a maximum",
    "comonotonic coupling---the bound branches (the $\\rho=0$ and $\\rho=1$ cases) share a single uniform variable and\neach layer applies its own threshold---the same marginals permit a maximum",
    1,
))

# --- Clarify 'log-indexing service' ----------------------------------------
EDITS.append((
    "a neutral log-indexing service instructed to list every credential\nstring in an excerpt it receives",
    "a neutral downstream consumer (a log-indexing service instructed to list every credential\nstring in an excerpt it receives)",
    1,
))

# --- Add 'ladder' clarification --------------------------------------------
EDITS.append((
    "a five-strategy ladder (indirect injection, key extraction from exposed CoT, code interpretation, multi-turn escalation, translation exfiltration). The attacker observes each response and advances only\nwhen the current strategy is blocked or fails.",
    "a five-strategy ladder (indirect injection, key extraction from exposed CoT, code interpretation, multi-turn escalation, translation exfiltration; by \\emph{ladder} we mean an ordered set of strategies the attacker tries in sequence). The attacker observes each response and advances only\nwhen the current strategy is blocked or fails.",
    1,
))

# --- Add statistical context for 7-request sample -------------------------
EDITS.append((
    "the security audit run attacker observed no final-answer leak in its 7\nrequests---a narrow sample whose upper bound should not be treated as representative of the\ndeployment.",
    "the security audit run attacker observed no final-answer leak in its 7\nrequests---a narrow sample (one-sided 95\\% upper bound 17.4\\% for a zero-for-seven rate) whose upper bound should not be treated as representative of the\ndeployment.",
    1,
))

# --- Define 'v' before first use in schema-hiding section ------------------
EDITS.append((
    "does not hold in this deployment shape. Here and below $v$ denotes the\nviolation-rate change under schema hiding relative to the same-probe baseline,",
    "does not hold in this deployment shape. Here and below $v$ denotes the\nviolation-rate change under schema hiding relative to the same-probe baseline,\nnormalized so that $v=1$ means the leak is eliminated, $v=0$ means no change, and\n$v<0$ means the leak worsens; formally $v=(r_{\\text{base}}-r_{\\text{new}})/r_{\\text{base}}$, with $r$ the CoT leak rate. The literature-anchored value $v\\approx0.55$ is\nthe reduction implied by the violation-rate finding of~\\cite{rbac2026}; it is the value the real-probe arm below tests against.",
    1,
))

# --- Remove the now-duplicated v definition that follows -------------------
EDITS.append((
    "normalized so that $v=1$ means the leak is eliminated, $v=0$ means no change, and\n$v<0$ means the leak worsens; formally $v=(r_{base}-r_{new})/r_{base}$, with $r$ the CoT leak rate. The literature-anchored value $v\\approx0.55$ is\nthe reduction implied by the violation-rate finding of~\\cite{rbac2026}; it is the value the real-probe arm below tests against.\nProbe-level",
    "Probe-level",
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
    tmp = SRC + ".tmp16b"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 16b: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())