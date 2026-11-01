#!/usr/bin/env python3
"""Pass-16a: AI-flavour reduction -- rewrite "We..." self-referential
sentences and evaluative AI phrasing into objective academic prose.
verify-then-apply, atomic write."""

import os, re, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
NL = chr(10)

EDITS = []

# --- "We give a concrete case" -> objective --------------------------------
EDITS.append((
    "We give a concrete case: a\nsimulated world model predicts that output-side filtering has a net benefit",
    "A concrete case illustrates the risk: a\nsimulated world model predicts that output-side filtering has a net benefit",
    1,
))

# --- "We add the channel-separated magnitudes" -> "This paper adds" --------
EDITS.append((
    "This line of work studies the same phenomenon from the privacy side rather\nthan the measurement side: it establishes that reasoning leaks. We add the\nchannel-separated magnitudes",
    "This line of work studies the same phenomenon from the privacy side rather\nthan the measurement side: it establishes that reasoning leaks. This paper adds\nthe channel-separated magnitudes",
    1,
))

# --- "We quantify the achievable inflation" -> "The achievable inflation" --
EDITS.append((
    "We quantify the achievable inflation under a margin-consistent coupling: the inflation is",
    "The achievable inflation under a margin-consistent coupling is",
    1,
))

# --- "We ask whether" -> "The question is whether" -------------------------
EDITS.append((
    "We ask whether these paradigms obviate the channel-layer finding, or whether the\nreasoning channel is simply beyond what they observe.",
    "The question is whether these paradigms obviate the channel-layer finding, or\nwhether the reasoning channel is simply beyond what they observe.",
    1,
))

# --- "We therefore adopt" -> "The union reduction is therefore adopted" ----
EDITS.append((
    "We therefore adopt the union\nreduction as the benefit metric throughout",
    "The union reduction is therefore adopted as the benefit metric throughout",
    1,
))

# --- "We tested whether" -> "Whether this premise held" -------------------
EDITS.append((
    "We tested\nwhether this premise holds on real data by applying",
    "Whether this premise holds on real data was tested by applying",
    1,
))

# --- "We re-ran six core probes" -> "Six core probes were re-run" -----------
EDITS.append((
    "We re-ran six\ncore probes under the schema-hidden prompt on the real model",
    "Six core probes were re-run under the schema-hidden prompt on the real model",
    1,
))

# --- "We extended the arm" -> "The arm was extended" -----------------------
EDITS.append((
    "We extended the arm to a\nfull three-condition comparison",
    "The arm was extended to a\nfull three-condition comparison",
    1,
))

# --- "We measure the converse case" -> "The converse case is measured" ------
EDITS.append((
    "We measure the converse case: a model whose final\nanswers are clean but whose reasoning enumerates secrets.",
    "The converse case is measured: a model whose final\nanswers are clean but whose reasoning enumerates secrets.",
    1,
))

# --- "Our probe suite covers" -> "The probe suite covers" ------------------
EDITS.append((
    "Our probe suite covers the same\nsurface but is instrumented for",
    "The probe suite covers the same\nsurface but is instrumented for",
    1,
))

# --- "Our results address a different stage" -> "The results address" ------
EDITS.append((
    "Our\nresults address a different stage: PCC-SQL is a producer-side deterministic mechanism",
    "The\nresults address a different stage: PCC-SQL is a producer-side deterministic mechanism",
    1,
))

# --- "Our finding that" -> "The finding that" -----------------------------
EDITS.append((
    "our finding that the\nfinal-answer channel can be clean is consistent with such controls closing it.",
    "the finding that the\nfinal-answer channel can be clean is consistent with such controls closing it.",
    1,
))

# --- "Our results have four direct consequences" -> "The results have four" --
EDITS.append((
    "Our results have four direct consequences for forensic practice, which we state\nseparately because they follow from the measurements rather than from analogy.",
    "The results have four direct consequences for forensic practice, stated\nseparately because they follow from the measurements rather than from analogy.",
    1,
))

# --- "We state separately" removed (merged above) --------------------------

# --- "We report this as a boundary condition" -> "This is reported as" ------
EDITS.append((
    "We\nreport this as a boundary condition; the correlation model remains a useful\nanalytical tool for",
    "This is reported as a boundary condition; the correlation model remains a useful\nanalytical tool for",
    1,
))

# --- "We therefore report" -> "It is reported as blocked" ------------------
EDITS.append((
    "we report it as blocked so that the\ncross-vendor transfer rates measured in simulation over six simulated vendors\nremain clearly labeled as simulation-only",
    "it is reported as blocked so that the\ncross-vendor transfer rates measured in simulation over six simulated vendors\nremain clearly labeled as simulation-only",
    1,
))

# --- "Two conclusions are supported" -> "Two conclusions follow" -----------
EDITS.append((
    "Two conclusions are supported: the CoT-native blind spot is not an artifact of probe selection,\nand the zero final-answer rate \\emph{is} probe-set-dependent.",
    "Two conclusions follow: the CoT-native blind spot is not an artifact of probe selection,\nand the zero final-answer rate \\emph{is} probe-set-dependent.",
    1,
))

# --- "Two further results are notable" -> "Two further results emerge" -----
EDITS.append((
    "Two further results are notable.",
    "Two further results emerge.",
    1,
))

# --- "We do not assume" -> "No assumption is made" -------------------------
EDITS.append((
    "We do not assume the attacker controls the model weights or the" + NL + "system prompt.",
    "No assumption is made that the attacker controls the model weights or the" + NL + "system prompt.",
    1,
))

# --- "We attempted to replicate" -> "An attempt was made to replicate" ------
EDITS.append((
    "We attempted to\nreplicate the blind spot on a second reasoning model through the same gateway",
    "An attempt was made to\nreplicate the blind spot on a second reasoning model through the same gateway",
    1,
))

# --- "We therefore replicated" -> "The measurement was therefore replicated"
EDITS.append((
    "We therefore replicated the\nmeasurement on a second, independent gateway (provider AtlasCloud) using the same",
    "The measurement was therefore replicated on a second, independent gateway (provider AtlasCloud) using the same",
    1,
))

# --- "We therefore stress-tested" -> "The conclusion was therefore stress-tested"
EDITS.append((
    "We therefore stress-tested that\nconclusion directly by running three key-extraction probes",
    "The conclusion was therefore stress-tested directly by running three key-extraction probes",
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
    tmp = SRC + ".tmp16a"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 16a: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())