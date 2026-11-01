#!/usr/bin/env python3
"""Pass-15a: AI-flavour reduction -- rewrite assertive short bold subheadings
into descriptive labels, and rephrase the Contributions list and the
'Note on evidence types.' paragraph.  verify-then-apply, atomic write."""

import os, re, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

NL = chr(10)

# Each tuple: (old, new, expected_count)
EDITS = []

# --- Introduction: three gap assertions merged into flowing prose -----------
EDITS.append((
    "\\textbf{The reasoning channel is not measured separately.} Reasoning",
    "Reasoning",
    1,
))
EDITS.append((
    "\\textbf{Defense stacking is evaluated under an independence\nassumption.} Production",
    "Production",
    1,
))
EDITS.append((
    "\\textbf{Simulation results are not calibrated against real models.} A\n",
    "A\n",
    1,
))

# --- Introduction: Contributions list ---------------------------------------
EDITS.append((
    "\\textbf{Contributions.}" + NL + "\\begin{enumerate}",
    "\\begin{enumerate}",
    1,
))

# --- Introduction: Note on evidence types -----------------------------------
EDITS.append((
    "\\textbf{Note on evidence types.} Direct forensic measurements",
    "Direct forensic measurements",
    1,
))

# --- Background -------------------------------------------------------------
EDITS.append((
    "\\textbf{Consumer-side channel visibility.} The quantity",
    "The quantity",
    1,
))

# --- Measurement Framework --------------------------------------------------
EDITS.append((
    "\\textbf{Reproducibility discipline.} Every experiment",
    "Every experiment",
    1,
))
EDITS.append((
    "\\textbf{Anti-cherry-picking.} An earlier",
    "An earlier",
    1,
))
EDITS.append((
    "\\textbf{Public-benchmark cross-validation (the public-benchmark probe set).} To address",
    "To address",
    1,
))

# --- Native Blind Spot ------------------------------------------------------
EDITS.append((
    "\\textbf{Channel isolation is verified, not assumed.} Gate",
    "Gate",
    1,
))
EDITS.append((
    "\\textbf{The input-side gateway is a separate, coarse layer.} Across",
    "Across",
    1,
))
EDITS.append((
    "\\textbf{Reproducibility failure is itself a result.} A gate",
    "A gate",
    1,
))
EDITS.append((
    "\\textbf{The pooled sample spans two regimes and must be split.} A single",
    "A single",
    1,
))
EDITS.append((
    "\\textbf{Cross-model generality is architecturally bounded.} We attempted",
    "We attempted",
    1,
))
EDITS.append((
    "\\textbf{Confidence structure.} The third sample",
    "The third sample",
    1,
))

# --- Cross-Vendor Replication -----------------------------------------------
EDITS.append((
    "\\textbf{The blind spot is consistent across vendors, but not uniformly.} the second",
    "the second",
    1,
))
EDITS.append((
    "\\textbf{NVIDIA models leak far less.} the first",
    "the first",
    1,
))
EDITS.append((
    "\\textbf{Channel structure is preserved.} Across",
    "Across",
    1,
))

# --- Defense Stacking -------------------------------------------------------
EDITS.append((
    "\\textbf{An earlier measurement, and its correction.} An earlier",
    "An earlier",
    1,
))
EDITS.append((
    "\\textbf{Deployment collapse.} At the deployed",
    "At the deployed",
    1,
))
EDITS.append((
    "\\textbf{Cost, not correlation, is the binding constraint.} Under",
    "Under",
    1,
))
EDITS.append((
    "\\textbf{Real-data calibration (the real-trace defense test).} The simulation",
    "The simulation",
    1,
))

# --- Output-Side Filtering --------------------------------------------------
EDITS.append((
    "\\textbf{The displacement problem.} An output-side",
    "An output-side",
    1,
))
EDITS.append((
    "\\textbf{Metric discipline.} Scoring",
    "Scoring",
    1,
))
EDITS.append((
    "\\textbf{The $\\tau$ countermeasure almost closes the displacement channel, but not" + NL + "the economic gap.} Adding",
    "Adding",
    1,
))
EDITS.append((
    "\\textbf{Real-model calibration inverts the picture.} On the real",
    "On the real",
    1,
))
EDITS.append((
    "\\textbf{Stress-test calibration (the stress test).} The claim",
    "The claim",
    1,
))
EDITS.append((
    "\\textbf{Prompt-level self-check is counter-productive.} An arm",
    "An arm",
    1,
))
EDITS.append((
    "\\textbf{Consumer-side visibility determines which leaks matter.} Equation",
    "Equation",
    1,
))
EDITS.append((
    "\\textbf{An end-to-end consumer lets us replace the modeled $p_{cot}$ with a" + NL + "measurement.} To ground",
    "To ground",
    1,
))

# --- Adaptive Defense -------------------------------------------------------
EDITS.append((
    "\\textbf{The naive bandit fails because of weak signal.} The expected-utility",
    "The expected-utility",
    1,
))
EDITS.append((
    "\\textbf{The model-driven agent dominates in both worlds.} Table",
    "Table",
    1,
))
EDITS.append((
    "\\textbf{Two measured properties stand out.} First",
    "First",
    1,
))
EDITS.append((
    "\\textbf{The oracle's nonzero residual has a concrete explanation.} In the",
    "In the",
    1,
))
EDITS.append((
    "\\textbf{Real adaptive attacker (the red-team run).} A real",
    "A real",
    1,
))
EDITS.append((
    "\\textbf{Attack-defense interaction.} the red-team",
    "the red-team",
    1,
))

# --- Baselines --------------------------------------------------------------
EDITS.append((
    "\\textbf{Mechanism reach is disjoint from the blind spot.} PCC-SQL",
    "PCC-SQL",
    1,
))
EDITS.append((
    "\\textbf{Real-probe arm confirms the model rather than the assumption.} We re-ran",
    "We re-ran",
    1,
))
EDITS.append((
    "\\textbf{Three-condition operational-baseline probe (the operational-baseline probe set).} We extended",
    "We extended",
    1,
))
EDITS.append((
    "\\textbf{Even with baselines in the action set, the channel-layer agent" + NL + "outperforms every alternative.} Extending",
    "Extending",
    1,
))


def main():
    if not os.path.exists(SRC):
        print("FATAL: source missing", file=sys.stderr)
        return 2
    s = open(SRC, encoding="utf-8").read()
    orig = s
    # verify all
    for i, (old, new, exp) in enumerate(EDITS):
        c = s.count(old)
        if c != exp:
            print(f"VERIFY FAIL edit#{i}: count={c} expected={exp}  OLD={old[:80]!r}", file=sys.stderr)
            return 1
    # apply
    for i, (old, new, exp) in enumerate(EDITS):
        s = s.replace(old, new, exp)
    if s == orig:
        print("NO CHANGE", file=sys.stderr)
        return 1
    # brace balance check
    if s.count("{") != s.count("}"):
        print(f"BRACE UNBALANCED: {{={s.count('{')} }}={s.count('}')}", file=sys.stderr)
        return 1
    # write tmp + fsync + replace
    tmp = SRC + ".tmp15a"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 15a: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())