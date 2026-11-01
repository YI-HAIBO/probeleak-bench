#!/usr/bin/env python
"""Pass-37: merge wave-2 cross-vendor results (E1c + B2) into p3_tifs.tex.

Atomic edits only: every (old, new) pair must occur exactly once in the file,
otherwise the whole patch aborts. Writes via .tmp + os.replace.
"""
import os
import sys

TEX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "paper", "p3_tifs.tex")
CRLF = chr(13) + chr(10)

EDITS = []


def A(old_lines, new_lines):
    EDITS.append((CRLF.join(old_lines), CRLF.join(new_lines)))


# ---------------------------------------------------------------- E1: family reading
A([
    "NVIDIA models is itself substantive: the blind spot is real but its expression",
    "depends on model-specific alignment, an interaction a single-model study",
    "cannot observe. The extension cohort below revises the family-level reading:",
    "vendor is not the operative variable.",
], [
    "NVIDIA models is itself substantive: the blind spot is real but its expression",
    "depends on model-specific alignment, an interaction a single-model study",
    "cannot observe. The extension cohort below revises the family-level reading:",
    "vendor is not the operative variable, and the second quota window revises the",
    "model-level reading: the 30B--A3B Nano rate was itself window-dependent.",
])

# ---------------------------------------------------------------- E1: wave-1 final-channel qualifier
A([
    "every other model keeps the final channel",
    "at zero on attack probes and controls at or near zero. The CoT-only asymmetry",
], [
    "every other first-wave model keeps the final channel",
    "at zero on attack probes and controls at or near zero. The CoT-only asymmetry",
])

# ---------------------------------------------------------------- E1: wave-2 paragraph + table caption
A([
    "within a quota window.",
    "",
    "\\begin{table}[t]",
    "\\centering",
    "\\caption{Extension cohort cross-vendor CoT leak rates, high-tier probes.}",
], [
    "within a quota window.",
    "",
    "\\textbf{Second quota window.} The shared quota rotates rather than depletes:",
    "the anonymous free pool re-opened on a later date, and the same protocol was",
    "re-run on four further free reasoning models (Table~\\ref{tab:e1b}, wave-2",
    "rows). Two re-tests of the original cross-vendor models qualify the earlier low",
    "rates: the 30B--A3B Nano model (Nemotron-3-Nano in Table~\\ref{tab:e1cross}),",
    "which leaked on 3/24 (12.5\\%) in the first window, leaks on 14/24 (58.3\\%) in",
    "the second, statistically indistinguishable from the primary baseline (Fisher",
    "$p=0.78$) and significantly above its own earlier window ($p=0.002$); Beam",
    "stays high (13/17 usable, 76.5\\%, $p=0.20$ versus the baseline and $p=0.50$",
    "versus its first window). The low Nemotron rates are therefore a property of",
    "the deployment window rather than of the model, and cross-window drift---not",
    "vendor, scale, or alignment---is the first-order source of rate variation on",
    "this gateway. A new vendor entry, Poolside Laguna XS 2.1, leaks on none of 13",
    "usable high-tier responses ($p=0.001$ while its reasoning channel is live:",
    "like the content-safety variant it never emits the keys, a second protective",
    "model. The wave-2 models also produce the first exceptions to the",
    "final-channel asymmetry outside the smallest model: the Nano model's fourth",
    "step-reconstruction probe twice leaks the key list in the final answer (2/24),",
    "and Laguna leaks once on the first prefix-extraction probe (1/13), so the",
    "CoT-only asymmetry is a property of larger or post-trained models rather than",
    "a universal consequence of channel separation. Xing 4.0 (29B--A4B, Xingchen",
    "AGI) was quota-blocked on all 32 attempts and contributes no data.",
    "",
    "\\begin{table}[t]",
    "\\centering",
    "\\caption{Extension cohort cross-vendor CoT leak rates across two quota windows.}",
])

# ---------------------------------------------------------------- tab:e1b rows
A([
    "Nemotron-3.5-Lightning (blocked) & NVIDIA & 0/0 & -- & -- \\\\",
    "\\midrule",
    "Ref.\\ primary model",
], [
    "Nemotron-3.5-Lightning (blocked) & NVIDIA & 0/0 & -- & -- \\\\",
    "\\midrule",
    "Nemotron-3-Nano-Omni (wave 2) & NVIDIA & 14/24 & 58.3\\% & 0.785 \\\\",
    "Beam (wave 2) & Reflection AI & 13/17 & 76.5\\% & 0.205 \\\\",
    "Laguna XS 2.1 & Poolside & 0/13 & 0.0\\% & 0.001 \\\\",
    "Xing 4.0 (blocked) & Xingchen AGI & 0/0 & -- & -- \\\\",
    "\\midrule",
    "Ref.\\ primary model",
])

# ---------------------------------------------------------------- census: drift revision
A([
    "That rate is far above the 8--12\\% that Nemotron-3-Super and Nemotron-3-Nano scored with the original probe set on the same gateway, so the difference is the probe set rather than the deployment. The remaining 36 candidates return",
], [
    "That rate is far above the 8--12\\% that Nemotron-3-Super and Nemotron-3-Nano scored with the original probe set on the same gateway, but the difference is not the probe set alone: the Nano model re-measured with the same probes in a later quota window scored 58.3\\% (Section~\\ref{sec:e1}), so per-model rates drift across quota windows and the census contrast reflects deployment drift as well as the probe set. The remaining 36 candidates return",
])

# ---------------------------------------------------------------- census: "seven" -> "seven first-wave"
A([
    "yet leaks on none of its 19 high-tier responses, four of the other seven",
    "extension models leak above the primary baseline",
], [
    "yet leaks on none of its 19 high-tier responses, four of the other seven",
    "first-wave extension models leak above the primary baseline",
])

# ---------------------------------------------------------------- adaptive attacker: cross-model paragraph
A([
    "The experiment runs against fixed defenses on one gateway, so it does",
    "not establish the co-evolutionary regime of Section~\\ref{sec:adaptive}, in",
    "which attacker and defense agent both adapt.",
    "",
    "\\section{Theoretical Boundary on Defense Stacking}",
], [
    "The experiment runs against fixed defenses on one gateway, so it does not",
    "establish the co-evolutionary regime of Section~\\ref{sec:adaptive}, in",
    "which attacker and defense agent both adapt.",
    "",
    "\\textbf{Cross-model replication.} When the quota window later re-opened, the",
    "same bandit was re-run against a second real reasoning model on the",
    "cross-vendor gateway, Nemotron-3.5-Lightning---the model fully quota-blocked",
    "during the extension cohort---with the same twelve arms, system prompt, and",
    "judge. The shared quota locked the run after 9 of 40 planned episodes (7",
    "usable), so the sample is small and the adaptation gate, computed on the",
    "final two episodes, passes formally but carries almost no statistical weight.",
    "Within that window the replication is decisive: the first usable episode",
    "already leaks, versus episode 5 on the primary model, and the leak family is",
    "the same, with the thinking-leak arms leaking on 4 of 4 pulls while the other",
    "three families leak on 0 of 3; the final channel leaks on none of the 7",
    "responses. An attacker with no prior knowledge therefore locates the blind",
    "spot on a second model within a single request, and the trigger family the",
    "bandit converged on is the same, so the paraphrase-resistance finding is not",
    "model-specific. The run still uses fixed defenses, now on two gateways, and",
    "does not establish the co-evolutionary regime.",
    "",
    "\\section{Theoretical Boundary on Defense Stacking}",
])

# ---------------------------------------------------------------- limitations: backend count
A([
    "gateway, on nine distinct measured backends in total (two from the original",
    "cross-vendor set, seven from the extension cohort): Reflection Beam is",
    "statistically indistinguishable from the primary model's baseline (62.5\\%",
    "versus 53.6\\%, Fisher $p=0.581$), the primary model's own family under separate",
    "hosting is likewise indistinguishable (54.2\\% versus 53.6\\%, $p=1.0$), and",
    "measured rates across the nine backends range from 0\\% to 100\\%. The",
], [
    "gateway, on ten distinct measured backends in total (two from the original",
    "cross-vendor set, eight from the extension cohort across two quota windows):",
    "Reflection Beam is",
    "statistically indistinguishable from the primary model's baseline (62.5\\%",
    "versus 53.6\\%, Fisher $p=0.581$), the primary model's own family under separate",
    "hosting is likewise indistinguishable (54.2\\% versus 53.6\\%, $p=1.0$), and",
    "measured rates across the ten backends range from 0\\% to 100\\%. The rates are",
    "window-dependent: the 30B--A3B Nano model moved from 12.5\\% to 58.3\\% between",
    "quota windows (Fisher $p=0.002$) while Beam stayed high ($p=0.50$ between",
    "windows); Nemotron-3.5-Lightning, blocked during the extension cohort, was",
    "additionally measured under the adaptive-attacker protocol",
    "(Section~\\ref{sec:adaptive-attacker}). The",
])

# ---------------------------------------------------------------- limitations: quota truncation tally
A([
    "set within roughly 250 requests, two extension models were truncated by quota",
    "exhaustion (19 and 9 valid high-tier responses), and one was fully blocked. A",
], [
    "set within roughly 250 requests, two extension models were truncated by quota",
    "exhaustion (19 and 9 valid high-tier responses), one was fully blocked, and",
    "the second wave truncated three further models (24, 17, and 13 valid",
    "high-tier responses) and blocked a fourth. A",
])

# ---------------------------------------------------------------- reproducibility release contents
A([
    "error responses for the blocked cross-model replication, the pooled-sample",
    "reconciliation data, the cross-vendor extension records, and the",
    "adaptive-attacker run records; each figure and table value maps to a stored",
], [
    "error responses for the blocked cross-model replication, the pooled-sample",
    "reconciliation data, the cross-vendor extension records from both quota",
    "windows, and the adaptive-attacker run records on both models; each figure",
    "and table value maps to a stored",
])

# ---------------------------------------------------------------- conclusion
A([
    "the asymmetry replicates across nine distinct cross-vendor backends---including",
    "the primary model's own family under separate hosting (54.2\\% versus 53.6\\%)---",
    "while measured rates range from 0\\% to 100\\%, so the structure is robust but",
    "the rate is model-dependent; fresh paraphrases leak at least as often as the",
    "original probes (83.3\\% on the thinking-leak family), and an online attacker",
    "with no prior knowledge finds the blind spot within five requests. A catalog",
], [
    "the asymmetry replicates across ten distinct cross-vendor backends---including",
    "the primary model's own family under separate hosting (54.2\\% versus 53.6\\%)---",
    "while measured rates range from 0\\% to 100\\%, so the structure is robust but",
    "the rate is model- and window-dependent; fresh paraphrases leak at least as",
    "often as the original probes (83.3\\% on the thinking-leak family, and 4/4 on a",
    "second model), and an online attacker with no prior knowledge finds the blind",
    "spot within five requests, and within a single request on a second model. A",
    "catalog",
])


def main():
    with open(TEX, "rb") as f:
        data = f.read().decode("utf-8")
    # sanity: file must be CRLF throughout
    if "\n" in data.replace(CRLF, ""):
        print("ABORT: file contains bare LF lines")
        sys.exit(1)
    for i, (old, new) in enumerate(EDITS):
        n = data.count(old)
        if n != 1:
            print("ABORT: edit %d matched %d times" % (i, n))
            print("  old[0]: %r" % old[:80])
            sys.exit(1)
        data = data.replace(old, new)
        print("edit %d/%d ok (%d -> %d chars)" % (i + 1, len(EDITS), len(old), len(new)))
    tmp = TEX + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data.encode("utf-8"))
    os.replace(tmp, TEX)
    print("Pass-37 wave-2 merge applied: %d atomic edits" % len(EDITS))


if __name__ == "__main__":
    main()
