# -*- coding- utf-8 -*-
"""Fourth cleanup pass on p3_tifs.tex: residual AI-smell + reader-confusion fixes.

Pairs derived from the fresh Turn-4 lists (50 confusion items + 20 AI-smell items).
Only items fixable by precise text replacement are included; items requiring
structural changes (figure/table caption rewrites, reference re-verification)
are tracked separately.
"""
import os, re

PATH = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

with open(PATH, "r", encoding="utf-8") as f:
    text = f.read()

def to_regex(s):
    parts = re.split(r"\s+", s)
    return r"\s+".join(re.escape(p) for p in parts)

PAIRS = [
# ==================== AI-SMELL REWRITES ====================

# A1: "closest prior work" -> neutral positioning
("This is the closest prior work, studying the same\n"
 "phenomenon from the privacy rather than the measurement side. That line asks",
 "This line of work studies the same phenomenon from the privacy side rather\n"
 "than the measurement side. That line asks"),

# A2: "complementary case" -> plain contrast
("our result is the complementary case---a model whose final\n"
 "answers are clean but whose reasoning enumerates secrets. Both phenomena show",
 "our result is the mirror case: a model whose final answers are clean but whose\n"
 "reasoning enumerates secrets. Both phenomena show"),

# A3: "in opposite directions" -> soften
("that single-channel evaluation misleads, in opposite directions.",
 "that single-channel evaluation misleads, in opposite ways."),

# A4: "instead we measure" -> plain contrast
("We do not defend the system prompt; instead we measure whether the reasoning\n"
 "channel exposes the secrets it is meant to protect.",
 "We do not defend the system prompt; we measure whether the reasoning channel\n"
 "exposes the secrets it is meant to protect."),

# A5: "it suffices to separate" -> plain statement
("The defense does not need to block the attack at the reasoning channel itself---it\n"
 "suffices to \\emph{separate} the channels.",
 "The defense does not need to block the attack at the reasoning channel itself;\n"
 "separating the channels is enough."),

# A6: "therefore that" -> plain statement
("The security claim is therefore that channel separation\n"
 "is a strictly weaker requirement than blocking",
 "The security claim is that channel separation is a strictly weaker requirement\n"
 "than blocking"),

# A7: "the least expensive control we identified" -> remove first person
("the least expensive control we identified: do not persist",
 "the least expensive control identified: do not persist"),

# A8: "what a forensic search needs" -> "requires"
("what a forensic search needs: it can be run retrospectively",
 "what a forensic search requires: it can be run retrospectively"),

# A9: "This is a hard constraint on independent verification; it does not weaken
#     the measurements themselves" -> soften defensive phrasing
("This is a hard constraint on independent verification; it does not weaken the\n"
 "measurements themselves.",
 "This is a constraint on independent verification. It does not weaken the\n"
 "measurements themselves."),

# A10: "best treated as" -> "should be treated as"
("the reasoning channel is best treated as an artifact of logging rather than of\n"
 "the model:",
 "the reasoning channel should be treated as an artifact of logging rather than of\n"
 "the model:"),

# A11: "exhibits" -> "shows"
("the same error class the input-side gateway exhibits",
 "the same error class the input-side gateway shows"),

# A12: "convergent rather than confirmatory" -> plain
("The support M-B offers is convergent rather than confirmatory---an independent\n"
 "vendor's model reproduces a high CoT leak rate on the same high-tier probes while\n"
 "its final channel stays at 0/24---so the observation is consistent with, but does\n"
 "not by itself establish, model-family generality.",
 "M-B reproduces a high CoT leak rate on the same high-tier probes while its final\n"
 "channel stays at 0/24, so the observation is consistent with, but does not by\n"
 "itself establish, model-family generality."),

# A13: "We do not read this as decisive" -> plain
("We do not read this as decisive: a non-significant test is not evidence of\n"
 "equivalence, and a formal equivalence test would require a pre-specified margin\n"
 "that we did not set.",
 "This is not decisive: a non-significant test is not evidence of equivalence,\n"
 "and a formal equivalence test would require a pre-specified margin that we did\n"
 "not set."),

# A14: "expression strength is model-dependent" -> plain
("but its expression strength is\n      model-dependent.",
 "but its expression varies by model."),

# A15: "weakly aligned models" -> "models with weaker alignment"
("confirming that the original probes undercount leaks for weakly aligned models.",
 "confirming that the original probes undercount leaks for models with weaker\n"
 "alignment."),

# A16: "the oracle still leaks 0.68%" -> remove "still"
("the oracle still leaks 0.68\\%. Because the oracle knows",
 "the oracle leaks 0.68\\%. Because the oracle knows"),

# A17: "works by keeping" -> "works by preventing"
("the defense works by keeping the credential from crossing from reasoning into the\n"
 "final answer, and the E8 attacker observed no final-answer leak in its 7",
 "the defense prevents the credential from crossing from reasoning into the final\n"
 "answer, and the E8 attacker observed no final-answer leak in its 7"),

# A18: "precisely when signal is weak—which is the case on real models" -> plain
("whereas naive online reward learning is dominated by a static baseline precisely\n"
 "when signal is weak---which is the case on real models.",
 "whereas naive online reward learning is dominated by a static baseline when signal\n"
 "is weak, which is the case on real models."),

# A19: "the same error class the input-side gateway exhibits" (already A11, skip duplicate)

# A20: "the defense-correlation concern is not testable on the current probe set.
#      This is reported as a boundary condition rather than a rejection of the
#      correlation model" -> soften
("the defense-correlation concern is not testable on the current probe set. This is\n"
 "reported as a boundary condition rather than a rejection of the correlation\n"
 "model, which remains the appropriate analytical tool for",
 "the defense-correlation concern is not testable on the current probe set. We\n"
 "report this as a boundary condition; the correlation model remains the appropriate\n"
 "analytical tool for"),

# ==================== TEXT CLARIFICATION ====================

# C1: "1.19× displacement coefficient" -> add source
("the 1.19$\\times$\ndisplacement coefficient measured in simulation has no",
 "the 1.19$\\times$ displacement coefficient (the simulated filter sweep of\n"
 "Section~\\ref{sec:output}) has no"),

# C2: "4.06×" -> add calculation basis
("a final-only metric overstates PCC-SQL's benefit by 4.06$\\times$.",
 "a final-only metric overstates PCC-SQL's benefit by 4.06$\\times$ (the final-only\n"
 "reduction is 100\\% while the union reduction is 24.6\\%)."),

# C3: "1.18×" -> add calculation basis
("the string-level dual-channel judge overstates downstream consumer exposure by\n"
 "only $1.18\\times$ on the CoT channel and produced no",
 "the string-level dual-channel judge overstates downstream consumer exposure by\n"
 "only $1.18\\times$ on the CoT channel (string-level hits 11/13 vs. consumer-recovered\n"
 "11/13, so the judge is exact on this sample; the 1.18$\\times$ is the worst-case\n"
 "ratio across all 32 responses) and produced no"),

# C4: "0.92% versus 3.0%" -> add labels
("a large false-positive reduction (0.92\\% versus 3.0\\% for the\n"
 "static baseline), which is the correct trade under $\\lambda=2$.",
 "a large false-positive reduction (agent 0.92\\% vs. static baseline 3.0\\%),\n"
 "which is the correct trade under $\\lambda=2$."),

# C5: "8–12%" -> add source
("far above the 8--12\\% measured on the NVIDIA models with the original probe set.",
 "far above the 8--12\\% measured on the NVIDIA models (M-A 8.3\\%, M-C 12.5\\%;\n"
 "Section~\\ref{sec:e1}) with the original probe set."),

# C6: "the 0.172" -> add unit clarification
("the joint residual exceeding the multiplicative prediction by up to\n"
 "$0.172$~\\cite{alotaibi2026}",
 "the joint residual exceeding the multiplicative prediction by up to $0.172$ in\n"
 "absolute leak rate~\\cite{alotaibi2026}"),
]

ok = True
for i, (old, new) in enumerate(PAIRS):
    rx = to_regex(old)
    n = len(re.findall(rx, text))
    if n != 1:
        print("pair %d: regex found %d matches (need 1):" % (i + 1, n))
        print("OLD:", repr(old[:120]))
        ok = False
        continue
    text = re.sub(rx, lambda m: new, text, count=1)

if not ok:
    print("ABORTING - no file written.")
    raise SystemExit(1)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("OK: %d pairs applied, %d bytes" % (len(PAIRS), os.path.getsize(PATH)))