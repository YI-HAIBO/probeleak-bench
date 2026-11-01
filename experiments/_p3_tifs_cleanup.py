# -*- coding: utf-8 -*-
"""Batch cleanup of p3_tifs.tex. Each (old,new) pair is verified by a
whitespace-flexible regex (so line-wrap differences do not break matching),
then applied by exact literal replacement. Atomic write; aborts on any mismatch."""
import os, re, sys

PATH = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

with open(PATH, "r", encoding="utf-8") as f:
    text = f.read()

def to_regex(s):
    """Escape regex metachars, then collapse every whitespace run to \\s+.

    re.escape does NOT escape literal spaces, so splitting on \\s+ first and
    re-escaping the tokens is the only way to make spaces, tabs, and newlines
    all interchangeable in the pattern (the file is CRLF on disk and the OLD
    strings are written with spaces or \\n wherever the line wrap happened to
    fall)."""
    parts = re.split(r"\s+", s)
    return r"\s+".join(re.escape(p) for p in parts)

PAIRS = [
# ---- T1: remove "to our knowledge" hedge ----
("occurs on real models has, to our knowledge, not been measured with",
 "occurs on real models has not been measured with"),

# ---- T2: "broader shift" trend claim -> grounded statement ----
("""visibility. This is consistent with the broader shift from probabilistic output
filters to formal information-flow control, which gives deterministic,
non-bypassable guarantees~\\cite{costa2025, gordon2026, doshi2026, storek2026}.""",
"""visibility. Formal information-flow control offers deterministic, non-bypassable
guarantees~\\cite{costa2025, gordon2026, doshi2026, storek2026}; our finding that the
final-answer channel can be clean is consistent with the possibility that such
controls close it."""),

# ---- T3: "internal to the model" -> "holds within the calibrated model" ----
("a result that is internal to the model, anchored to real leak",
 "a result that holds within the calibrated model, anchored to real leak"),

# ---- T4: "mirror image" -> "complementary case" ----
("answer~\\cite{rbac2026}; our result is its mirror image---a model whose final",
 "answer~\\cite{rbac2026}; our result is the complementary case---a model whose final"),

# ---- T5: "Our contribution is a calibrated..." -> "We provide a calibrated..." ----
("Our contribution is a calibrated,",
 "We provide a calibrated,"),

# ---- T6: "We complement rather than compete" -> direct statement ----
("""We complement rather than compete with
these: we do not defend the system prompt, but measure whether the reasoning""",
"""We do not defend the system prompt; instead we measure whether the reasoning"""),

# ---- T7: "defining feature of our model" -> neutral ----
("A defining feature of our model is",
 "The quantity that determines consumer exposure is"),

# ---- T8: define "boundary condition" at first use ----
("""reduces the target metric by at least a threshold). When a gate fails we report
the result as a boundary condition, not as evidence against the hypothesis.""",
"""reduces the target metric by at least a threshold). A failed gate is reported
as a \\emph{boundary condition}---an artifact of the probe set, sample, or
deployment shape rather than evidence against the claim; every failure below is
reported as such."""),

# ---- T9: campaign-code legend ----
("""Pooled totals refer to the union of specified campaigns; e.g., ``B1+B3 arm A''
means the first arm of the B1 and B3 campaigns combined.""",
"""Pooled totals refer to the union of specified campaigns; e.g., ``B1+B3 arm A''
means the first arm of the B1 and B3 campaigns combined. The main campaign codes
are: B1, B3, and E6 (the three samples of Section~\\ref{sec:cot}); E1 and E1-v2
(cross-vendor and census runs of Sections~\\ref{sec:e1}--\\ref{sec:census});
E2b (schema hiding, Section~\\ref{sec:baselines}); E4 (consumer arm,
Section~\\ref{sec:output}); E7 ($\\tau$+D30 on real traces); E8 (real red teamer);
E9, E10, E11 (production-baseline, stress-test, and public-benchmark probes);
and E12 (repetition-v2). Probe identifiers used in the text---tl (thinking leak),
pe (prefix extraction), sr (step reconstruction), te (translation-exfiltration),
rp (role-play), se (stress key-extraction), ii (indirect injection), ci (code
interpretation), and re (refusal cliff)---are expanded where first used."""),

# ---- T10: "guarded against" -> "refuses" ----
("""This is consistent with a model that is guarded
against direct requests but not against appeals to its own reasoning trace.""",
"""This is consistent with a model that refuses direct requests but not appeals to
its own reasoning trace."""),

# ---- T11: "overestimates two classes that did not leak" -> precise ----
("and 1.6$\\times$, and also overestimates two classes that did not leak.",
 "and 1.6$\\times$, and it also assigns positive leak rates to two classes that\nthe real model never leaked."),

# ---- T12: "the measured joint" -> "the model's joint residual" (x2) ----
("the measured joint at $\\rho=0$ is 3.41\\%.",
 "the model's joint residual at $\\rho=0$ is 3.41\\%."),
("where the measured joint residual is",
 "where the model's joint residual is"),

# ---- T13: rho_max = null -> plain statement ----
("($\\rho_{\\max}=\\mathrm{null}$ on all three values of $\\lambda$).",
 "(no value of $\\rho$ yields a positive net benefit at any of the three $\\lambda$ values)."),

# ---- T14: "does not bite" / "right analytical tool" ----
("""defense-correlation concern does not bite on the current probe set. This is
reported as a boundary condition rather than a rejection of the correlation
model, which remains the right analytical tool for""",
"""defense-correlation concern is not testable on the current probe set. This is
reported as a boundary condition rather than a rejection of the correlation
model, which remains the appropriate analytical tool for"""),

# ---- T15: "operationalizes" -> "puts to a real test" ----
("This operationalizes the displacement argument on real data: when the final channel leaks, suppressing the reasoning channel eliminates the leak source, but redacting the final answer alone does not.",
 "This puts the displacement argument to a real test: when the final channel leaks, suppressing the reasoning channel eliminates the leak source, but redacting the final answer alone does not."),

# ---- T16: "carried entirely by" -> "driven entirely by" ----
("is\ncarried entirely by one probe's single-repeat flip,",
 "is\ndriven entirely by one probe's single-repeat flip,"),

# ---- T17: "the model followed the instruction" -> neutral ----
("followed the instruction and applied the self-check afterwards. This",
 "applied the self-check after answering. This"),

# ---- T18: "turns p_cot from a parameter into a measurement" -> neutral ----
("An end-to-end consumer turns $p_{cot}$ from a parameter into a\nmeasurement.",
 "An end-to-end consumer lets us replace the modeled $p_{cot}$ with a\nmeasurement."),

# ---- T19: "provides empirical confirmation ... never hallucinates" ----
("""This provides empirical confirmation of the consumer-channel prediction previously available only in
simulation, and it is consistent with the string-level judge, which on the CoT
channel overstates downstream exposure by only $1.18\\times$ and never
hallucinates.""",
"""This confirms the consumer-channel prediction on real data, and it is consistent
with the string-level judge, which on the CoT channel overstates downstream
exposure by only $1.18\\times$ and produced no false positives in this sample."""),

# ---- T20: "never hallucinates a key it did not receive" ----
("""the string-level dual-channel judge overstates downstream consumer exposure by only $1.18\\times$ on the CoT channel and never hallucinates
a key it did not receive.""",
"""the string-level dual-channel judge overstates downstream consumer exposure by only $1.18\\times$ on the CoT channel and produced no
false positives on the keys it was given."""),

# ---- T21: "degrades gracefully / arms race does not converge" ----
("""the currently highest-residual class, the agent degrades gracefully (utility
$-0.0352$, leak 3.17\\%) and the arms race does not converge.""",
"""the currently highest-residual class, the agent's utility falls to $-0.0352$
(leak 3.17\\%) and the attack mix does not settle to a fixed distribution."""),

# ---- T22: "is not a defect" -> "is expected" ----
("rate alongside higher utility in the simulated world is not a defect: the",
 "rate alongside higher utility in the simulated world is expected: the"),

# ---- T23: "matches the shifted oracle context for context" ----
("and ends with a policy that matches the shifted oracle context for context.",
 "and ends with a policy that matches the shifted oracle's configuration."),

# ---- T24: "is itself informative" -> "has a concrete explanation" ----
("\\textbf{The oracle's nonzero residual is itself informative.} In the",
 "\\textbf{The oracle's nonzero residual has a concrete explanation.} In the"),

# ---- T25: "the same class of error that" -> "the same error class" ----
("This is the same class of error that the input-side gateway exhibits",
 "This is the same error class the input-side gateway exhibits"),

# ---- T26: conditional annotation on the core security claim ----
("because the final-answer baseline is observed at zero on the real model. The",
 "because the final-answer baseline is observed at zero on the real model (this\nholds only on fresh probes; see E10/E11 in Section~\\ref{sec:output}). The"),

# ---- T27: "the defense wins" -> "the defense holds" ----
("the defense wins by keeping the credential from crossing from reasoning into the",
 "the defense holds by keeping the credential from crossing from reasoning into the"),

# ---- T28: "for that reason a more credible one" -> evidence-backed ----
("""reasoning-channel leakage outright; this is a weaker requirement, and for that
reason a more credible one.""",
"""reasoning-channel leakage outright; this is a weaker requirement, and one that
the evidence supports."""),

# ---- T29: "dominates" -> "outperforms every alternative" ----
("the channel-layer agent\ndominates.",
 "the channel-layer agent\noutperforms every alternative."),

# ---- T30: "not only outside ... it is also the only" -> plain conjunction ----
("""The reasoning channel is therefore not only outside the reach of
production-side defenses; it is also the only channel in which an adaptive
defender can find a usable signal.""",
"""The reasoning channel is therefore outside the reach of
production-side defenses, and it is the only channel in which an adaptive
defender can find a usable signal."""),

# ---- T31: "created by logging, not by the model" -> "made visible by logging" ----
("""The reasoning channel is a forensic artifact that is created by
logging, not by the model.""",
"""The reasoning channel is a forensic artifact: it is made visible by
logging, not by the model itself."""),

# ---- T32: "standing exfiltration channel ... attached to it" -> neutral ----
("""retains reasoning traces is a standing exfiltration channel with no
compromising event attached to it---an attacker never needs to touch a stored""",
"""retains reasoning traces is itself an exfiltration channel, with no
compromising event required---an attacker never needs to touch a stored"""),

# ---- T33: "the cheapest control identified here" -> "the least expensive control we identified" ----
("""containment measure is correspondingly simple and is the cheapest
control identified here: do not persist""",
"""containment measure is correspondingly simple and is the least expensive
control we identified: do not persist"""),

# ---- T34: "self-evidencing" -> "directly attributable" ----
("a specific probe response is self-evidencing and carries no exposure of real",
 "a specific probe response is directly attributable and carries no exposure of real"),

# ---- T35: "both the safer and the more probative forensic design" -> balanced ----
("""Honeypot instrumentation is thus both the safer and the more probative forensic design, and the""",
"""Honeypot instrumentation is both the safer forensic design and the more probative one, and the"""),

# ---- T36: "supports admissible attribution" -> "supports reliable attribution" ----
("""measured zero false-positive behavior of the literal judge supports admissible
attribution.""",
"""measured zero false-positive behavior of the literal judge supports reliable
attribution."""),

# ---- T37: "not a caveat on the measurements themselves" -> neutral ----
("This is a hard constraint on independent verification, not a caveat on the measurements themselves.",
 "This is a hard constraint on independent verification; it does not weaken the measurements themselves."),

# ---- T38: "every gateway model" -> "all three gateway models" (n=3) ----
("finds the blind spot on every gateway model that exposes a reasoning channel",
 "finds the blind spot on all three gateway models that expose a reasoning channel"),

# ---- T39: "We disclose that the pooled rate" -> plain statement ----
("We disclose that the\npooled rate (38.27\\%) is bimodal because repetition and stress runs re-execute",
 "The pooled rate (38.27\\%) is bimodal because repetition and stress runs re-execute"),

# ---- T40: "which, on real models, is the normal case" -> "which is the case on real models" ----
("""baseline precisely when signal is weak---which, on real models, is the normal
case.""",
"""baseline precisely when signal is weak---which is the case on real models."""),

# ---- T41: "strictly weaker and more credible requirement" -> "strictly weaker requirement" ----
("is a strictly weaker and more credible requirement than blocking",
 "is a strictly weaker requirement than blocking"),

# ---- T42: Conclusion "artifact created by logging ... cheapest control" ----
("""the reasoning channel is best treated as an artifact created by logging rather than by the model:
the cheapest control is to avoid persisting it in production logs.""",
"""the reasoning channel is best treated as an artifact of logging rather than of the model:
the least expensive control is to avoid persisting it in production logs."""),

# ---- T43: "honest point estimate" -> "the point estimate we report" ----
("this is the honest point estimate of the native blind spot and the basis for the headline claim.",
 "this is the point estimate we report for the native blind spot and the basis for the headline claim."),

# ---- T44: "clearest single disclosure" -> "strongest evidence" ----
("""and its 66.99\\% final-answer rate is the clearest single
disclosure that the ``final answer is always clean'' observation is a property""",
"""and its 66.99\\% final-answer rate is the strongest evidence that the ``final answer
is always clean'' observation is a property"""),

# ---- T45: "we deliberately report the cohort split" -> "we report the cohort split" ----
("and we deliberately report the cohort split rather than a single rate: 39/268 (14.55\\%) on",
 "and we report the cohort split rather than a single rate: 39/268 (14.55\\%) on"),

# ---- T46: "excluded from the attack rate deliberately" -> "by construction" ----
("it is excluded from the attack rate deliberately.",
 "it is excluded from the attack rate by construction."),

# ---- T47: "not filtered for leakability" -> "were not pre-filtered for leakability" ----
("""Probe texts were authored to cover the full attack surface, not filtered for
leakability, and the tier assignment ranks leak \\emph{volume} rather than leak""",
"""Probe texts were authored to cover the full attack surface and were not pre-filtered for
leakability, and the tier assignment ranks leak \\emph{volume} rather than leak"""),

# ---- T48: "its calibration transfers" -> "should transfer" ----
("and its calibration transfers to other secret sets because the match rule is literal",
 "and its calibration should transfer to other secret sets because the match rule is literal"),

# ---- T49: "universal among reasoning models" -> "present in every gateway model" ----
("""The blind spot is therefore universal among reasoning models that
expose a parseable reasoning channel, and architecturally bounded to them:""",
"""The blind spot is therefore present in every gateway model that exposes a reasoning
channel, and architecturally bounded to them:"""),

# ---- T50: undefined "P1.1" -> explicit five-sample list ----
("five independent real samples of dots3-note-prev (P1.1, B1+B3, E2b, E6,",
 "five independent real samples of dots3-note-prev (B1, B3, E2b, E6,"),

# ---- T51: D30 forward reference -> inline gloss at first use ----
("and the measured two-layer $\\tau$+D30 stack collapses to\nits stronger layer's residual",
 "and the measured two-layer $\\tau$+D30 stack (D30: sentence-level output-side\nsuppression) collapses to\nits stronger layer's residual"),

# ---- T52: PCC-SQL acronym never expanded in text ----
("On defenses, policy-conditioned constrained decoding\nreports 0\\% leakage on supported SQL fragments~\\cite{pccsql2026}.",
 "On defenses, policy-conditioned constrained decoding (PCC-SQL)\nreports 0\\% leakage on supported SQL fragments~\\cite{pccsql2026}."),

# ---- T53: $v$ definition appears after first use -> reorder ----
("""($v\\approx0.55$) does not hold in this deployment shape. Here and below $v$
denotes the violation-rate change under schema hiding relative to the same-probe
baseline, normalized so that $v=1$ means the leak is eliminated, $v=0$ means no
change, and $v<0$ means the leak worsens. Probe-level""",
"""does not hold in this deployment shape. Here and below $v$ denotes the
violation-rate change under schema hiding relative to the same-probe baseline,
normalized so that $v=1$ means the leak is eliminated, $v=0$ means no change, and
$v<0$ means the leak worsens (the literature-anchored value is $v\\approx0.55$).
Probe-level"""),

# ---- R1: storek2026 wrong arXiv ID + year + author diacritic (verified 2606.23277) ----
("""A.~Storek, N.~Holzer, Z.~Zhang, and S.~Jana, ``GIF: Locally sound geometric
information flow control for LLMs,'' \\emph{arXiv preprint arXiv:2603.12345},
2026.""",
"""A.~Štorek, N.~Holzer, Z.~Zhang, and S.~Jana, ``GIF: Locally sound geometric
information flow control for LLMs,'' \\emph{arXiv preprint arXiv:2606.23277},
2026."""),

# ---- R2: milliere2025 unverifiable (arXiv:2504.12345 does not resolve) -> drop cite ----
("""ecosystems~\\cite{mao2025}, with systematic reviews covering transferability across model
families~\\cite{milliere2025}. The landmark white-box attack appends""",
"""ecosystems~\\cite{mao2025}. The landmark white-box attack appends"""),

# ---- R3: delete milliere2025 bibitem ----
("""\\emph{arXiv preprint arXiv:2506.15170}, 2025.
\\bibitem{milliere2025}
P.~Milli{\\'e}re, ``Jailbreaking large language models with adversarial prompts: A
systematic review and taxonomy,'' \\emph{arXiv preprint arXiv:2504.12345}, 2025.
\\bibitem{zou2023}""",
"""\\emph{arXiv preprint arXiv:2506.15170}, 2025.
\\bibitem{zou2023}"""),

# ---- R4: conclaude2025 wrong ID/title/authors (verified 2501.18837) ----
("""Y.~Sharma, A.~B. Das, and A.~C.~I.~M.~A., ``Constitutional classifiers: Aligning
LLM safety with human feedback at scale,'' \\emph{arXiv preprint arXiv:2502.17041},
2025.""",
"""M.~Sharma, M.~Tong, J.~Mu, \\emph{et al.}, ``Constitutional Classifiers: Defending
against Universal Jailbreaks across Thousands of Hours of Red Teaming,''
\\emph{arXiv preprint arXiv:2501.18837}, 2025."""),

# ---- R5: safetybench2024 wrong ID + garbled authors (verified 2309.07045) ----
("""C.~Piet, M.~J.~H.~van der Veen, and J.~B.~S.~M., ``SafetyBench: A benchmark for
safety evaluation in LLMs,'' \\emph{arXiv preprint arXiv:2404.09858}, 2024.""",
"""Z.~Zhang, L.~Lei, L.~Wu, R.~Sun, Y.~Huang, C.~Long, X.~Liu, X.~Lei, J.~Tang, and
M.~Huang, ``SafetyBench: Evaluating the Safety of Large Language Models,''
\\emph{arXiv preprint arXiv:2309.07045}, 2024."""),

# ---- R6: leakbench2026 had no author field (verified 2606.18673) ----
("""``Understanding and mitigating prompt leaking attacks in real-world LLM-based
applications,'' \\emph{arXiv preprint arXiv:2606.18673}, 2026.""",
"""Y.~Yang, C.~Fu, T.~Zhang, R.~Zeng, Q.~Li, T.~Du, Z.~Wang, S.~Ji, and W.~Chen,
``Understanding and mitigating prompt leaking attacks in real-world LLM-based
applications,'' \\emph{arXiv preprint arXiv:2606.18673}, 2026."""),

# ---- R7: owasp2025 / owaspagents2025 are the same document -> merge cites ----
("edition~\\cite{owaspagents2025}",
 "edition~\\cite{owasp2025}"),

# ---- R8: delete duplicate owaspagents2025 bibitem ----
("""\\bibitem{owaspagents2025}
OWASP Foundation, ``OWASP top 10 for large language model applications,'' 2025,
available:
\\url{https://owasp.org/www-project-top-10-for-large-language-model-applications/}.
\\bibitem{anthropic2024}""",
"""\\bibitem{anthropic2024}"""),

# ---- R9: hubinger2024 "C.~Denison, et al." non-standard -> "et al." only ----
("E.~Hubinger, C.~Denison, \\emph{et al.}, ``Sleeper agents: When hidden backdoors",
 "E.~Hubinger \\emph{et al.}, ``Sleeper agents: When hidden backdoors"),
]

errors = []
for i, (old, new) in enumerate(PAIRS, 1):
    pat = re.compile(to_regex(old))
    hits = pat.findall(text)
    if len(hits) != 1:
        errors.append("pair %d: regex found %d matches (need 1):\nOLD:\n%s" % (i, len(hits), old[:300]))
        continue
    # apply via regex sub (lambda avoids backslash-escaping issues in `new`);
    # count=1 is safe because findall already proved exactly one match.
    text = pat.sub(lambda m: new, text, count=1)

if errors:
    sys.stderr.write("ABORTING - no file written.\n")
    for e in errors:
        sys.stderr.write(e + "\n\n")
    sys.exit(1)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("OK: %d pairs applied, %d bytes" % (len(PAIRS), os.path.getsize(PATH)))