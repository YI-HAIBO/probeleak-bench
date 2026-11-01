# -*- coding: utf-8 -*-
"""Pass-11 cleanup: fifth-round review fixes for p3_tifs.tex.
Verify-then-apply: every OLD must match exactly BEFORE any write.
"""
import io, os, sys

P = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'

PAIRS = []

def add(old, new):
    PAIRS.append((old, new))

# ================= A. hard text errors =================
# A1 duplicated "The gateway and"
add("extraction and thinking leak were essentially never blocked). The gateway and\n"
    "the gateway and the model's own refusals cover different requests and are\n"
    "individually insufficient:\n"
    "neither covers the reasoning channel.",
    "extraction and thinking leak were essentially never blocked). The gateway and\n"
    "the model's own refusals cover different requests and are individually\n"
    "insufficient: neither covers the reasoning channel.")

# A2 dangling "1.19x displacement coefficient" (not defined in sec:output;
#    30.33/25.5 is the final-channel inflation of the simulated sweep; the
#    numeric form also collided with the +1.19 pp E6 rate difference)
add("the 1.19$\\times$ displacement coefficient (the simulated filter sweep in\n"
    "Section~\\ref{sec:output}) has no\n"
    "real-model counterpart.",
    "in the simulated sweep the final-answer rate rises from 25.5\\% to 30.33\\%\n"
    "(Section~\\ref{sec:output}), and that inflation has no real-model counterpart.")

# A3a CoT first use expands the abbreviation (was expanded only at L223)
add("\\item Evidence of a \\emph{CoT-native blind spot} on real models",
    "\\item Evidence of a \\emph{chain-of-thought (CoT)-native blind spot} on real\n"
    "      models")

# A3b drop the now-redundant second expansion and the awkward triple
add("responses) and \\emph{through which channel} (CoT, chain-of-thought, only, with the final-answer",
    "responses) and \\emph{through which channel} (CoT only, with the final-answer")

# ================= B. terminology / concept clarifications =================
# B1 third world model term (real-calibrated / calibrated-model) defined once
add("\\texttt{dots3-note-prev} per our disclosure agreement. All real experiments use",
    "\\texttt{dots3-note-prev} per our disclosure agreement. A third term,\n"
    "\\emph{real-calibrated} (also \\emph{calibrated-model}), denotes analyses whose\n"
    "parameters are anchored to the real measurements but whose request streams and\n"
    "aggregations remain simulated (Sections~\\ref{sec:corr} and~\\ref{sec:adaptive}).\n"
    "All real experiments use")

# B2 g1--g4 are numbered per experiment (not a fixed global set)
add("g1--g4 are per-experiment checks (e.g., g2 asserts that the literal scrubber\n"
    "reduces the target metric by at least a threshold).",
    "g1--g4 are numbered per experiment, and each assertion is stated where its\n"
    "result is reported (for example, g2 of the E10 stress test asserts that the\n"
    "literal scrubber reduces the target metric by at least a threshold).")

# B3 high-tier probe classes vs probe-responses
add("a 4-probe high tier carrying all\n"
    "15 observed CoT leaks (15 of 28 high-tier probe-responses across the three samples) and a 31-probe tier with none.",
    "a 4-probe high tier carrying all\n"
    "15 observed CoT leaks (15 of 28 high-tier probe-responses: the four classes\n"
    "re-run across the three samples) and a 31-probe tier with none.")

# B4 Fig 1 caption: input-side rewriting acts BEFORE the model
add("Output-side filtering (D30,\n"
    "parameterized by strictness $s$), literal redaction ($\\tau$), input-side rewriting coverage $c\\in[0,1]$, and the\n"
    "consumer's channel visibility $p_{cot}\\in[0,1]$ act after generation.}",
    "Output-side filtering (D30,\n"
    "parameterized by strictness $s$), literal redaction ($\\tau$), and the consumer's\n"
    "channel visibility $p_{cot}\\in[0,1]$ act after generation; input-side rewriting\n"
    "(coverage $c\\in[0,1]$) acts on the request before the model.}")

# B5 CI expanded at first use (abstract)
add("leaks at 14.55\\% (95\\%\n"
    "CI [10.83, 19.27]) while the final-answer channel shows none",
    "leaks at 14.55\\% (95\\%\n"
    "confidence interval (CI) [10.83, 19.27]) while the final-answer channel shows none")

# ================= C. figures / tables =================
# C1 Table II footnote split into two paragraphs
add("{\\raggedright\\footnotesize Wilson 95\\% intervals: diverse CoT [10.83, 19.27], repetition CoT [96.40, 100.00], grand-pool CoT [33.47, 43.32]; grand-pool final [14.97, 22.87]. The repetition cohort re-runs probes already known to leak and is therefore selection-conditioned, not an estimate of the marginal rate. All 69 final-channel hits fall in that cohort: none occurs in the 0 of 268 fresh-probe result reported as the headline, so the two numbers are not in conflict. The ``Experiments'' column counts the campaigns contributing to each cohort (5 per cohort, 10 in total).\\par}",
    "{\\raggedright\\footnotesize Wilson 95\\% intervals: diverse CoT [10.83, 19.27], repetition CoT [96.40, 100.00], grand-pool CoT [33.47, 43.32]; grand-pool final [14.97, 22.87]. The ``Experiments'' column counts the campaigns contributing to each cohort (5 per cohort, 10 in total).\\par}\n"
    "{\\raggedright\\footnotesize The repetition cohort re-runs probes already known to leak and is therefore selection-conditioned, not an estimate of the marginal rate. All 69 final-channel hits fall in that cohort: none occurs in the 0 of 268 fresh-probe result reported as the headline, so the two numbers are not in conflict.\\par}")

# C2a Table VI: tau Final-only gains a unit
add("$\\tau$ literal scrub & channel & 8/8 & 100\\% & 0 \\\\",
    "$\\tau$ literal scrub & channel & 8/8 & 100\\% & 0\\% \\\\")

# C2b Table VI: D30 Final-only unified to the same relative-reduction unit
#     (JSON e2_baseline_comparison_v1.json results.metric_blindness_W_S.per_config
#      .C4_d30_s10.final_only_reduction_pct = -21.05; final_channel_change_pp = 5.41)
add("D30 suppression & channel & 8/8 & 25.5\\% & $-5.4$pp \\\\",
    "D30 suppression & channel & 8/8 & 25.5\\% & $-21.1$\\% \\\\")

# C2c Table VI: C0 has no mechanism, so Reach is undefined
add("No defense (C0) & -- & 8/8 & 0\\% & 0\\% \\\\",
    "No defense (C0) & -- & -- & 0\\% & 0\\% \\\\")

# C2d Table VI footnote rewritten
add("{\\raggedright\\footnotesize `Reach' is the number of the eight real CoT-only leak\n"
    "events that the mechanism can observe or rewrite (8 of 8 = all, 0 of 8 =\n"
    "none). `Union' is the reduction in union leak rate and `Final-only' the\n"
    "reduction measured on the final answer alone; `--' means the quantity is\n"
    "undefined for that mechanism (pp = percentage points). Scored on the eight real CoT-only leak events and in the simulated world; a final-only metric overstates PCC-SQL's benefit by 4.06$\\times$ (the final-only\n"
    "reduction is 100\\% while the union reduction is 24.6\\%).\\par}",
    "{\\raggedright\\footnotesize `Reach' is the number of the eight real CoT-only leak\n"
    "events that the mechanism can observe or rewrite (8 of 8 = all, 0 of 8 =\n"
    "none); no mechanism exists for C0, so its reach is undefined. `Union' and\n"
    "`Final-only' are the relative reductions in the union and final-answer leak\n"
    "rates; `--' means the quantity is not scored (the real-model arm measured no\n"
    "reduction for schema hiding, Section~\\ref{sec:baselines}). The $\\tau$ row is the\n"
    "real post-hoc measurement; the other rows are simulated-world scores. The D30\n"
    "entry is negative because displacement raises the final rate by 5.4pp; a\n"
    "final-only metric overstates PCC-SQL's benefit by 4.06$\\times$ (100\\% versus\n"
    "24.6\\% on the union).\\par}")

# C3 Fig 4 caption: self-contained CI pointer + coverage note
#     (verified in p3_figures_gen.py: both bar series cover the same five modes)
add("real bars from the B3 sample ($N=112$ effective\n"
    "attacks; Wilson 95\\% intervals are in Fig.~\\ref{fig:e6ci}).}",
    "real bars from the B3 sample ($N=112$ effective\n"
    "attacks; Wilson 95\\% intervals for these rates are in Fig.~\\ref{fig:e6ci}); both\n"
    "bar series cover the same five attack classes.}")

# ================= D. references =================
# D1 peng2025: ACE is an EWA Publishing journal (ISSN 2755-2721), verified;
#     the ACM ICEIT proceedings note was factually wrong and self-contradictory
add("ISSN 2755-2721 (conference paper; the ACE series is the ACM ICEIT proceedings).",
    "ISSN 2755-2721 (EWA Publishing).")

# D2 OWASP expanded at first (only) use
add("System prompts are now recognized as a top risk by OWASP~\\cite{owasp2025},",
    "System prompts are now recognized as a top risk by the Open Worldwide\n"
    "Application Security Project (OWASP)~\\cite{owasp2025},")

# D3 SIGMOD expanded in the rbac2026 note
add("(we cite the preprint version; to appear at ACM SIGMOD 2027).",
    "(we cite the preprint version; to appear at the ACM International Conference on Management of Data (SIGMOD), 2027).")

# ================= E. residual AI-tone =================
add("inverting the deployment recommendation. We exhibit a concrete case: a",
    "inverting the deployment recommendation. We give a concrete case: a")

add("model-specific limitation is reported honestly: M-C exposes both reasoning and",
    "model-specific limitation applies: M-C exposes both reasoning and")

# ================= F. self-deprecation consolidation =================
# F1 disclosure paragraph: drop the third repetition of "cannot be independently
#     reproduced" (already stated in Limitations and Reproducibility)
add("disclose that the primary real model is identified only under a non-disclosure\n"
    "agreement with the operator, that the gateway credential is not released, and\n"
    "that the findings therefore cannot be independently reproduced against that\n"
    "specific endpoint; the released artifacts permit reproduction of every derived\n"
    "number and of all simulation results.",
    "disclose that the primary real model is identified only under a non-disclosure\n"
    "agreement with the operator and that the gateway credential is not released\n"
    "(Section~\\ref{sec:limitations}); the released artifacts permit reproduction of\n"
    "every derived number and of all simulation results.")

# F2 reproducibility paragraph: drop the honeypot/PII sentence duplicated verbatim
#     two paragraphs later in Responsible disclosure
add("possible. Only synthetic honeypot credentials are used (all prefixed\n"
    "\\texttt{FAKE\\_}) in a dedicated test database; no production secret and no\n"
    "personally identifiable data appear in any artifact.",
    "possible.")


def main():
    t = io.open(P, encoding='utf-8').read()
    fails = []
    for i, (old, new) in enumerate(PAIRS):
        if old not in t:
            fails.append(i)
    if fails:
        for i in fails:
            print("FAIL pair", i)
            print("  OLD:", repr(PAIRS[i][0][:140]))
        print("ABORT: %d pair(s) did not match; no file written" % len(fails))
        sys.exit(1)
    for i, (old, new) in enumerate(PAIRS):
        t = t.replace(old, new, 1)
    tmp = P + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        f.write(t)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, P)
    print("OK: %d pairs applied" % len(PAIRS))
    print("bytes", len(t.encode('utf-8')), "lines", t.count('\n') + 1)


if __name__ == '__main__':
    main()
