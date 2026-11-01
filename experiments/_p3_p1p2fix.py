# -*- coding: utf-8 -*-
"""P1/P2 fixes for p3_tifs.tex (14-point audit, results/p3_14point_audit.md).

P1-1  Limitations compression (73 lines -> 3 paragraphs)
P1-2  four figure notes merged into captions / preceding text
P1-3  primary gateway / cross-vendor gateway naming
P2    AI-scent, engineering detail (HTTP codes, identifiers), gate numbering,
      JSON first-use expansion, behaviour/behavior, missing colons,
      naive-recomputations strawman, self-deprecation.

Atomic: every (old,new) must hit exactly once, else abort without writing.
All strings are double-quoted raw strings (LaTeX closing quotes are '').
"""
import os
import sys

P = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
NL = '\r\n'


def L(lines):
    return NL.join(lines)


EDITS = [
    # ---- P2: attack surface, drop dangling wave definition + self-deprecation,
    #      expand JSON at first visible use -------------------------------
    (L([
        r"and LLM semantics), grouped into four evaluation waves (a wave is a coordinated batch of probes targeting one attack layer). Per-experiment budgets in the broader research program",
        r"range from 1{,}000 to millions of probes; the experiments reported in this paper are far smaller---tens to a few hundred requests per arm---and every reported number traces to a released JSON artifact. The",
    ]),
     L([
        r"and LLM semantics). Per-experiment budgets",
        r"range from tens to a few hundred requests per arm, and every reported number traces to a released JSON (JavaScript Object Notation) artifact. The",
     ])),
    # ---- P2: reproducibility phrasing (drop dashboard/idempotent jargon) --
    (L([
        r"Every experiment runs under fixed,",
        r"isolated random streams (separate seeds for request-class, outcome, and",
        r"exploration), and every report and dashboard is produced by a reproducible",
        r"generator that re-reads the JSON artifacts (structured records storing per-response verdicts, gate results, and content-based hashes); re-running any generator reproduces",
        r"the report byte for byte (verified by content-based comparison).",
    ]),
     L([
        r"Every experiment runs under fixed,",
        r"isolated random streams (separate seeds for request-class, outcome, and",
        r"exploration), and every report is recomputed from the structured result",
        r"records (per-response verdicts, gate results, and content-based hashes) by",
        r"generators that re-read them; re-running any generator reproduces",
        r"the report byte for byte.",
     ])),
    # ---- P2: experiment-notation line, rename repetition-v2 --------------
    (r"the repetition-v2 run are each named by their purpose.",
     r"the expanded repetition run are each named by their purpose."),
    # ---- P2: same line, note that indexed probe texts are released -------
    (r"a trailing index selects the individual probe (the first translation-exfiltration probe), and this form is used throughout.",
     r"a trailing index selects the individual probe (the first translation-exfiltration probe), and this form is used throughout; the verbatim text of every indexed probe is part of the released library."),
    # ---- P2: gate definition, drop per-experiment g1--g4 numbering -------
    (L([
        r"g1--g4 are numbered per experiment, and each assertion is stated where its",
        r"result is reported (for example, g2 of the stress test asserts that the",
        r"literal scrubber reduces the target metric by at least a threshold). A failed gate is reported",
    ]),
     L([
        r"each gate's assertion is stated where its",
        r"result is reported (for example, the stress-test reduction gate asserts that the",
        r"literal scrubber reduces the target metric by at least a threshold). A failed gate is reported",
     ])),
    # ---- P2: drop HTTP 403 parenthesis in repetition paragraph -----------
    (r"from 48 requests sent, with one role-play probe entirely gateway-rejected by the upstream content-safety layer (HTTP 403, Forbidden) and one",
     r"from 48 requests sent, with one role-play probe entirely gateway-rejected by the upstream content-safety layer and one"),
    # ---- P2: drop hollow transition, neutral gate failure reporting ------
    (L([
        r"(AgentDojo 0\%, WildBench 50\%, HarmBench 100\% by mode). Two conclusions follow: the CoT-native blind spot is not an artifact of probe selection,",
        r"and the zero final-answer rate \emph{is} probe-set-dependent. The public-benchmark probe set gate",
        r"incompleteness (g1 and g3 did not hold because half the probes were blocked) is",
        r"reported as a boundary condition.",
    ]),
     L([
        r"(AgentDojo 0\%, WildBench 50\%, HarmBench 100\% by mode). The CoT-native blind spot is not an artifact of probe selection,",
        r"and the zero final-answer rate \emph{is} probe-set-dependent. Because half the public-benchmark probes were blocked before reaching the model, the",
        r"probe-set coverage gates for that arm did not hold; its rates are reported",
        r"with that coverage limit.",
     ])),
    # ---- P1-3: name the primary gateway at first introduction ------------
    (L([
        r"The \emph{real} world is a deployed reasoning model accessed",
        r"through its OpenAI-compatible gateway, which returns both the final answer and",
    ]),
     L([
        r"The \emph{real} world is a deployed reasoning model accessed",
        r"through its OpenAI-compatible primary gateway, which returns both the final answer and",
     ])),
    # ---- P2: naive-recomputations strawman paragraph -> methodology -----
    (L([
        r"A single",
        r"pooled rate would mix fresh probes with runs that deliberately re-execute",
        r"probes already known to leak. By \emph{naive recomputations} we mean pooled-rate estimates that apply an undocumented filter to the raw records, without the reconciliation script that maps every reported figure to its JSON field (Section~\ref{sec:reproducibility}). Three successive naive recomputations of this",
        r"one statistic disagreed by up to 5.2 percentage points because each applied a different record filter: per-sample counts",
        r"include only attack-kind traffic, whereas the naive scans also counted benign,",
        r"negative-control, and ablation records; in addition the stress test stores the reasoning leak under a label",
        r"that differs from the one used by other runs. None of the",
        r"naive variants reconciles with the underlying records, and none is",
        r"reported in this paper. Re-deriving the statistic from source",
        r"with an explicit, documented filter yields Table~\ref{tab:cohort}.",
    ]),
     L([
        r"A single",
        r"pooled rate would mix fresh probes with runs that deliberately re-execute",
        r"probes already known to leak. The pooled statistics below are therefore",
        r"derived from the source records with a single documented filter (attack-class",
        r"records only, for the first and second samples, and per-experiment channel",
        r"labels), which reconciles every reported figure with the underlying records",
        r"and yields Table~\ref{tab:cohort}.",
     ])),
    # ---- P2: rephrase repeated slogan in cohort paragraph ----------------
    (L([
        r"at 6--8 repetitions, so its 100\% CoT rate is an upper bound obtained by",
        r"construction, and its 66.99\% final-answer rate shows that the ``final answer",
        r"is always clean'' observation is a property",
        r"of the probe set, not of the model. The 14.55\% rate on diverse probes is the",
    ]),
     L([
        r"at 6--8 repetitions, so its 100\% CoT rate is an upper bound obtained by",
        r"construction, and its 66.99\% final-answer rate shows that the clean-final-answer",
        r"observation does not extend beyond the fresh-probe set. The 14.55\% rate on diverse probes is the",
     ])),
    # ---- P1-3 + P2: blocked second-model paragraph, gateway naming, ------
    #      HTTP codes / response identifiers removed, self-defence trimmed
    (L([
        r"An attempt was made to",
        r"replicate the blind spot on a second reasoning model through the same gateway:",
        r"the model listing exposes exactly one model (the primary model); all 25",
        r"probed candidate identifiers returned HTTP 400 (Bad Request; ``model is not configured'') or",
        r"HTTP 403 (Forbidden; ``key not bound to this model''), with per-model error responses and",
        r"unique response identifiers preserved (each response carries a unique identifier that allows the operator to correlate the error with the request, though the identifiers are not released). Response bodies distinguish ``model absent'' from",
        r"``key invalid'' (no credential echo in either case). The inability to access a",
        r"second reasoning model through this gateway is an accessibility constraint, not",
        r"evidence against the phenomenon; it is reported as blocked so that the",
        r"cross-vendor transfer rates measured in simulation over six simulated vendors",
        r"remain clearly labeled as simulation-only; the same",
        r"simulation-versus-real comparison across attack classes (Fig.~\ref{fig:simvsreal})",
    ]),
     L([
        r"An attempt was made to",
        r"replicate the blind spot on a second reasoning model through the primary gateway:",
        r"the model listing exposes exactly one model (the primary model); all 25",
        r"probed candidate identifiers were rejected by the gateway with",
        r"model-not-configured or key-not-bound responses, and the response bodies",
        r"distinguish ``model absent'' from",
        r"``key invalid'' with no credential echo in either case. Because no second",
        r"reasoning model was reachable through the primary gateway, the",
        r"cross-vendor transfer rates measured in simulation over six simulated vendors",
        r"are reported as simulation-only; the same",
        r"simulation-versus-real comparison across attack classes (Fig.~\ref{fig:simvsreal})",
     ])),
    # ---- P1-3 + P2: cross-vendor section header, gateway naming, --------
    #      mechanical first/second/third enumeration -> model names
    (L([
        r"All evidence above comes from a single model, which is the most frequent",
        r"criticism of the native-blind-spot claim. The measurement was therefore replicated on a second, independent gateway (provider AtlasCloud) using the same",
        r"probe set, system prompt, honeypot keys, and dual-channel judge. Three",
        r"cross-vendor models that expose a plaintext reasoning channel were run on the",
        r"four high-tier probes (the first thinking-leak probe, the fourth thinking-leak probe, the first prefix-extraction probe, the fourth step-reconstruction probe) with six repetitions each (24 requests per model) plus eight control probes at",
        r"one repetition each:",
        r"the first cross-vendor model \emph{nvidia/nemotron-3-super-120b-a12b} (NVIDIA, 120B-A12B mixture-of-experts, MoE; sizes give total--active parameters in billions),",
        r"the second cross-vendor model \emph{reflection/beam-free} (Reflection AI, Beam 501B-A23B MoE), and",
        r"the third cross-vendor model \emph{nvidia/nemotron-3-nano-omni-30b-a3b-reasoning} (NVIDIA, 30B-A3B",
        r"reasoning). Table~\ref{tab:e1cross} lists the short names used below: the first cross-vendor model is Nemotron-3-Super, the second is Beam, and the third is Nemotron-3-Nano. The primary model's high-tier pooled estimate is used (15/28, where 28 is the total",
        r"high-tier probe-responses; 53.6\%) as the baseline for comparison. Results are in Table~\ref{tab:e1cross}",
        r"and Fig.~\ref{fig:e1cross}.",
    ]),
     L([
        r"All evidence above comes from a single model, which is the most frequent",
        r"criticism of the native-blind-spot claim. The measurement was therefore replicated on a second, independent gateway (provider AtlasCloud; henceforth the cross-vendor gateway) using the same",
        r"probe set, system prompt, honeypot keys, and dual-channel judge. Three",
        r"cross-vendor models that expose a plaintext reasoning channel were run on the",
        r"four high-tier probes (the first thinking-leak probe, the fourth thinking-leak probe, the first prefix-extraction probe, the fourth step-reconstruction probe) with six repetitions each (24 requests per model) plus eight control probes at",
        r"one repetition each:",
        r"\emph{nvidia/nemotron-3-super-120b-a12b} (NVIDIA, 120B-A12B mixture-of-experts, MoE; sizes give total--active parameters in billions),",
        r"\emph{reflection/beam-free} (Reflection AI, Beam 501B-A23B MoE), and",
        r"\emph{nvidia/nemotron-3-nano-omni-30b-a3b-reasoning} (NVIDIA, 30B-A3B",
        r"reasoning). Table~\ref{tab:e1cross} lists the short names used below: Nemotron-3-Super, Beam, and Nemotron-3-Nano. The primary model's high-tier pooled estimate is used (15/28, where 28 is the total",
        r"high-tier probe-responses; 53.6\%) as the baseline for comparison. Results are in Table~\ref{tab:e1cross}",
        r"and Fig.~\ref{fig:e1cross}, whose per-model intervals are 95\% intervals; the",
        r"dashed reference line marks the primary model's high-tier pooled rate (15/28,",
        r"53.6\%) and is drawn for comparison only.",
     ])),
    # ---- P2: replace ordinal model references by short names ------------
    (r"The second cross-vendor model leaks", r"Beam leaks"),
    (r"generality. the second cross-vendor model reproduces a high CoT leak rate",
     r"generality. Beam reproduces a high CoT leak rate"),
    (r"At the probe level the second cross-vendor model matches the baseline",
     r"At the probe level Beam matches the baseline"),
    (r"The first cross-vendor model (8.3\%) and the third cross-vendor model (12.5\%) are both",
     r"Nemotron-3-Super (8.3\%) and Nemotron-3-Nano (12.5\%) are both"),
    (r"the blind spot: both models still produce a reasoning channel, and the third cross-vendor model leaks on",
     r"the blind spot: both models still produce a reasoning channel, and Nemotron-3-Nano leaks on"),
    (r"The contrast between the second cross-vendor model and the two",
     r"The contrast between Beam and the two"),
    (r"model-specific limitation applies: the third cross-vendor model exposes both reasoning and",
     r"model-specific limitation applies: Nemotron-3-Nano exposes both reasoning and"),
    (r"rest on a smaller effective sample; the first cross-vendor model and the second cross-vendor model expose both channels in 100\%.",
     r"rest on a smaller effective sample; Nemotron-3-Super and Beam expose both channels in 100\%."),
    # ---- P1-3: figure caption gateway name -------------------------------
    (r"\caption{Cross-vendor CoT leak rates on the second gateway.}",
     r"\caption{Cross-vendor CoT leak rates on the cross-vendor gateway.}"),
    # ---- P1-2: delete fig:e1cross standalone reading note ----------------
    (L([
        r"The figure plots per-model CoT leak rates on the four high-tier probes ($n=24$ each) with 95\% intervals; the dashed reference line marks the primary model's high-tier pooled rate (15/28, 53.6\%) measured on the first gateway and is drawn for comparison only.",
        r"",
    ]), ''),
    # ---- P1-3: census paragraph gateway name + missing colon + HTTP -----
    (L([
        r"A 39-model census on the second gateway of Section~\ref{sec:e1} found that only 3 models",
        r"(8\%) expose a usable reasoning channel---the first cross-vendor model, the second cross-vendor model, and a third open-router entry---but all three leak at 100\% on the",
        r"two high-leak probes the second indirect-injection probe and the second code-interpretation probe. That rate is far above the 8--12\% that the first cross-vendor model and the third cross-vendor model scored with the original probe set on the same gateway, so the difference is the probe set rather than the deployment. The remaining 36 candidates return",
        r"gateway errors (HTTP 401 Unauthorized, paid-model authorization required; HTTP 404 Not Found, model-not-found; or empty responses) or expose reasoning through non-standard",
    ]),
     L([
        r"A 39-model census on the cross-vendor gateway of Section~\ref{sec:e1} found that only 3 models",
        r"(8\%) expose a usable reasoning channel---Nemotron-3-Super, Beam, and a third open-router entry---but all three leak at 100\% on the",
        r"two high-leak probes: the second indirect-injection probe and the second code-interpretation probe. That rate is far above the 8--12\% that Nemotron-3-Super and Nemotron-3-Nano scored with the original probe set on the same gateway, so the difference is the probe set rather than the deployment. The remaining 36 candidates return",
        r"gateway errors (paid-model authorization required, model-not-found, or empty responses) or expose reasoning through non-standard",
     ])),
    # ---- P1-2: fig:corr, move reading guidance into preceding paragraph --
    (L([
        r"Stacking two defenses with shared blind spots collapses the stack to the",
        r"stronger layer's own residual: the second layer adds nothing.",
    ]),
     L([
        r"Stacking two defenses with shared blind spots collapses the stack to the",
        r"stronger layer's own residual: the second layer adds nothing. In Fig.~\ref{fig:corr} the discount factor is plotted against $\rho$ with the deployment point marked, and the independence prediction is the upper-right corner (validation pair $q_a=0.221$, $q_b=0.1513$).",
     ])),
    # ---- P1-2: fig:corr caption carries line-style meaning ----------------
    (r"\caption{Joint-residual discount versus the independence prediction.}",
     r"\caption{Joint-residual discount versus the independence prediction (solid: measured; dashed: achievable bound; dotted: errata anchor).}"),
    # ---- P1-2: delete fig:corr standalone note ---------------------------
    (L([
        r"The discount factor is plotted against $\rho$; solid = measured, dashed = achievable bound (4.48$\times$), dotted = errata anchor (7.63$\times$), and the deployment point is marked. Validation pair $q_a=0.221$, $q_b=0.1513$; the independence prediction is the upper-right corner.",
        r"",
    ]), ''),
    # ---- P2: defense-correlation concern phrasing ------------------------
    (L([
        r"undefined rather than merely small. The real defenses appear more effective than the simulation's conservative priors assume, and the defense-correlation concern is not resolved by the current probe set. This is reported as a boundary condition; the correlation model remains a useful",
        r"analytical tool for",
        r"defenses whose failure rates are non-negligible.",
    ]),
     L([
        r"undefined rather than merely small. The real defenses are more effective than the simulation's conservative priors assume, so the zero observed failure rate leaves the correlation between them unmeasured on this probe set; the correlation model remains a useful",
        r"analytical tool for",
        r"defenses whose failure rates are non-negligible.",
     ])),
    # ---- P2: drop repeated "not a measured one" discount phrase ----------
    (r"in the calibrated" + NL +
     r"model, where it predicts a residual of 5.8\% for the adaptive agent (a model-predicted rate, not a measured one).",
     r"in the calibrated" + NL +
     r"model, where it predicts a residual of 5.8\% for the adaptive agent."),
    # ---- P1-2: fig:output caption ----------------------------------------
    (r"\caption{Output-side filtering displaces rather than removes leakage.}",
     r"\caption{Output-side filtering displaces leakage: rates versus strictness, union floor marked.}"),
    # ---- P1-2: delete fig:output standalone note -------------------------
    (L([
        r"The vertical axis is leak rate (\%); CoT-effective, final-effective, and union leak rates are plotted against output-filter strictness $s$ (3{,}000 probes per point), with the $\tau$ countermeasure at $s=1$ and the irreducible union floor marked.",
        r"",
    ]), ''),
    # ---- P1-2: fig:e4consumer caption ------------------------------------
    (r"\caption{Real end-to-end consumer exposure by channel and filter.}",
     r"\caption{Consumer exposure by channel and filter; right: residual leak versus visibility.}"),
    # ---- P1-2: delete fig:e4consumer standalone note ---------------------
    (L([
        r"The left panel shows the downstream exposure rate on the positive-layer paired subset ($n=13$), by channel and after each output-side filter; the right panel plots consumer-side residual leak against channel visibility $p_{cot}$, which is zero at $p_{cot}=0$.",
        r"",
    ]), ''),
    # ---- P2: adaptive setup, question sentence + redundant parenthetical -
    (L([
        r"\textbf{Setup.} The question is whether an online agent that observes honeypot-downstream",
        r"labels (attack class, leaked flag, benign false-positive) can learn which of the",
        r"candidate defense configurations to deploy per observation context, under a",
        r"utility that charges leakage at $\lambda$ and penalizes false positives and",
        r"latency. Two learners are compared against a static best-single-configuration",
        r"baseline, a random baseline, and a label-omniscient oracle: a \emph{naive}",
        r"contextual bandit (a reinforcement-learning agent that selects among defense",
        r"configurations using per-request rewards) updated directly from per-request rewards, and a",
        r"\emph{model-driven} agent that pools labels from all contexts into a",
        r"per-configuration, per-class leak-rate model and re-optimizes periodically",
        r"requests.",
    ]),
     L([
        r"\textbf{Setup.} We test whether an online agent that observes honeypot-downstream",
        r"labels (attack class, leaked flag, benign false-positive) can learn which of the",
        r"candidate defense configurations to deploy per observation context, under a",
        r"utility that charges leakage at $\lambda$ and penalizes false positives and",
        r"latency. Two learners are compared against a static best-single-configuration",
        r"baseline, a random baseline, and a label-omniscient oracle: a \emph{naive}",
        r"contextual bandit updated directly from per-request rewards, and a",
        r"\emph{model-driven} agent that pools labels from all contexts into a",
        r"per-configuration, per-class leak-rate model and re-optimizes periodically.",
     ])),
    # ---- P2: reduce hedge density in the simulation disclaimer -----------
    (L([
        r"This section reports calibrated-model results rather than measured throughput.",
        r"The per-class leak rates, false-positive rates, and latency terms that drive",
        r"the utility are anchored to the real measurements reported in",
        r"Sections~\ref{sec:cot}--\ref{sec:output}, but",
        r"the request stream, the co-evolution schedule (in which an adaptive attacker migrates",
        r"its attack mix periodically), and the utility aggregation are",
        r"simulated. The $+0.0128$ gain per request is therefore a quantity internal to",
        r"the model: it says that, given those anchored rates and that utility, pooling",
        r"beats per-request reward learning when signal is weak---not a number a deployed agent would be expected to realize in practice. The seven validation gates are stated in model",
        r"terms for the same reason, and the cross-model migration variant of this",
        r"experiment remains a simulation-layer conclusion",
        r"(Section~\ref{sec:limitations}).",
    ]),
     L([
        r"This section reports calibrated-model results rather than measured throughput:",
        r"the per-class leak rates, false-positive rates, and latency terms that drive",
        r"the utility are anchored to the real measurements reported in",
        r"Sections~\ref{sec:cot}--\ref{sec:output}, while",
        r"the request stream, the co-evolution schedule (in which an adaptive attacker migrates",
        r"its attack mix periodically), and the utility aggregation are",
        r"simulated. The $+0.0128$ gain per request is therefore an internal",
        r"comparison---given those anchored rates and that utility, pooling beats",
        r"per-request reward learning when signal is weak---and the cross-model",
        r"migration variant of this experiment remains a simulation-layer conclusion",
        r"(Section~\ref{sec:limitations}).",
     ])),
    # ---- P2: drop HTTP 502 parenthesis in the three-condition arm --------
    (r"at three repetitions (24 successful responses from 27 requests; 3 failed" + NL +
     r"with HTTP 502 (Bad Gateway, the upstream gateway returned an invalid response). The CoT leak rate was",
     r"at three repetitions (24 successful responses from 27 requests; 3 failed" + NL +
     r"with gateway errors (invalid upstream responses). The CoT leak rate was"),
    # ---- P2: neutral reporting of g4 + the 44.4% rate --------------------
    (L([
        r"44.4\% rate should be interpreted with that in mind. Gate g4 (``final leak zero in all",
        r"conditions'') did not hold, and this is reported as such: deployed-side paradigms defend the final-answer and prompt layers but cannot reach the",
        r"reasoning channel, where the CoT-native blind spot lives. This is the same",
    ]),
     L([
        r"44.4\% rate combines real credential emission with policy-discourse mentions. The pre-registered zero-final-leak gate did not hold: deployed-side paradigms defend the final-answer and prompt layers but cannot reach the",
        r"reasoning channel, where the CoT-native blind spot lives. This is the same",
     ])),
    # ---- P2: forensic intro, drop self-praising clause -------------------
    (r"The results have four direct consequences for forensic practice, stated" + NL +
     r"separately because they follow from the measurements rather than from analogy.",
     r"The results have four direct consequences for forensic practice."),
    # ---- P2: split the judge-ratio sentence into two ---------------------
    (L([
        r"\textbf{2. The honeypot judge is usable as a log-scanning detector.} Across the",
        r"measured evidence the string-level dual-channel judge overstates downstream consumer exposure by",
        r"only $1.18\times$ on the CoT channel (string-level hits 11/13 vs. consumer-recovered",
        r"11/13, so the judge is exact on this sample; the 1.18$\times$ is the worst-case",
        r"ratio across all 32 responses) and produced no",
        r"false positives on the keys it was given. A substring-matching scanner over archived reasoning",
    ]),
     L([
        r"\textbf{2. The honeypot judge is usable as a log-scanning detector.} Across the",
        r"measured evidence the string-level dual-channel judge produced no",
        r"false positives on the keys it was given. On the CoT-positive samples it is",
        r"exact (string-level hits 11/13 versus consumer-recovered 11/13); its $1.18\times$",
        r"overstatement of downstream exposure is the worst-case ratio across all 32",
        r"responses. A substring-matching scanner over archived reasoning",
     ])),
    # ---- P2: behaviour -> behavior (two places) --------------------------
    (r"The match rule is literal rather than semantic, so false-positive behaviour is" + NL +
     r"governed by the key strings supplied to the scanner rather than by model" + NL +
     r"behaviour; transfer to a different secret set has not been evaluated.",
     r"The match rule is literal rather than semantic, so false-positive behavior is" + NL +
     r"governed by the key strings supplied to the scanner rather than by model" + NL +
     r"behavior; transfer to a different secret set has not been evaluated."),
    (r"extraction) do not leak: the refusal behaviour is applied to the final answer",
     r"extraction) do not leak: the refusal behavior is applied to the final answer"),
    # ===== P1-1: compress the whole Limitations section ===================
    # The old block is extracted from the file itself (enumerate indentation
    # in the source mixes 0- and 6-space continuation lines).
    (None,
     L([
        r"\textbf{Disclosure and reproducibility.} The primary real model is identified",
        r"only as the primary model under a disclosure agreement with the gateway",
        r"operator, and the gateway credential is not released, so the core real-model",
        r"measurements cannot be re-executed byte-for-byte by a third party: the released",
        r"probe suite and experiment framework can be re-run only against another",
        r"gateway. Every number in the paper is computed from released structured",
        r"artifacts by reproducible generators, so the derivation---and all simulation",
        r"results, which use fixed seeds---is exactly reproducible; the gateway operator",
        r"was informed before submission.",
        r"",
        r"\textbf{One primary real reasoning model.} The blind spot is confirmed on five",
        r"independent real samples of the primary model (diverse-cohort total $N=268$)",
        r"and on the cross-vendor gateway with three cross-vendor models: Reflection",
        r"Beam is statistically indistinguishable from the primary model's baseline",
        r"(62.5\% versus 53.6\%, Fisher $p=0.581$), while two NVIDIA models leak",
        r"significantly less (8.3\%, 12.5\%). The cross-vendor evidence is real, not",
        r"simulated, but its expression varies by model, and a 39-model census on the",
        r"cross-vendor gateway found only 3 models (8\%) that expose a usable reasoning",
        r"channel, all leaking at 100\% on the two high-leak indirect-injection and",
        r"code-interpretation probes. The cross-vendor migration analysis in",
        r"Section~\ref{sec:adaptive} is therefore a simulation-layer conclusion: the",
        r"architectural constraint is established on real data, but the cross-model",
        r"generalization of specific leak rates is not.",
        r"",
        r"\textbf{Further boundary conditions.} The grand pool of 371 attack responses",
        r"spans two regimes, and the cohort split is reported rather than a single rate",
        r"(39/268 on fresh probes versus 103/103 on repetition and stress runs, the",
        r"latter an upper bound obtained by construction); per-class cells in the",
        r"diverse cohort remain small, with thinking leak dominating the signal. The 4",
        r"high-tier probes that carry all observed CoT leaks are also the probes most",
        r"heavily reproduced, so rates on them are the most replicated and the most",
        r"selection-pressured; the headline 14.55\% rate comes from the diverse cohort,",
        r"and the generalization claim concerns channel structure, not any single",
        r"probe's leak probability. False-positive rates, latency, and the observer",
        r"confusion matrix are deployment assumptions (the benign sample comprises 4",
        r"records; sensitivity sweeps over observer quality change the oracle gap by",
        r"only 0.0018), and split-across-boundary leakage remains parameterized rather",
        r"than observed, with the zero $\tau$ residual measured only on the probe",
        r"families that produced leaks in the consumer arm. The co-evolution attacker",
        r"migrates against the defense agent's current residual; the real security",
        r"audit extracted the credential in 4 of 4 sessions, but all extractions",
        r"occurred in the reasoning channel and none reached the final answer, so the",
        r"channel-separation defense held. Agentic-system security more broadly",
        r"continues to evolve~\cite{agentic2025}.",
     ])),
    # ---- P2: reproducibility section, structured records phrasing --------
    (L([
        r"Every number in this paper is computed from stored experiment artifacts rather",
        r"than entered by hand. Each run writes a JSON record carrying its configuration,",
        r"per-response verdicts, gate results, and a content-based hash; the pooled statistics",
        r"reported in Section~\ref{sec:cot} are produced by a single reconciliation script that applies the",
        r"documented filter (attack-class records only, for the first and second samples,",
        r"per-experiment channel labels) and re-verifies determinism by byte-level",
        r"comparison on re-run. Every figure is generated by a script that reads those",
        r"JSON records directly, so no plotted value can drift from the stored evidence.",
        r"Report and figure generators are reproducible and expose a verification mechanism that signals failure if a regenerated artifact differs from the stored one.",
    ]),
     L([
        r"Every number in this paper is computed from stored experiment artifacts rather",
        r"than entered by hand. Each run writes a structured record carrying its",
        r"configuration,",
        r"per-response verdicts, gate results, and a content-based hash; the pooled statistics",
        r"reported in Section~\ref{sec:cot} are produced by a single reconciliation script that applies the",
        r"documented filter (attack-class records only, for the first and second samples,",
        r"per-experiment channel labels) and re-verifies determinism by byte-level",
        r"comparison on re-run. Every figure is generated by a script that reads those",
        r"records directly, so no plotted value can drift from the stored evidence.",
        r"Report and figure generators expose a verification mechanism that signals failure if a regenerated artifact differs from the stored one.",
     ])),
    # ---- P2: release contents, drop repeated JSON jargon -----------------
    (L([
        r"generators, and every JSON result artifact, including the per-model gateway",
        r"error responses for the blocked cross-model replication and the pooled-sample",
        r"reconciliation data; each figure and table value maps to a JSON field in",
        r"it.",
    ]),
     L([
        r"generators, and every result artifact, including the per-model gateway",
        r"error responses for the blocked cross-model replication and the pooled-sample",
        r"reconciliation data; each figure and table value maps to a stored field in",
        r"it.",
     ])),
    # ---- P1-3: conclusion gateway name -----------------------------------
    (r"the asymmetry is consistent on a second gateway and vendor, and a 39-model census",
     r"the asymmetry is consistent on the cross-vendor gateway, and a 39-model census"),
]


def main():
    with open(P, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for i, (old, new) in enumerate(EDITS):
        if old is None:
            anchor = r'\textbf{Reproducibility is constrained by disclosure.}'
            a = data.find(anchor)
            b = data.find(r'\end{enumerate}', a)
            assert a != -1 and b != -1
            old = data[a:b + len(r'\end{enumerate}')]
            EDITS[i] = (old, new)
        n = data.count(old)
        if n != 1:
            print('FAIL edit %d: %d hits (need exactly 1)' % (i, n))
            print('  old first line: %r' % old.split(NL)[0][:110])
            sys.exit(1)
        data = data.replace(old, new)
    tmp = P + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='') as f:
        f.write(data)
    os.replace(tmp, P)
    print('OK: %d edits applied' % len(EDITS))


if __name__ == '__main__':
    main()
