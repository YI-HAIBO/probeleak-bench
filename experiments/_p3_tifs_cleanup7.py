# -*- coding: utf-8 -*-
"""Pass-7 cleanup for paper/p3_tifs.tex.

Covers the third-round review list:
  * hard typographic errors (stray quote in captions, double comma)
  * first-reader confusion items (text / figures / tables / references)
  * residual AI-smell phrasings
  * non-academic content (vendor-survey framing, duplicated disclosure)

Atomic write: any mismatch aborts and nothing is written.
"""
import io
import os
import re
import sys

PATH = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'


def to_regex(s):
    # re.escape does NOT escape spaces; the file wraps lines at arbitrary points,
    # so every whitespace run in the pattern must match any whitespace run.
    return r'\s+'.join(re.escape(t) for t in re.split(r'\s+', s) if t)


PAIRS = [
    # ------------------------------------------------------------------
    # H1-H4  hard typographic errors
    # ------------------------------------------------------------------
    ("pooled rate.\"}", "pooled rate.}"),
    ("shown separately.\"}", "shown separately.}"),
    ("irreducible union floor are marked.\"}", "irreducible union floor are marked.}"),
    ("requests coming from a prompt-level self-check arm),, and E6",
     "requests coming from a prompt-level self-check arm), and E6"),

    # ------------------------------------------------------------------
    # T1  pooled-sample paragraph: explain the three unreconciled totals
    # ------------------------------------------------------------------
    (r"""\textbf{The pooled sample is bimodal and must be split.} Pooling all real-gateway
experiments into a single rate is the natural analytical move. Done without
distinction, it produces three totals for this statistic (149/491 = 30.3\%,
77/220 = 35.0\%, and 115/324 = 35.5\%), none of which reconciles with the
underlying records. The two causes were a filter mismatch
(per-sample counts include only attack-kind traffic, while naive scans counted
benign, negative-control, and ablation records) and a field-name inconsistency
(E10 stores the reasoning leak in \texttt{reasoning\_leak} rather than
\texttt{cot\_leak}). Re-deriving the statistic from source with explicit
filters yields Table~\ref{tab:cohort}.""",
     r"""\textbf{The pooled sample spans two regimes and must be split.} A single
pooled rate would mix fresh probes with runs that deliberately re-execute
probes already known to leak. Three successive naive recomputations of this
one statistic disagreed---149/491 = 30.3\%, 77/220 = 35.0\%, and 115/324 =
35.5\%---because each applied a different record filter: per-sample counts
include only attack-kind traffic, whereas the naive scans also counted benign,
negative-control, and ablation records; in addition E10 stores the reasoning
leak in \texttt{reasoning\_leak} rather than \texttt{cot\_leak}. None of the
three reconciles with the underlying records, and none of the three is
reported anywhere else in this paper. Re-deriving the statistic from source
with an explicit, documented filter yields Table~\ref{tab:cohort}."""),

    # ------------------------------------------------------------------
    # T2  contribution item 3: fix broken line wrap, define tau and D30
    # ------------------------------------------------------------------
    ("1.70$\\times$ (see Section~\\ref{sec:corr}), and the measured two-layer $\\tau$+D30 stack (D30: sentence-level output-side\nsuppression) collapses to\nits stronger layer's residual (a 4.51$\\times$ discount on 13 real\n      CoT-positive traces).",
     "1.70$\\times$ (see Section~\\ref{sec:corr}); the measured two-layer stack\n      of $\\tau$ (literal key redaction) and D30 (sentence-level output-side\n      suppression) collapses to\n      its stronger layer's residual (a 4.51$\\times$ discount on 13 real\n      CoT-positive traces)."),

    # ------------------------------------------------------------------
    # T3  provenance table is a released artifact, not a table in the paper
    # ------------------------------------------------------------------
    ("are generated from stored JSON artifacts; a provenance table maps every\nreported figure to its JSON field.",
     "are generated from stored JSON artifacts; the released reconciliation\nartifact maps every reported figure to its JSON field\n(Section~\\ref{sec:reproducibility})."),

    # ------------------------------------------------------------------
    # T4 / A11  "non-trivially high"
    # ------------------------------------------------------------------
    ("The important contrast is that no class except thinking leak is non-trivially high, not that the other classes have a zero rate.",
     "Only one of the seven classes has a point estimate above 6\\%; for the remaining classes the small counts bound the rate rather than establish it as zero."),

    # ------------------------------------------------------------------
    # T5  reproducibility gate: unit of analysis is the probe, not the request
    # ------------------------------------------------------------------
    ("\\emph{failed} in the B3 sample (3 of 30 probes inconsistent, 90.0\\% consistency (27/30; source: p1\\_real\\_scale\\_validation\\_v1.json)). At temperature 0.1 leakage is a probabilistic event.",
     "The gate compares the verdict triple (final leak, CoT leak, refusal) across\nrepeats of the same probe, so its unit is the probe rather than the request:\n27 of the 30 evaluated probes returned the same triple on every repeat and 3\ndid not (90.0\\% consistency, 27/30; source:\np1\\_real\\_scale\\_validation\\_v1.json). This count is therefore not comparable\nwith the 112 effective attacks of Table~\\ref{tab:cot}, which counts requests.\nAt temperature 0.1 leakage is a probabilistic event."),

    # ------------------------------------------------------------------
    # T6  simulation baseline provenance
    # ------------------------------------------------------------------
    ("A simulation predicted an asymmetry (CoT 42.4\\% versus final\n26.7\\%, ratio 1.59$\\times$), which we tested on a real reasoning model.",
     "A simulated world model predicted an asymmetry (CoT 42.4\\% versus final\n26.7\\%, ratio 1.59$\\times$; simulated-LLM campaign, not a real-model\nmeasurement), which we tested on a real reasoning model."),

    # ------------------------------------------------------------------
    # T7  47.7--55.4% dangling number
    # ------------------------------------------------------------------
    ("cross-vendor transfer rates measured in simulation (47.7--55.4\\% over six\nvendors) remain clearly labeled as simulation-only;",
     "cross-vendor transfer rates measured in simulation (47.7--55.4\\% over six\nsimulated vendors; these rates appear in no table or figure of this paper and\nenter no downstream calculation) remain clearly labeled as simulation-only;"),

    # ------------------------------------------------------------------
    # T8 / A1  "mirror case"
    # ------------------------------------------------------------------
    ("answer~\\cite{rbac2026}; our result is the mirror case: a model whose final answers are clean but whose\nreasoning enumerates secrets. Both phenomena show",
     "answer~\\cite{rbac2026}. We measure the converse case: a model whose final\nanswers are clean but whose reasoning enumerates secrets. Both phenomena show"),

    # ------------------------------------------------------------------
    # T9  "complementary" vs "mirror case" contradiction (PCC-SQL)
    # ------------------------------------------------------------------
    ("results are complementary: PCC-SQL is a producer-side deterministic mechanism",
     "results address a different stage: PCC-SQL is a producer-side deterministic mechanism"),

    # ------------------------------------------------------------------
    # T10 / A4  deduplicate the "how much / through which channel" refrain
    # ------------------------------------------------------------------
    ("This line of work studies the same phenomenon from the privacy side rather\nthan the measurement side. That line asks\n\\emph{whether} reasoning leaks; we instead quantify \\emph{how much} (14.55\\% on\n268 fresh-probe responses) and \\emph{through which channel} (CoT only, with the\nfinal-answer channel at 0/268), over five independent real-model replications.",
     "This line of work studies the same phenomenon from the privacy side rather\nthan the measurement side: it establishes that reasoning leaks. We add the\nchannel-separated magnitudes---\\emph{how much} (14.55\\% on 268 fresh-probe\nresponses) and \\emph{through which channel} (CoT only, with the final-answer\nchannel at 0/268)---over five independent real-model replications."),

    ("what transfers across model families~\\cite{tian2025}. This work is orthogonal to these lines: rather than asking whether reasoning leaks, we\nmeasure \\emph{how much} and \\emph{through which channel}.",
     "what transfers across model families~\\cite{tian2025}. Those results treat the\nreasoning trace as an asset to be protected or distilled; we treat it as a\nmeasurement surface and report per-channel rates."),

    ("obfuscation~\\cite{promptobfuscation2025}. We do not defend the system prompt; we measure whether the reasoning channel\nexposes the secrets it is meant to protect.",
     "obfuscation~\\cite{promptobfuscation2025}. We do not evaluate prompt-level\ndefenses; the measurement target here is whether the reasoning channel\nexposes credentials planted in the database."),

    # ------------------------------------------------------------------
    # T11  "bimodal" -> two regimes (abstract, body, limitations, conclusion)
    # ------------------------------------------------------------------
    ("at 62.5\\% ($n=8$), and the pooled rate (38.27\\%) is bimodal---14.55\\% in the",
     "at 62.5\\% ($n=8$), and the pooled rate (38.27\\%) mixes two regimes---14.55\\% in the"),

    ("\\item \\textbf{Sample size and bimodality.} The grand pool of 371 attack",
     "\\item \\textbf{Sample size and cohort heterogeneity.} The grand pool of 371 attack"),

    ("(8\\% of the 39), while architecturally bounded to those models. The pooled rate (38.27\\%) is bimodal because repetition and stress runs re-execute",
     "(8\\% of the 39), while architecturally bounded to those models. The pooled rate (38.27\\%) mixes two regimes because repetition and stress runs re-execute"),

    # ------------------------------------------------------------------
    # A2 / N5  product-release narrative; gulyamov is a survey, not a demo
    # ------------------------------------------------------------------
    ("injection against LLM-integrated web applications has been demonstrated in\nproduction systems~\\cite{gulyamov2026}. The releases of GPT-4~\\cite{gpt4tech2023},\nLlama 3~\\cite{llama32024}, and DeepSeek-R1~\\cite{deepseekr12025} have\naccelerated both capability and safety research.",
     "injection against LLM-integrated web applications is surveyed\ncomprehensively, with attack vectors and defenses catalogued~\\cite{gulyamov2026}.\nOf the models cited here, DeepSeek-R1~\\cite{deepseekr12025} exposes a separate\nreasoning field and is therefore the representative of the surface this paper\nmeasures; GPT-4~\\cite{gpt4tech2023} and Llama 3~\\cite{llama32024} do not."),

    # ------------------------------------------------------------------
    # A6 / A7 / A8  Related Work connectors
    # ------------------------------------------------------------------
    ("and SafetyBench~\\cite{safetybench2024}; none separates reasoning-channel from\nfinal-answer outputs.",
     "and SafetyBench~\\cite{safetybench2024}; none reports leak rates separately for\nthe reasoning channel and for the final answer."),

    ("enhanced reasoning improves security while model size does not---complementary to\nour observation that the same reasoning capabilities that improve backbone",
     "enhanced reasoning improves security while model size does not, which relates to\nour observation that the same reasoning capabilities that improve backbone"),

    ("of prompt injection as the leading LLM risk for the second consecutive\nedition~\\cite{owasp2025} further motivate measurement-based evaluation;",
     "of prompt injection as the leading LLM risk for the second consecutive\nedition~\\cite{owasp2025} bear directly on the design of measurement-based\nevaluation;"),

    # ------------------------------------------------------------------
    # A9 / A10 / A12  Results section wording
    # ------------------------------------------------------------------
    ("Leaked reasoning material was frequently\nexhaustive---all 15 honeypot keys enumerated---while the final answer emitted\nonly a count (``15''), a displacement signature revisited in\nSection~\\ref{sec:output}.",
     "Leaked reasoning often enumerated all 15 honeypot keys, while the final\nanswer emitted only a count (``15''); the displacement effect behind this\ncontrast is quantified in Section~\\ref{sec:output}."),

    ("extraction) do not leak. This is consistent with a model that refuses direct requests but not appeals to\nits own reasoning trace.",
     "extraction) do not leak: the refusal behaviour is applied to the final answer\nand not to the reasoning trace."),

    # ------------------------------------------------------------------
    # A15 / A16  cohort split rhetoric
    # ------------------------------------------------------------------
    ("The split changes the conclusion. The \\emph{diverse-probe cohort}",
     "The two cohorts support different inferences. The \\emph{diverse-probe cohort}"),

    ("construction, and its 66.99\\% final-answer rate is the strongest evidence that the ``final answer",
     "construction, and its 66.99\\% final-answer rate shows that the ``final answer"),

    # ------------------------------------------------------------------
    # T12 / A20  "only channel" over-claim (body)
    # ------------------------------------------------------------------
    ("production-side defenses, and it is the only channel in which an adaptive\ndefender can find a usable signal in our threat model.",
     "production-side mechanisms do not observe it, so within our threat model the\nusable signal for an adaptive defender lies in the reasoning channel."),

    # ------------------------------------------------------------------
    # T13  unverified "likely to transfer"
    # ------------------------------------------------------------------
    ("corpus to identify credential-bearing reasoning without re-running the model, and its calibration is likely to transfer to other secret sets because the match rule is literal\nrather than semantic.",
     "corpus to identify credential-bearing reasoning without re-running the model.\nThe match rule is literal rather than semantic, so false-positive behaviour is\ngoverned by the key strings supplied to the scanner rather than by model\nbehaviour; we did not test transfer to a different secret set."),

    # ------------------------------------------------------------------
    # A17  "Two consequences follow"
    # ------------------------------------------------------------------
    ("keys---while reasoning-channel suppression eliminated 7 of 7. Two consequences\nfollow.",
     "keys---while reasoning-channel suppression eliminated 7 of 7. Two operational\npoints follow."),

    # ------------------------------------------------------------------
    # N6  "least expensive control" (unsupported cost claim), twice
    # ------------------------------------------------------------------
    ("secret. The containment measure is correspondingly simple and is the least expensive control identified: do not persist \\texttt{reasoning\\_content} in\nproduction logs, or persist it only after redaction.",
     "secret. The containment measure is a logging-policy change rather than a model\nchange: do not persist \\texttt{reasoning\\_content} in production logs, or\npersist it only after redaction."),

    ("the model:\nthe least expensive control is to avoid persisting it in production logs.",
     "the model:\nthe exposure is removed by not persisting it in production logs."),

    # ------------------------------------------------------------------
    # A18 / A19 / A20  Conclusion closing claim
    # ------------------------------------------------------------------
    ("Fourth, production-side baselines (constrained decoding, schema hiding)\nare structurally blind to the reasoning channel, which is the only channel in which an adaptive\ndefender finds a signal in our threat model. The security claim is that channel separation is a strictly weaker requirement\nthan blocking",
     "Fourth, production-side baselines (constrained decoding, schema hiding) do not\nobserve the reasoning channel, so within our threat model they give an adaptive\ndefender no signal from it. The resulting claim is that channel separation is a strictly weaker requirement\nthan blocking"),

    ("reasoning-channel leakage outright---but only conditionally: it suffices when\nthe final-answer baseline is observed at zero, as on fresh probes, and\ndegrades to channel-complete scanning when the final channel itself leaks, as",
     "reasoning-channel leakage outright---but only conditionally: it holds when\nthe final-answer baseline is observed at zero, as on fresh probes, and\nrequires channel-complete scanning when the final channel itself leaks, as"),

    # ------------------------------------------------------------------
    # N1  vendor-survey framing in the introduction
    # ------------------------------------------------------------------
    ("The stakes\nare not theoretical, though the 88\\% figure comes from vendor surveys\nand serves as motivation rather than evidence: 88\\% of organizations deploying\nAI agents report security incidents, with uncontrolled database access as the\nprimary attack vector~\\cite{grap2026, bessemer2026, microsoft2026}, and the\nInternational AI Safety Report concludes that no current alignment method\nreliably prevents unsafe outputs~\\cite{bengio2025}.",
     "The stakes\nare reported by industry surveys rather than established by peer-reviewed\nmeasurement: 88\\% of organizations deploying AI agents report a security\nincident, with uncontrolled database access named as the primary\nvector~\\cite{grap2026, bessemer2026, microsoft2026}. These are self-reported\nvendor surveys and are cited only as context. The International AI Safety\nReport concludes that no current alignment method reliably prevents unsafe\noutputs~\\cite{bengio2025}."),

    # ------------------------------------------------------------------
    # N3  repeated caveat in Limitations
    # ------------------------------------------------------------------
    ("final answer, so the channel-separation defense held. Agentic-system security\nmore broadly remains an active area; the vendor-reported 88\\% figure serves as\nmotivation rather than evidence, and we cite it as such.",
     "final answer, so the channel-separation defense held. Agentic-system security\nmore broadly remains an active area~\\cite{agentic2025}."),

    # ------------------------------------------------------------------
    # N4  duplicated responsible-disclosure sentence
    # ------------------------------------------------------------------
    ("it. The gateway operator was informed of the findings before submission and\nconsented to their publication.",
     "it."),

    # ------------------------------------------------------------------
    # F1  Fig. 1: explain D30(s), tau, p_cot boxes
    # ------------------------------------------------------------------
    ("\\caption{Measured agent stack: input-side controls precede generation; output-side filters and consumer visibility follow.}",
     "\\caption{Measured agent stack. A user prompt passes an input-side\ncontent-safety gateway, then the reasoning model, which returns two streams:\n\\texttt{reasoning\\_content} and the final answer. Output-side filtering (D30,\nparameterized by strictness $s$), literal redaction ($\\tau$), and the\nconsumer's channel visibility $p_{cot}\\in[0,1]$ act after generation.}"),

    # ------------------------------------------------------------------
    # F2  Fig. 4: data sources and bar labels
    # ------------------------------------------------------------------
    ("\\caption{Per-attack-class CoT leak rates: simulation versus the real model.}",
     "\\caption{Per-attack-class CoT leak rates: simulation versus the real model.\nBars give the CoT leak rate for each attack class and are labelled with the\npercentage; simulated bars come from the simulated world model, real bars from\nthe B3 sample ($N=112$ effective attacks).}"),

    # ------------------------------------------------------------------
    # F3  Fig. 8: reference line is from the *other* gateway
    # ------------------------------------------------------------------
    ("\\caption{Cross-vendor CoT leak rates and 95\\% intervals on the second gateway.}",
     "\\caption{Cross-vendor CoT leak rates and 95\\% intervals on the second gateway\n(AtlasCloud, \\url{https://api.kilo.ai/api/gateway}). Points are per-model CoT\nleak rates on the four high-tier probes ($n=24$ each) and bars are 95\\%\nintervals. The dashed reference line is the dots3-note-prev high-tier pooled\nestimate (15/28, 53.6\\%) measured on the \\emph{first} gateway and is drawn for\ncomparison only.}"),

    # ------------------------------------------------------------------
    # F4  Fig. 7: axis semantics
    # ------------------------------------------------------------------
    ("\\caption{Real end-to-end consumer exposure and measured channel visibility.}",
     "\\caption{Real end-to-end consumer exposure and measured channel visibility.\nLeft: number of samples from which the downstream consumer recovered at least\none honeypot key, by channel (final: 0 of 32; CoT: 11 of 13 positive samples)\nand after each output-side defense. Right: consumer benefit in\nleak-equivalents per request (vertical axis) against channel visibility\n$p_{cot}$ (horizontal axis); the benefit is $p_{cot}\\cdot\\Delta E_{cot}$, so it\nis zero at $p_{cot}=0$.}"),

    # ------------------------------------------------------------------
    # F5  Fig. 6: define "pooled"
    # ------------------------------------------------------------------
    ("pooled. Points show the CoT leak rate by attack class; horizontal bars show\nWilson 95\\% intervals; the vertical dashed line marks the pooled rate.}",
     "pooled (B3 and E6 combined). Points show the CoT leak rate by attack class;\nhorizontal bars show Wilson 95\\% intervals; the vertical dashed line marks the\npooled rate.}"),

    # ------------------------------------------------------------------
    # T-I  Table I: effective-N decay and gateway blocks
    # ------------------------------------------------------------------
    ("\\caption{CoT-native blind spot on a real reasoning model, three independent\nsamples.}",
     "\\caption{CoT-native blind spot on a real reasoning model, three independent\nsamples. Counts in parentheses are leak events; rates are computed over\neffective attacks.}"),

    ("Refusal rate & 32.0\\% & 28.6\\% & 23.8\\% \\\\\nAll leaks CoT-only & yes & yes & yes \\\\\nGateway blocks & 9 & 20 & 8 \\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}",
     "Refusal rate & 32.0\\% & 28.6\\% & 23.8\\% \\\\\nAll leaks CoT-only & yes & yes & yes \\\\\nGateway blocks & 9 & 20 & 8 \\\\\n\\bottomrule\n\\end{tabular}\n\\vspace{-4pt}\n{\\raggedright\\footnotesize Effective attack $N$ is below `requests sent' because\ngateway-blocked prompts, benign probes, negative controls, and failed requests\nare excluded; the two counts therefore differ by more than the gateway-block\ncolumn. `Gateway blocks' counts sent requests rejected upstream by the\ncontent-safety layer before reaching the model.\\par}\n\\end{table}"),

    # ------------------------------------------------------------------
    # T-II  Table II: definition of n
    # ------------------------------------------------------------------
    ("\\caption{Per-attack-class results on the real model (4 repeats per probe).}",
     "\\caption{Per-attack-class results on the real model. $n$ is the number of\nscorable repeats, at 4 repeats per probe, so $n$ differs across classes only\nbecause they contain different numbers of probes.}"),

    # ------------------------------------------------------------------
    # T-III  Table III: reconcile Final = 69 with the zero-leak claim
    # ------------------------------------------------------------------
    ("The repetition cohort re-runs probes already known to leak and is therefore selection-conditioned, not an estimate of the marginal rate.\\par}",
     "The repetition cohort re-runs probes already known to leak and is therefore selection-conditioned, not an estimate of the marginal rate. All 69 final-channel hits fall in that cohort: none occurs in the 0 of 268 fresh-probe result reported as the headline, so the two numbers are not in conflict. The `Experiments' column counts the campaigns contributing to each cohort (5 per cohort, 10 in total).\\par}"),

    # ------------------------------------------------------------------
    # T-IV  Table IV: header wording and p-value precision
    # ------------------------------------------------------------------
    ("Model & Vendor & CoT leaks & Rate & $p$ vs.\\ ref. \\\\",
     "Model & Vendor & CoT leaks & Rate & $p$ (vs.\\ reference) \\\\"),

    ("though not equivalently (Fisher $p=0.58$).",
     "though not equivalently (Fisher $p=0.581$)."),

    ("$p=0.58$; Wald CI for the rate difference $[-0.178, +0.357]$ covers zero).",
     "$p=0.581$; Wald CI for the rate difference $[-0.178, +0.357]$ covers zero)."),

    ("      62.5\\% versus 53.6\\% (Fisher $p=0.58$; not an equivalence test, so",
     "      62.5\\% versus 53.6\\% (Fisher $p=0.581$; not an equivalence test, so"),

    # ------------------------------------------------------------------
    # T-V  Table V: negative utilities and the meaning of the gain
    # ------------------------------------------------------------------
    ("{\\raggedright\\footnotesize Utility per request at $\\lambda=2$; leak rate in parentheses.\\par}",
     "{\\raggedright\\footnotesize Utility per request at $\\lambda=2$; leak rate in\nparentheses. Utilities are negative for every arm because leak cost\n($\\lambda$), false-positive cost, and latency cost are all charged against a\nzero-cost baseline, so the sign carries no meaning; what matters is the\nordering and the differences between arms. In the real-calibrated world the\nstatic arm is the no-defense configuration, whose residual negative utility is\nobserver false-positive cost.\\par}"),

    # ------------------------------------------------------------------
    # T-VI  Table VI: define Reach / Union / Final-only
    # ------------------------------------------------------------------
    ("{\\raggedright\\footnotesize Scored on the eight real CoT-only leak events and in the simulated world;",
     "{\\raggedright\\footnotesize `Reach' is the number of the eight real CoT-only leak\nevents that the mechanism can observe or rewrite (8 of 8 = all, 0 of 8 =\nnone). `Union' is the reduction in union leak rate and `Final-only' the\nreduction measured on the final answer alone; `--' means the quantity is\nundefined for that mechanism. Scored on the eight real CoT-only leak events and in the simulated world;"),

    # ------------------------------------------------------------------
    # R1-R4  reference tier / status wording
    # ------------------------------------------------------------------
    ("\\emph{arXiv preprint arXiv:2607.22115}, 2026\n(accepted at ACM SIGMOD 2027).",
     "\\emph{arXiv preprint arXiv:2607.22115}, 2026; to appear at ACM SIGMOD 2027."),

    ("arXiv:2506.15674}, 2025 (accepted at EMNLP 2025; conference paper).",
     "arXiv:2506.15674}, 2025; to appear at EMNLP 2025."),

    ("ISSN 2755-2721 (journal article; a peer-reviewed applied-engineering outlet).",
     "ISSN 2755-2721."),

    ("\\emph{arXiv preprint arXiv:2607.24625}, 2026\n(preprint; not yet peer-reviewed).",
     "\\emph{arXiv preprint arXiv:2607.24625}, 2026."),

    # ------------------------------------------------------------------
    # N2  label the three industry sources explicitly
    # ------------------------------------------------------------------
    ("\\url{https://www.gravitee.io/ai-agent-security-2026}.",
     "\\url{https://www.gravitee.io/ai-agent-security-2026} (industry report; not\npeer-reviewed)."),

    ("\\url{https://bvp.com/resources/research/securing-ai-agents-2026}.",
     "\\url{https://bvp.com/resources/research/securing-ai-agents-2026} (industry\nreport; not peer-reviewed)."),

    ("\\url{https://www.microsoft.com/security/business/ai-security/securing-agentic-ai}.",
     "\\url{https://www.microsoft.com/security/business/ai-security/securing-agentic-ai}\n(industry report; not peer-reviewed)."),
]


def main():
    with io.open(PATH, encoding='utf-8') as f:
        text = f.read()

    applied = 0
    for idx, (old, new) in enumerate(PAIRS, 1):
        rx = to_regex(old)
        n = len(re.findall(rx, text))
        if n != 1:
            sys.stderr.write('ABORT pair %d: regex found %d matches\n' % (idx, n))
            sys.stderr.write('OLD: %r\n' % old)
            return 1
        text = re.sub(rx, lambda m: new, text, count=1)
        applied += 1

    tmp = PATH + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, PATH)
    sys.stdout.write('OK: %d pairs applied, %d bytes\n'
                     % (applied, os.path.getsize(PATH)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
