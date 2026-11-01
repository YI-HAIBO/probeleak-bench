#!/usr/bin/env python3
# Pass-10: fix fourth-round review (hard grammar, AI-smell, non-academic,
# abbreviations, text clarifications, figure/table captions, references).
# Strategy: verify ALL old strings against the original before writing anything.
# NOTE: OLD strings MUST reproduce the file's actual line wraps (LF) verbatim.
import io, sys, os

PATH = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
b = io.open(PATH, encoding='utf-8').read()

# Each pair: (old, new). Multi-line pairs use triple-quoted raw strings.
PAIRS = [
 # ---- A. hard grammar errors ----
 (r'''\textbf{Reproducibility failure is itself a result.} A gate asserting identical
(final, CoT, refusal) classification over repeats of the same probe
The gate compares the verdict triple (final leak, CoT leak, refusal) across
repeats of the same probe, so its unit is the probe rather than the request:''',
  r'''\textbf{Reproducibility failure is itself a result.} A gate asserting identical
(final, CoT, refusal) classification over repeats of the same probe
\emph{failed} in the B3 sample: the gate compares the verdict triple
(final leak, CoT leak, refusal) across repeats of the same probe, so its
unit is the probe rather than the request:'''),

 (r'''The reasoning channel is therefore outside the reach of
production-side mechanisms do not observe it, so within our threat model the''',
  r'''The reasoning channel is therefore outside the reach of
production-side mechanisms that do not observe it, so within our threat model the'''),

 (r'''and no value of $\rho$ yields a positive net
(no value of $\rho$ yields a positive net benefit at any of the three $\lambda$ values). Reducing''',
  r'''and no value of $\rho$ yields a positive net benefit at any of the three $\lambda$ values. Reducing'''),

 (r'''of 0.0186
and ends with a policy that matches the shifted oracle's configuration.''',
  r'''of 0.0186)
and ends with a policy that matches the shifted oracle's configuration.'''),

 (r'not by filter insufficiency.', r'not to filter insufficiency.'),

 # ---- B. E7 dual meaning + "refutes this" ----
 (r'An earlier expansion (E7) seemed to refute the concern that the probe set was',
  r'An earlier, broader probe expansion ran 12 attack modes at 3 repetitions each and appeared to suggest the probe set was not'),

 (r'''classes. The E12 repetition-v2 run (te1--te3, rp1--rp2, 8 repetitions each, 39
successful responses from 48 requests; rp3 was entirely gateway-blocked with
HTTP 403, so role-play results are rp1--rp2 only) \emph{refutes this}:
role-play leaked CoT 16/16 (100\%) and final 16/16 (100\%), and
translation-exfiltration leaked CoT 23/23 (100\%) and final 16/23 (69.6\%).
The E7 ``zero leak'' result was a small-sample artifact---3 repetitions were
insufficient to observe leakage---not a property of the attack modes. Probe texts were authored to cover the full attack surface and were not pre-filtered for
leakability, and the tier assignment ranks leak \emph{volume} rather than leak''',
  r'''classes. The E12 repetition-v2 run shows that appearance was a small-sample
artifact. E12 (te1--te3, rp1--rp2, 8 repetitions each; 39 successful responses
from 48 requests sent, with rp3 entirely gateway-blocked by HTTP 403 and one
further request failing, so role-play results are rp1--rp2 only) found that
role-play leaked CoT 16/16 (100\%) and final 16/16 (100\%), and
translation-exfiltration leaked CoT 23/23 (100\%) and final 16/23 (69.6\%). The
earlier zero-leak result reflected 3 repetitions being insufficient to observe
leakage, not a property of the attack modes. Probe texts were authored to cover
the full attack surface and were not pre-filtered for
leakability, and the tier assignment ranks leak \emph{volume} rather than leak'''),

 # ---- C. AI-smell ----
 (r'This activity masks three measurement gaps that this paper addresses.',
  r'This activity leaves three measurement gaps that this paper addresses.'),
 (r'that single-channel evaluation misleads, in opposite ways.',
  r'that single-channel evaluation reaches opposite conclusions.'),
 (r'''reasoning trace as an asset to be protected or distilled; we treat it as a
measurement surface and report per-channel rates.''',
  r'''reasoning trace as an asset to be protected or distilled; we instead report per-channel rates for it as a measurement surface.'''),
 (r'''bear directly on the design of measurement-based
evaluation;''',
  r'''motivate measurement-based
evaluation;'''),
 (r'''the correlation model remains the appropriate
analytical tool for''',
  r'''the correlation model remains a useful
analytical tool for'''),
 (r'''the consumer could not
reconstruct the masked middle:''',
  r'''the consumer did not
reconstruct the masked middle:'''),
 (r'''not that any deployed
agent will observe that number.''',
  r'''not a number any deployed
agent is expected to realize.'''),
 (r'The model-driven agent wins in both worlds.',
  r'The model-driven agent dominates in both worlds.'),
 (r'Two measured properties merit attention.',
  r'Two measured properties stand out.'),
 (r'''exploitable by an
adaptive adversary, not merely by a fixed probe set.''',
  r'''exploitable by an
adaptive adversary, not only by a fixed probe set.'''),
 (r'separating the channels is enough.',
  r'separating the channels is sufficient.'),
 (r'''measures the strength of the
\emph{reasoning} channel as an attack surface, not the weakness of the defense''',
  r'''quantifies the strength of the
\emph{reasoning} channel as an attack surface rather than any weakness of the
defense'''),
 (r'''this is a weaker requirement, and one that
the evidence supports.''',
  r'''this requirement is weaker and is supported by
the evidence.'''),
 (r'''or whether the
reasoning channel is simply outside their reach.''',
  r'''or whether the
reasoning channel is simply beyond what they observe.'''),
 (r'Real-probe arm confirms the model, not the assumption.',
  r'Real-probe arm confirms the model rather than the assumption.'),
 (r'Two further results deserve emphasis.',
  r'Two further results are notable.'),
 (r'Honeypot instrumentation is the safer forensic design and provides more probative evidence, and the',
  r'Honeypot instrumentation provides more probative evidence, and the'),
 (r'''This is a constraint on independent verification. It does not weaken the
measurements themselves.''',
  r'''This limits independent verification but does not weaken the
measurements themselves.'''),
 (r'''Agentic-system security
more broadly remains an active area~\cite{agentic2025}.''',
  r'''Agentic-system security
more broadly continues to evolve~\cite{agentic2025}.'''),

 # ---- D. non-academic ----
 (r'''vector~\cite{grap2026, bessemer2026, microsoft2026}. These are self-reported
vendor surveys and are cited only as context. The International AI Safety''',
  r'''vector~\cite{grap2026, bessemer2026, microsoft2026}, and these self-reported
vendor surveys are cited only as context. The International AI Safety'''),
 (r'''persist it only after redaction. This is a configuration
control, not a model property, and it is enforceable without changing the model.''',
  r'''persist it only after redaction. This is a configuration control, enforceable
without changing the model.'''),

 # ---- E. abbreviations ----
 (r'through which channel} (CoT only, with the final-answer',
  r'through which channel} (CoT, chain-of-thought, only, with the final-answer'),
 (r'three defense arms: RAW (no defense),',
  r'three defense arms: RAW (the no-defense control; the same configuration is labelled C0 in Table~\ref{tab:reach}),'),
 (r'NVIDIA, 120B-A12B MoE)',
  r'NVIDIA, 120B-A12B MoE, mixture-of-experts; the size notation is total--active parameters in billions)'),
 (r'grouped into four evaluation waves.',
  r'grouped into four evaluation waves (a wave is a coordinated batch of probes targeting one attack layer).'),
 (r'CoT prompting consistently elevates PII leakage in model',
  r'CoT prompting consistently elevates PII (personally identifiable information) leakage in model'),
 (r'extensions such as WMDP for dual-use knowledge',
  r'extensions such as WMDP (Weapons of Mass Destruction Proxy) for dual-use knowledge'),
 (r'alignment methods from RLHF to direct preference optimization',
  r'alignment methods from RLHF (reinforcement learning from human feedback) to direct preference optimization'),
 (r'reaches $\phi=0.30$--$0.75$ with',
  r'reaches $\phi=0.30$--$0.75$ ($\phi$ is the failure-correlation coefficient of~\cite{alotaibi2026}) with'),
 (r'These endpoints, $E_{final}=0$ and $E_{cot}=0.344$',
  r'These consumer-exposure endpoints ($E$ denotes consumer exposure), $E_{final}=0$ and $E_{cot}=0.344$'),
 (r'''and
$v<0$ means the leak worsens.''',
  r'''and
$v<0$ means the leak worsens; formally $v=(r_{base}-r_{new})/r_{base}$, with $r$ the CoT leak rate.'''),
 (r'''$\tau$ partial scrubbing
(retaining the first 11 and last 4 characters, the common production redaction
shape), and D30 sentence suppression each reduced consumer leaks from 11 to 0''',
  r'''$\tau$ partial scrubbing
(retaining the first 11 and last 4 characters, the common production redaction
shape; here $\tau$ denotes the literal-scrub defense at full or partial coverage), and D30 sentence suppression each reduced consumer leaks from 11 to 0'''),
 (r'An output-side filter that detects and',
  r'An output-side filter (D30, our sentence-level output-side filter) that detects and'),
 (r'''`--' means the quantity is
undefined for that mechanism.''',
  r'''`--' means the quantity is
undefined for that mechanism (pp = percentage points).'''),

 # ---- F. text clarifications ----
 (r'the 1.19$\times$ displacement coefficient (the simulated filter sweep of',
  r'the 1.19$\times$ displacement coefficient (the simulated filter sweep described above'),
 (r'far above the 8--12\% measured on the NVIDIA models (M-A 8.3\%, M-C 12.5\%;',
  r'far above the 8--12\% measured on the NVIDIA models (M-A 8.3\%, M-C 12.5\%, both on the second gateway of Section~\ref{sec:e1};'),
 (r'content in only 43.8\% of successful responses (14/32), so its CoT measurements',
  r'content in only 43.8\% of successful responses (14 of the 24 high-tier plus 8 control, 32 total), so its CoT measurements'),
 (r"joint residual of $0.221 \times 0.1513 = 3.34\%$; the model's joint residual at $\rho=0$ is 3.41\%. But",
  r"joint residual of $0.221 \times 0.1513 = 3.34\%$; the model's joint residual at $\rho=0$ is 3.41\% (the 0.07 pp gap is within measurement error of the product). But"),
 (r'''mentioning
\texttt{key\_value}---a string-level false positive that $\tau$ cannot redact (the''',
  r'''mentioning
\texttt{key\_value} (a database field name the model paraphrased)---a string-level false positive that $\tau$ cannot redact (the'''),
 (r'''by a consumer; a calibration parameter, not a measurement) in the calibrated
model, where it predicts a residual of 5.8\% for the adaptive agent).''',
  r'''by a consumer; a calibration parameter, not a measurement) in the calibrated
model, where it predicts a residual of 5.8\% for the adaptive agent (a model-predicted rate, not a measured one).'''),
 (r'large false-positive reduction (agent 0.92\% vs. static baseline 3.0\%),',
  r'large false-positive reduction (agent 0.92\% vs. static baseline 3.0\%; these are false-positive rates, not leak rates),'),
 (r'''but the events are much rarer (13.7\% versus 44.1\% no-defense
leak rate), so observations are dominated by benign outcomes.''',
  r'''but the events are much rarer (13.7\% versus 44.1\% no-defense
leak rate in the calibrated model; these are model-predicted rates, distinct from the directly measured real-model static-arm rate of 0.0\% in Table~\ref{tab:agent}), so observations are dominated by benign outcomes.'''),
 (r'''In the real-calibrated world the
static arm is the no-defense configuration, whose residual negative utility is
observer false-positive cost.\par}''',
  r'''In the real-calibrated world the
static arm is the no-defense configuration, whose residual negative utility is
observer false-positive cost; the oracle's 0.68\% leak exceeds the static arm's 0\% because the static arm sees no attacks in this sample, whereas the oracle actively selects configurations and incurs observer-misclassification leakage---ordering is by utility, not leak rate.\par}'''),
 (r'15 observed CoT leaks (15/28) and a 31-probe tier with none. The benchmark ships',
  r'15 observed CoT leaks (15 of 28 high-tier probe-responses across the three samples) and a 31-probe tier with none. The benchmark ships'),
 (r'''On 32 producer responses (13 of them CoT-positive; a fourth independent
sample, also CoT-only, is pooled into the same 32), the consumer reading the''',
  r'''On 32 producer responses (13 of them CoT-positive; a fourth independent
sample, also CoT-only, is pooled into the same 32; these are the E4 consumer-arm responses, distinct from the 268/103 cohorts of Table~\ref{tab:cohort}), the consumer reading the'''),

 # ---- G. figure captions ----
 (r'''literal redaction ($\tau$), and the
consumer's channel visibility $p_{cot}\in[0,1]$ act after generation.}''',
  r'''literal redaction ($\tau$), input-side rewriting coverage $c\in[0,1]$, and the
consumer's channel visibility $p_{cot}\in[0,1]$ act after generation.}'''),
 (r'shown separately.}',
  r'shown separately (solid = measured curve, dashed = achievable bound, dotted = errata anchor, marked = deployment point).}'),
 (r'''\caption{Output-side filtering displaces rather than removes leakage (simulated world).
CoT-effective, final-effective, and union leak rates are plotted against
output-filter strictness $s$; the $\tau$ countermeasure at $s=1$ and the
irreducible union floor are marked.}''',
  r'''\caption{Output-side filtering displaces rather than removes leakage (simulated world).
The vertical axis is leak rate (\%); CoT-effective, final-effective, and union
leak rates are plotted against output-filter strictness $s$ (3{,}000 probes per
point); the $\tau$ countermeasure at $s=1$ and the
irreducible union floor are marked.}'''),
 (r'''\caption{Per-attack-class CoT leak rates: simulation versus the real model.
Bars give the CoT leak rate for each attack class and are labelled with the
percentage; simulated bars come from the simulated world model, real bars from
the B3 sample ($N=112$ effective attacks).}''',
  r'''\caption{Per-attack-class CoT leak rates: simulation versus the real model.
Bars give the CoT leak rate for each attack class and are labelled with the
percentage; simulated bars come from the simulated world model (no error bars,
being model-generated), real bars from the B3 sample ($N=112$ effective
attacks; Wilson 95\% intervals are in Fig.~\ref{fig:e6ci}).}'''),
 (r'''\caption{Per-class reasoning-channel leak rates and 95\% intervals for B3, E6, and
pooled (B3 and E6 combined). Points show the CoT leak rate by attack class;
horizontal bars show Wilson 95\% intervals; the vertical dashed line marks the
pooled rate.}''',
  r'''\caption{Per-class reasoning-channel leak rates and 95\% intervals for B3, E6, and
pooled (B3 and E6 combined). Points show the CoT leak rate by attack class;
horizontal bars show Wilson 95\% intervals; the vertical dashed line marks the
pooled rate (B3, E6, and pooled are distinguished by point shape: circle, square, triangle).}'''),
 (r'{\raggedright\footnotesize Left: the raw CoT reader recovers secrets in 11 of 13 positive samples, while all three output-side defenses drive exposure to zero (McNemar $p=0.0010$). Right: consumer benefit scales linearly with channel visibility, so a final-only consumer gains nothing.\par}',
  r'{\raggedright\footnotesize Left: the raw CoT reader recovers secrets in 11 of 13 positive samples, while all three output-side defenses drive exposure to zero (paired McNemar exact $p=0.0010$, $n=13$).\par}'),

 # ---- H. table fixes ----
 (r'''\caption{Per-attack-class results on the real model. $n$ is the number of
scorable repeats, at 4 repeats per probe, so $n$ differs across classes only
because they contain different numbers of probes.}''',
  r'''\caption{Per-attack-class results on the real model. $n$ is the number of
scorable repeats, at 4 repeats per probe; the probe counts per class are 4, 4,
2, 4, 4, 5, and 6 (Prefix, Step, Tool, Reasoning, Thinking, SQL, Jailbreak),
giving $n = 16, 16, 8, 16, 16, 20, 24$.}'''),
 (r'All three models show final-channel leak 0/24 (one-sided 95\% upper bound 11.7\% each).\par}',
  r'All three models show final-channel leak 0/24 (one-sided 95\% upper bound 11.7\% each). Per-model 95\% CIs for the CoT rates are plotted in Fig.~\ref{fig:e1cross}.\par}'),
 (r'$\tau$ literal scrub & channel & 8/8 & 100\% & -- \\',
  r'$\tau$ literal scrub & channel & 8/8 & 100\% & 0 \\'),

 # ---- I. references ----
 (r'\emph{arXiv preprint arXiv:2607.22115}, 2026; to appear at ACM SIGMOD 2027.',
  r'\emph{arXiv preprint arXiv:2607.22115}, 2026 (we cite the preprint version; to appear at ACM SIGMOD 2027).'),
 (r'''The theoretical analysis of correlated failure modes
in AI safety techniques further demonstrates that defense in depth provides no
protection when failures are perfectly correlated~\cite{bengio2025}. This''',
  r'''The International AI Safety Report reaches the same conclusion: defense in depth
provides no protection when failures are perfectly correlated~\cite{bengio2025}. This'''),
 (r'ISSN 2755-2721.',
  r'ISSN 2755-2721 (conference paper; the ACE series is the ACM ICEIT proceedings).'),
]

# ---- verify first ----
text = b
fails = []
for i,(old,new) in enumerate(PAIRS):
    if old not in text:
        fails.append(i)
        print("FAIL pair", i)
        print("  OLD:", repr(old[:120]))
    elif text.count(old) > 1:
        print("  WARN pair %d appears %d times (replacing first only)" % (i, text.count(old)))
if fails:
    print("ABORT: %d pair(s) did not match" % len(fails))
    sys.exit(1)

# ---- apply ----
for old,new in PAIRS:
    text = text.replace(old, new, 1)

tmp = PATH + '.tmp'
with io.open(tmp, 'w', encoding='utf-8', newline='') as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("OK: %d pairs applied, %d bytes" % (len(PAIRS), len(text.encode('utf-8'))))
