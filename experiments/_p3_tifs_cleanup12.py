# -*- coding: utf-8 -*-
"""Pass-12: sixth-round review fixes (verify-then-apply, atomic write).
Sections: A hard errors (3), B terminology/logic (12), C abbreviations (3),
D table footnote (1), E self-deprecation dedup (5).
"""
import io, os, sys

PATH = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'

PAIRS = []

def add(tag, old, new):
    PAIRS.append((tag, old, new))

# ================= A. Hard errors =================

# A1. census gateway attribution + third model name + error forms + probe ids
add('A1 census gateway',
    'A 39-model census on the production gateway (E1-v2) found that only 3 models\n'
    '(8\\%) expose a usable reasoning channel, but all three leak at 100\\% on the\n'
    'high-leak indirect-injection probes---far above the 8--12\\% measured on the NVIDIA models (M-A 8.3\\%, M-C 12.5\\%; both on the second gateway of\n'
    'Section~\\ref{sec:e1}, with the original probe set). The remaining 36 candidates return\n'
    'gateway errors (model not configured) or expose reasoning through non-standard\n'
    'fields.',
    'A 39-model census on the second gateway of Section~\\ref{sec:e1} (E1-v2) found that only 3 models\n'
    '(8\\%) expose a usable reasoning channel---M-A, M-B, and a third open-router entry (\\texttt{openrouter/free})---but all three leak at 100\\% on the\n'
    'two high-leak probes ii2 and ci2. That rate is far above the 8--12\\% that M-A and M-C scored with the original probe set on the same gateway, so the difference is the probe set rather than the deployment. The remaining 36 candidates return\n'
    'gateway errors (HTTP 401 paid-model authorization required, HTTP 404 model-not-found, or empty responses) or expose reasoning through non-standard\n'
    'fields.')

# A2. E4 producer responses ARE in the diverse 268 cohort
add('A2 E4 cohort attribution',
    'sample, also CoT-only, is pooled into the same 32; these are the E4 consumer-arm responses, distinct from the 268/103 cohorts of Table~\\ref{tab:cohort}), the consumer reading the',
    'sample, also CoT-only, is pooled into the same 32; these E4 producer responses are part of the diverse cohort ($N=268$) of Table~\\ref{tab:cohort}, and the consumer-stage verdicts below are a separate measurement stage), the consumer reading the')

# A3. in-section self reference inside sec:output
add('A3 self-reference',
    'zero magnitude---in the simulated sweep the final-answer rate rises from 25.5\\% to 30.33\\%\n'
    '(Section~\\ref{sec:output}), and that inflation has no real-model counterpart.',
    'zero magnitude---in the simulated sweep the final-answer rate rises from 25.5\\% to 30.33\\%, and that inflation has no real-model counterpart.')

# ================= B. Terminology / logic =================

# B1/B2. framework gate G1 -> Gate I (isolation), distinct from per-experiment g1--g4
add('B1 Gate I def',
    'must hold for a measurement to be considered valid: G1 asserts that',
    'must hold for a measurement to be considered valid: Gate I (isolation) asserts that')
add('B2 Gate I use',
    '\\textbf{Channel isolation is verified, not assumed.} Gate G1 asserts that',
    '\\textbf{Channel isolation is verified, not assumed.} Gate I (isolation) asserts that')

# B3. tau/key_value since-clause contradicted the tau definition (tau redacts the final answer)
add('B3 tau key_value logic',
    '\\texttt{key\\_value} (a database field name the model paraphrased)---a string-level false positive that $\\tau$ cannot redact (the\n'
    'judge flags the mention, but no credential was emitted)\n'
    'since it appears in the final answer rather than in reasoning. The D30 arm',
    '\\texttt{key\\_value} (a database field name the model paraphrased)---a string-level false positive that $\\tau$ cannot redact, since $\\tau$\n'
    'matches verbatim credential strings and the refusal text contains none\n'
    '(the judge flags the mention, but no credential was emitted). The D30 arm')

# B4. calibrated world is simulated: not "measured"
add('B4 calibrated not measured',
    'Measured residual leakage in the calibrated world is therefore primarily attributable to classifier confusion,',
    'Residual leakage in the calibrated world is therefore primarily attributable to classifier confusion,')

# B5. dangling "shown here only as a reference point"
add('B5 v=0.55 anchor',
    'independent measurement; it is shown here only as a reference point.',
    'independent measurement; it is the value the real-probe arm below tests against.')

# B6. probe identifiers: keep the notation promise
add('B6 probe id promise',
    'interpretation), and re (refusal cliff)---are expanded where first used.',
    'interpretation), and re (refusal cliff)---are class codes; a trailing index selects the individual probe (te1 is the first translation-exfiltration probe), and this form is used throughout.')

# B7. budget scale must be matchable to this paper's experiments
add('B7 budget scale',
    '(a wave is a coordinated batch of probes targeting one attack layer). Per-experiment budgets\n'
    'range from 1{,}000 to millions of probes; the largest grid analysis runs\n'
    '840{,}000 grid probes plus 2{,}000{,}000 validation probes. The',
    '(a wave is a coordinated batch of probes targeting one attack layer). Per-experiment budgets in the broader research program\n'
    'range from 1{,}000 to millions of probes; the experiments reported in this paper are far smaller---tens to a few hundred requests per arm---and every reported number traces to a released JSON artifact. The')

# B8. tier denominators: tiers span the 35 records
add('B8 tier denominators',
    'pooled leak rate rather than from intuition: a 4-probe high tier carrying all\n'
    '15 observed CoT leaks (15 of 28 high-tier probe-responses: the four classes\n'
    're-run across the three samples) and a 31-probe tier with none.',
    'pooled leak rate rather than from intuition: a 4-probe high tier (4 of the 35 records) carrying all\n'
    '15 observed CoT leaks (15 of 28 high-tier probe-responses, the four high-tier probes\n'
    're-run across the three samples) and a 31-probe tier with none (0 of 168).')

# B9. mapping among the four probe groupings (11 modes / 5 classes / 7 table rows / 5 fig classes)
add('B9 grouping map',
    "\\emph{thinking leak} (direct appeals to the model's own reasoning trace).",
    "\\emph{thinking leak} (direct appeals to the model's own reasoning trace). The 11 modes of the released library are these five classes plus six protocol variants (direct SQL, union SQL, error SQL, split-channel, jailbreak, and encoding); Table~\\ref{tab:permode} aggregates them into seven rows and Fig.~\\ref{fig:simvsreal} compares the five credential-extraction classes.")

# B10. M-A triple-clause sentence
add('B10 M-A sentence',
    'M-A \\emph{nvidia/nemotron-3-super-120b-a12b} (NVIDIA, 120B-A12B MoE, mixture-of-experts; the size notation is total--active parameters in billions),',
    'M-A \\emph{nvidia/nemotron-3-super-120b-a12b} (NVIDIA, 120B-A12B mixture-of-experts, MoE; sizes give total--active parameters in billions),')

# B11. Fig 7 footnote duplicates the caption's right-panel statement
add('B11 fig7 footnote',
    '{\\raggedright\\footnotesize Left: the raw CoT reader recovers secrets in 11 of 13 positive samples, while all three output-side defenses drive exposure to zero (paired McNemar exact $p=0.0010$, $n=13$). Right: consumer exposure grows linearly with channel visibility $p_{cot}$.\\par}',
    '{\\raggedright\\footnotesize The raw CoT reader recovers secrets in 11 of 13 positive samples, while all three output-side defenses drive exposure to zero (paired McNemar exact $p=0.0010$, $n=13$).\\par}')

# B12. "more probative evidence" lacked a comparison object
add('B12 probative antecedent',
    'Honeypot instrumentation provides more probative evidence, and the',
    'Honeypot instrumentation provides more probative evidence than real-credential findings, and the')

# ================= C. Abbreviations =================

# C1. LLM first use
add('C1 LLM expand',
    'LLM agents now mediate database access in production, yet evaluations treat the',
    'Large language model (LLM) agents now mediate database access in production, yet evaluations treat the')

# C2. Wald first use
add('C2 Wald expand',
    'sample: the rate difference is $+1.19$ percentage points with a Wald 95\\% CI of',
    'sample: the rate difference is $+1.19$ percentage points with a Wald (normal-approximation) 95\\% CI of')

# C3a/C3b. pp -> percentage points (two uses)
add('C3a pp gap',
    '(the 0.07 pp gap is within measurement error of the product)',
    '(the 0.07 percentage-point gap is within measurement error of the product)')

# ================= D. Table VI footnote =================

# D1. tau and C0 both read 0% in Final-only for different reasons; 5.4pp -> percentage points
add('D1 tab:reach footnote',
    'real post-hoc measurement; the other rows are simulated-world scores. The D30\n'
    'entry is negative because displacement raises the final rate by 5.4pp; a',
    'real post-hoc measurement; the other rows are simulated-world scores. The $\\tau$ and C0 rows both read 0\\% in the Final-only column for different reasons: $\\tau$ found no final-answer hits to remove (the real final baseline is zero), while C0 applies no mechanism and so reduces nothing. The D30\n'
    'entry is negative because displacement raises the final rate by 5.4 percentage points; a')

# ================= E. Self-deprecation dedup =================

# E1. third statement of the byte-exact constraint -> cross-reference Limitations
add('E1 reproducibility dedup',
    'The real-model experiments target a third-party hosted gateway;\n'
    'the request scripts and full response artifacts are released, but the gateway\n'
    'credential is not, so byte-exact re-execution against that gateway is not\n'
    'possible.',
    'The real-model experiments target a third-party hosted gateway;\n'
    'the request scripts and full response artifacts are released, while the\n'
    'credential constraint on byte-exact re-execution is described in\n'
    'Section~\\ref{sec:limitations}.')

# E2. conclusion states the aggressive/public-benchmark regime twice
add('E2 conclusion dedup',
    'requires channel-complete scanning when the final channel itself leaks, as\n'
    'on aggressive and public-benchmark probes. In both regimes the reasoning channel should be treated as an artifact of logging rather than of',
    'requires channel-complete scanning when the final channel itself leaks.\n'
    'In both regimes the reasoning channel should be treated as an artifact of logging rather than of')

# E3. defensive closer in Limitations
add('E3 limitations closer',
    'gateway operator was informed before submission. This limits independent verification but does not weaken the\n'
    'measurements themselves.',
    'gateway operator was informed before submission.')

# E4. three orphan recomputation numbers nobody can locate
add('E4 orphan recomputation',
    'Three successive naive recomputations of this\n'
    'one statistic disagreed---149/491 = 30.3\\%, 77/220 = 35.0\\%, and 115/324 =\n'
    '35.5\\%---because each applied a different record filter: per-sample counts\n'
    'include only attack-kind traffic, whereas the naive scans also counted benign,\n'
    'negative-control, and ablation records; in addition E10 stores the reasoning\n'
    'leak in \\texttt{reasoning\\_leak} rather than \\texttt{cot\\_leak}. None of the\n'
    'three reconciles with the underlying records, and none of the three is\n'
    'reported anywhere else in this paper. Re-deriving the statistic from source\n'
    'with an explicit, documented filter yields Table~\\ref{tab:cohort}.',
    'Three successive naive recomputations of this\n'
    'one statistic disagreed by up to 5.2 percentage points because each applied a different record filter: per-sample counts\n'
    'include only attack-kind traffic, whereas the naive scans also counted benign,\n'
    'negative-control, and ablation records; in addition E10 stores the reasoning\n'
    'leak in \\texttt{reasoning\\_leak} rather than \\texttt{cot\\_leak}. None of the\n'
    'naive variants reconciles with the underlying records, and none is\n'
    'reported in this paper. Re-deriving the statistic from source\n'
    'with an explicit, documented filter yields Table~\\ref{tab:cohort}.')

# E5. transfer rates that appear in no table or figure
add('E5 orphan transfer rates',
    'cross-vendor transfer rates measured in simulation (47.7--55.4\\% over six\n'
    'simulated vendors; these rates appear in no table or figure of this paper and\n'
    'enter no downstream calculation) remain clearly labeled as simulation-only; the same',
    'cross-vendor transfer rates measured in simulation over six simulated vendors\n'
    'remain clearly labeled as simulation-only; the same')

# E6. census probe naming in Limitations (consistency with A1)
add('E6 census probes in limitations',
    'A 39-model census found only 3 models (8\\%) expose a\n'
    '      usable reasoning channel, all three leaking at 100\\% on high-leak\n'
    '      indirect-injection probes---a rate far above the 8--12\\% measured with the',
    'A 39-model census on the second gateway (E1-v2) found only 3 models (8\\%) expose a\n'
    '      usable reasoning channel, all three leaking at 100\\% on the two\n'
    '      high-leak probes ii2 and ci2---a rate far above the 8--12\\% measured with the')


def main():
    text = io.open(PATH, encoding='utf-8').read()
    fails = []
    for i, (tag, old, new) in enumerate(PAIRS):
        if old not in text:
            fails.append(i)
            print('FAIL pair %d [%s]' % (i, tag))
            print('  OLD:', repr(old[:150]))
        elif text.count(old) > 1:
            fails.append(i)
            print('FAIL pair %d [%s] matches %d times' % (i, tag, text.count(old)))
    if fails:
        print('ABORT: %d pair(s) did not match' % len(fails))
        sys.exit(1)
    for tag, old, new in PAIRS:
        text = text.replace(old, new, 1)
    tmp = PATH + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8', newline='') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, PATH)
    print('OK: %d pairs applied' % len(PAIRS))

if __name__ == '__main__':
    main()
