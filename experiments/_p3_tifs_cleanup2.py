# -*- coding: utf-8 -*-
"""Second cleanup pass on p3_tifs.tex: reader-confusion fixes + residual AI-smell.

Pairs verified against the post-pass-1 text. Same regex-verify-then-atomic-write
discipline as _p3_tifs_cleanup.py; aborts on any mismatch so the file is never
partially modified.
"""
import os, re, sys

PATH = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

with open(PATH, "r", encoding="utf-8") as f:
    text = f.read()

def to_regex(s):
    parts = re.split(r"\s+", s)
    return r"\s+".join(re.escape(p) for p in parts)

PAIRS = [
# ---- F1: verified factual error -- G4 gate says n_probes=30, n_inconsistent=3
#          => 27/30 = 90.0%, not 89.3% (source: p1_real_scale_validation_v1.json)
("3 of 30 probes inconsistent, 89.3\\% consistency",
 "3 of 30 probes inconsistent, 90.0\\% consistency (27/30; source: p1\\_real\\_scale\\_validation\\_v1.json)"),

# ---- F2: conclusion grammar -- "is bimodal because X, and that Y" is ungrammatical
("""The pooled rate (38.27\\%) is bimodal because repetition and stress runs re-execute
known-leaking probes, and that the final channel does leak on aggressive and
public-benchmark probes (62.5--100\\%)""",
"""The pooled rate (38.27\\%) is bimodal because repetition and stress runs re-execute
known-leaking probes; moreover, the final channel does leak on aggressive and
public-benchmark probes (62.5--100\\%)"""),

# ---- G1: "figure below" with no figure
("though the 88\\% figure below comes from vendor surveys",
 "though the 88\\% figure comes from vendor surveys"),

# ---- G2: forward reference without section pointer
("exceeds the attainable range by\n1.70$\\times$, and the measured two-layer",
 "exceeds the attainable range by\n1.70$\\times$ (see Section~\\ref{sec:corr}), and the measured two-layer"),

# ---- G3: 15/28 undefined
("dots3-note-prev high-tier pooled estimate (15/28,\n53.6\\%) as the baseline",
 "dots3-note-prev high-tier pooled estimate (15/28, where 28 is the total\nhigh-tier probe-responses; 53.6\\%) as the baseline"),

# ---- G4: extra requests unexplained
("B3 ($N=112$ from 157 requests; 33 probes at 4 repeats),\nincluding an arm testing a prompt-level self-check",
 "B3 ($N=112$ from 157 requests; 33 probes at 4 repeats, the extra 25\nrequests coming from a prompt-level self-check arm),"),

# ---- G5: upper-bound method not stated
("one-sided 95\\% upper bounds 11.3\\%, 2.6\\%, and 3.5\\%)",
 "one-sided 95\\% upper bounds 11.3\\%, 2.6\\%, and 3.5\\% (Jeffreys prior,\nBeta(0.5, 0.5))"),

# ---- G6: three classes not named in text
("the simulation overestimates the three classes that leaked at all by 7.8$\\times$, 6.9$\\times$,\nand 1.6$\\times$",
 "the simulation overestimates the three classes that leaked at all---thinking leak,\nprefix extraction, and step reconstruction---by 7.8$\\times$, 6.9$\\times$, and 1.6$\\times$"),

# ---- G7: control probe repetitions unspecified
("with six repetitions each (24 requests per model) plus eight control probes:",
 "with six repetitions each (24 requests per model) plus eight control probes at\none repetition each:"),

# ---- G8: shared-blindspot model needs intuition before the technical definition
("We model correlation with a\nshared-blindspot mixture: with probability $\\rho$ every layer's failure is\nbound to a single per-probe Bernoulli (layers fail together), and with\nprobability $1-\\rho$ layers fail independently.",
 "We model correlation with a shared-blindspot mixture: on each probe, with\nprobability $\\rho$ every layer's failure is bound to a single Bernoulli (so\nlayers fail together), and with probability $1-\\rho$ layers fail independently."),

# ---- G9: "at the head level" unclear
("all observed leaks are verbatim enumerations at the head level;",
 "all observed leaks are verbatim key enumerations appearing at the head of the\nreasoning trace;"),

# ---- G10: E10 leaks are string-level false positives, not credential emission
("the final leaks were not verbatim credential strings but the model's own refusal text mentioning\n\\texttt{key\\_value}---a string-level false positive that $\\tau$ cannot redact",
 "the final leaks were not verbatim credential strings but the model's own refusal text mentioning\n\\texttt{key\\_value}---a string-level false positive that $\\tau$ cannot redact (the\njudge flags the mention, but no credential was emitted)"),

# ---- G11: "reverse-effective" undefined
("configuration is labeled reverse-effective.",
 "configuration is labeled \\emph{reverse-effective} (it removes refusals while\nleaving CoT leakage unchanged)."),

# ---- G12: "fourth independent sample" unclear
("On 32 producer responses (13 of them CoT-positive; a fourth\nindependent sample again leaked only through CoT),",
 "On 32 producer responses (13 of them CoT-positive; a fourth independent\nsample, also CoT-only, is pooled into the same 32),"),

# ---- G13: static best single has 0% leak but negative utility -- explain
("Static best single & $-0.1314$ (24.4\\%) & $-0.0294$ (0.0\\%) \\\\",
 "Static best single & $-0.1314$ (24.4\\%) & $-0.0294$ (0.0\\%, the no-defense\nconfiguration; its negative utility is observer false-positive cost) \\\\"),

# ---- G14: "map onto" unclear
("We map each paradigm onto the eight real CoT-only leak events",
 "We evaluate each paradigm against the eight real CoT-only leak events"),

# ---- G15: compressed sentence about PCC-SQL reach
("scored on the union of channels it reaches 0/8 on the real events, whereas a final-only metric",
 "scored on the union metric it reaches 0 of the 8 real events (they live in the reasoning\nchannel), whereas a final-only metric"),

# ---- G16: baseline denominator 24 unexplained
("21 requests; 18\naccepted, of which 15 are attack-kind and 3 benign). Against the same-probe\nbaseline the CoT leak rate did not fall:",
 "21 requests; 18\naccepted, of which 15 are attack-kind and 3 benign). Against the same-probe\nbaseline (24 probe-responses) the CoT leak rate did not fall:"),

# ---- G17: tl1/tl4 baseline rates missing
("tl1 (thinking leak) $v=0.00$---the leak persists at 100\\%---and\ntl4 (thinking leak) $v=-1.00$---the leak doubles from 50\\% to 100\\%---while",
 "tl1 (thinking leak) $v=0.00$---the leak persists at 100\\% (unchanged from the\nbaseline)---and tl4 (thinking leak) $v=-1.00$---the leak doubles from 50\\% to\n100\\%---while"),

# ---- A1: "consistent with the possibility that" double hedge
("our finding that the\nfinal-answer channel can be clean is consistent with the possibility that such\ncontrols close it.",
 "our finding that the\nfinal-answer channel can be clean is consistent with such controls closing it."),

# ---- A2: "anchored to"
("a result that holds within the calibrated model, anchored to real leak\nrates rather than to measured throughput.",
 "a result that holds within the calibrated model, whose parameters are set from real leak\nrates rather than from measured throughput."),

# ---- A3: "We provide a calibrated, margin-consistent quantification"
("We provide a calibrated,\nmargin-consistent quantification: the achievable inflation is 4.48$\\times$ for",
 "We quantify the achievable inflation under a margin-consistent coupling: the inflation is\n4.48$\\times$ for"),

# ---- A4: "the binding constraint is cost" (actual text: "the stack collapses ...")
("the stack collapses to the stronger layer's residual, and the\nbinding constraint is cost.",
 "the stack collapses to the stronger layer's residual, and cost, not correlation, is what\nlimits the benefit of stacking."),

# ---- A5: "Our contribution is orthogonal"
("Our contribution is\northogonal to all of these: rather than asking whether reasoning leaks, we",
 "This work is orthogonal to these lines: rather than asking whether reasoning leaks, we"),

# ---- A6: "frame" as verb
("and autonomous-agent surveys frame the tool-using agent stack our threat model targets~\\cite{agentsurvey}.",
 "and autonomous-agent surveys describe the tool-using agent stack our threat model targets~\\cite{agentsurvey}."),

# ---- A7: "fit from prior experiments" vague
("The \\emph{simulated} world is a calibrated\nstochastic LLM (temperature 0.1) whose per-class leak rates were fit from prior experiments.",
 "The \\emph{simulated} world is a calibrated\nstochastic LLM (temperature 0.1) whose per-class leak rates were estimated from the campaigns of Section~\\ref{sec:cot}."),

# ---- A8: "appeared to refute"
("An earlier expansion (E7) appeared to refute the\ncherry-picking concern:",
 "An earlier expansion (E7) seemed to refute the concern that the probe set was\nselective:"),

# ---- A9: "are strengthened"
("Two findings are strengthened: the CoT-native blind spot is not an artifact of probe selection",
 "Two conclusions are supported: the CoT-native blind spot is not an artifact of probe selection"),

# ---- A10: "worth drawing"
("The contrast worth drawing is that no class except thinking leak is non-trivially high",
 "The important contrast is that no class except thinking leak is non-trivially high"),

# ---- A11: "is itself a finding" (separate from the 89.3% fix above)
("\\textbf{Reproducibility is itself a finding.} A gate asserting identical",
 "\\textbf{Reproducibility failure is itself a result.} A gate asserting identical"),

# ---- A12: "matters substantively"
("The split matters substantively. The \\emph{diverse-probe cohort}",
 "The split changes the conclusion. The \\emph{diverse-probe cohort}"),

# ---- A13: rhetorical question in worst-case framing
("The model's purpose is to establish the \\emph{worst case} for\nstacking---if correlation saturates, how much of the product-law benefit\nsurvives?---and the real defenses",
 "The model establishes the \\emph{worst case} for stacking: if correlation saturates, the product-law\nbenefit is reduced to the stronger layer's residual---and the real defenses"),

# ---- A14: "strictly more effective"
("The real defenses are strictly more effective than the simulation's conservative priors assume, and the",
 "The real defenses appear more effective than the simulation's conservative priors assume, and the"),

# ---- A15: "no displacement space"
("because the final baseline is zero there is \\emph{no displacement\nspace}---the 1.19$\\times$ displacement coefficient measured in simulation has no",
 "because the final baseline is zero the displacement effect has zero magnitude---the 1.19$\\times$\ndisplacement coefficient measured in simulation has no"),

# ---- A16: "puts to a real test"
("This puts the displacement argument to a real test: when the final channel leaks",
 "This is a direct test of the displacement argument: when the final channel leaks"),

# ---- A17: "outruns"
("($-0.0061$), because\nexploration cost outruns the benefit on rare events.",
 "($-0.0061$), because\nexploration cost exceeds the benefit on rare events."),

# ---- A18: "confirms" -> "supports" (consumer channel)
("This confirms the consumer-channel prediction on real data, and it is consistent",
 "This supports the consumer-channel prediction on real data, and it is consistent"),

# ---- A19: "does not settle"
("the agent's utility falls to $-0.0352$\n(leak 3.17\\%) and the attack mix does not settle to a fixed distribution.",
 "the agent's utility falls to $-0.0352$\n(leak 3.17\\%) and the attack mix does not converge to a fixed distribution."),

# ---- A20: "deserve emphasis"
("\\textbf{Two measured properties deserve emphasis.} First, the agent's higher leak",
 "\\textbf{Two measured properties merit attention.} First, the agent's higher leak"),

# ---- A21: "dominated by"
("Measured residual leakage in the calibrated world is therefore dominated by classifier confusion,",
 "Measured residual leakage in the calibrated world is therefore primarily attributable to classifier confusion,"),

# ---- A22: "confirms" -> "suggests" (E8 adaptive attacker)
("confirms that the CoT blind spot is exploitable by an\nadaptive adversary, not merely by a fixed probe set.",
 "suggests that the CoT blind spot is exploitable by an\nadaptive adversary, not merely by a fixed probe set."),

# ---- A23: "The interaction is the core finding:"
("The interaction is the core finding: the defense does not need to block the attack at the reasoning channel itself",
 "The defense does not need to block the attack at the reasoning channel itself"),

# ---- A24: "holds" -> "works"
("the defense holds by keeping the credential from crossing from reasoning into the",
 "the defense works by keeping the credential from crossing from reasoning into the"),

# ---- A25: "misleads in both directions"
("The single-channel metric misleads in both\ndirections: applied to D30 it judges the filter harmful",
 "The single-channel metric gives misleading answers in both\ndirections: applied to D30 it judges the filter harmful"),

# ---- A26: "structurally blind"
("production-side paradigms defend the final-answer and prompt layers but are structurally blind to\nthe reasoning channel, where the CoT-native blind spot lives.",
 "production-side paradigms defend the final-answer and prompt layers but cannot reach the\nreasoning channel, where the CoT-native blind spot lives."),

# ---- A27: "the only channel" overclaim
("The reasoning channel is therefore outside the reach of\nproduction-side defenses, and it is the only channel in which an adaptive\ndefender can find a usable signal.",
 "The reasoning channel is therefore outside the reach of\nproduction-side defenses, and it is the only channel in which an adaptive\ndefender can find a usable signal in our threat model."),

# ---- A28: "should transfer" unverified
("its calibration should transfer to other secret sets because the match rule is literal",
 "its calibration is likely to transfer to other secret sets because the match rule is literal"),

# ---- A29: "both the safer forensic design and the more probative one"
("Honeypot instrumentation is both the safer forensic design and the more probative one, and the",
 "Honeypot instrumentation is the safer forensic design and provides more probative evidence, and the"),

# ---- A30: "supports reliable attribution"
("measured zero false-positive behavior of the literal judge supports reliable\nattribution.",
 "measured zero false-positive behavior of the literal judge is a necessary condition for reliable\nattribution."),

# ---- A31: "the only adaptable signal lives"
("are structurally blind to the reasoning channel, which is where the only adaptable signal lives.",
 "are structurally blind to the reasoning channel, which is the only channel in which an adaptive\ndefender finds a signal in our threat model."),
]

errors = []
for i, (old, new) in enumerate(PAIRS, 1):
    pat = re.compile(to_regex(old))
    hits = pat.findall(text)
    if len(hits) != 1:
        errors.append("pair %d: regex found %d matches (need 1):\nOLD:\n%s" % (i, len(hits), old[:300]))
        continue
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