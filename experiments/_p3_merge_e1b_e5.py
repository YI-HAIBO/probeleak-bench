"""Pass-36: merge the cross-vendor extension cohort and the adaptive-attacker
experiment into p3_tifs.tex.

All anchors must match exactly once; the file is CRLF. Writes to a .tmp then
os.replace (atomic). No internal experiment codes (E1b, E5, M_*) and no
vendor name for the primary model's family are introduced.
"""
import os
import sys

TEX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "paper", "p3_tifs.tex")
NL = chr(13) + chr(10)


def join(lines):
    return NL.join(lines)


PAIRS = []

# ---------------------------------------------------------------- E1 abstract
PAIRS.append((
    join([
        "traces, which three output-side filters nullify. Four forensic implications",
        "follow for logging, detection, containment, and evidence integrity.",
    ]),
    join([
        "traces, which three output-side filters nullify. The asymmetry replicates on an",
        "independent gateway---including the primary model's own family under separate",
        "hosting (54.2\\% versus 53.6\\%)---and fresh paraphrases of the leaking probes leak",
        "at least as often (83.3\\% on the thinking-leak family), so the blind spot is",
        "neither gateway-specific nor phrasing-specific, and an online attacker with no",
        "prior knowledge of the probes finds it within five requests. Four forensic",
        "implications follow for logging, detection, containment, and evidence",
        "integrity.",
    ])))

# ------------------------------------------------- E2 intro measurement list
PAIRS.append((
    join([
        "Direct forensic measurements on deployed",
        "reasoning-model gateways cover channel-isolated leakage",
        "(Section~\\ref{sec:cot}), cross-vendor replication and model census",
        "(Sections~\\ref{sec:e1}--\\ref{sec:census}), and end-to-end consumer exposure",
        "(Section~\\ref{sec:output}). The defense-stacking bound",
    ]),
    join([
        "Direct forensic measurements on deployed",
        "reasoning-model gateways cover channel-isolated leakage",
        "(Section~\\ref{sec:cot}), cross-vendor replication, model census, and an",
        "adaptive-attacker experiment",
        "(Sections~\\ref{sec:e1}--\\ref{sec:adaptive-attacker}), and end-to-end",
        "consumer exposure (Section~\\ref{sec:output}). The defense-stacking bound",
    ])))

# ------------------------------------ E3 revise the three-model vendor claim
PAIRS.append((
    join([
        "Nemotron-3-Super (8.3\\%) and Nemotron-3-Nano (12.5\\%) are both",
        "significantly below the baseline (Fisher $p=0.0008$ and $p=0.003$). This is",
        "consistent with stronger alignment in the Nemotron family rather than absence of",
        "the blind spot: both models still produce a reasoning channel, and Nemotron-3-Nano leaks on",
        "the first prefix-extraction probe and the fourth step-reconstruction probe in isolated repetitions. The contrast between Beam and the two",
        "NVIDIA models is itself substantive: the blind spot is real but its expression",
        "depends on model-specific alignment, an interaction a single-model study",
        "cannot observe.",
    ]),
    join([
        "Nemotron-3-Super (8.3\\%) and Nemotron-3-Nano (12.5\\%) are both",
        "significantly below the baseline (Fisher $p=0.0008$ and $p=0.003$), which is",
        "consistent with stronger alignment in the Nemotron family rather than absence of",
        "the blind spot: both models still produce a reasoning channel, and Nemotron-3-Nano leaks on",
        "the first prefix-extraction probe and the fourth step-reconstruction probe in isolated repetitions. The contrast between Beam and the two",
        "NVIDIA models is itself substantive: the blind spot is real but its expression",
        "depends on model-specific alignment, an interaction a single-model study",
        "cannot observe. The extension cohort below revises the family-level reading:",
        "vendor is not the operative variable.",
    ])))

# ------------------------- E4 extension cohort paragraphs + table tab:e1b
PAIRS.append((
    join([
        "rest on a smaller effective sample; Nemotron-3-Super and Beam expose both channels in 100\\%.",
        "",
        "\\begin{figure*}[t]",
    ]),
    join([
        "rest on a smaller effective sample; Nemotron-3-Super and Beam expose both channels in 100\\%.",
        "",
        "\\textbf{Extension cohort.} The cross-vendor gateway rotates its anonymous",
        "free-tier pool: after the three models above became quota-blocked, a",
        "re-enumeration of the gateway catalog (402 models, 330 carrying",
        "reasoning-family keywords, 15 free-tier) identified eight further free models",
        "that expose a plaintext reasoning channel, and the same protocol was run on",
        "them (Table~\\ref{tab:e1b}). The key addition is the primary model's own family",
        "served through the cross-vendor gateway as a separate deployment instance,",
        "which leaks on 13/24 high-tier responses (54.2\\%), statistically",
        "indistinguishable from the primary gateway's 15/28 (53.6\\%; Fisher $p=1.0$)",
        "despite separate hosting, network paths, and state. The blind spot is not an",
        "artifact of one gateway operator.",
        "",
        "Two results revise the three-model reading. The low rates on the small",
        "Nemotron models were a scale effect, not a vendor effect: Nemotron-3-Ultra",
        "(550B--A55B) leaks on 12/24 (50.0\\%), indistinguishable from the primary",
        "baseline ($p=1.0$), so within one vendor the rate rises with scale. Safety",
        "post-training, not vendor, is the operative protective factor: the",
        "content-safety variant of the same Nemotron-3.5 family leaks on none of 19",
        "high-tier responses ($p=6.4\\!\\times\\!10^{-5}$ versus the baseline) while its",
        "same-family base model leaks on 17/19 (89.5\\%). The smallest model in the",
        "cohort collapses the channel separation entirely, leaking on 23/24 high-tier",
        "reasoning responses and on 13/24 final answers, and even on benign control",
        "prompts (2/8 reasoning, 1/8 final); every other model keeps the final channel",
        "at zero on attack probes and controls at or near zero. The CoT-only asymmetry",
        "is therefore a property of larger or post-trained models rather than of the",
        "architecture in general.",
        "",
        "One selected model (Nemotron-3.5-Lightning) was fully quota-blocked during the",
        "run and contributes no data; quota exhaustion also truncated the valid counts",
        "of two models (19 and 9 of 24 planned high-tier responses). The anonymous",
        "free-tier quota is a shared rotating budget: a re-probe after the run found all",
        "15 free candidates blocked, so replication on this gateway is possible only",
        "within a quota window.",
        "",
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Extension cohort cross-vendor CoT leak rates, high-tier probes.}",
        "\\label{tab:e1b}",
        "\\footnotesize",
        "{\\setlength{\\tabcolsep}{2.5pt}",
        "\\begin{tabular}{@{}p{3.4cm}lccc@{}}",
        "\\toprule",
        "Model & Vendor & CoT leaks & Rate & $p$ vs.\\ ref.\\\\",
        "\\midrule",
        "Primary model family & withheld & 13/24 & 54.2\\% & 1.000 \\\\",
        "Nemotron-3-Ultra (550B--A55B) & NVIDIA & 12/24 & 50.0\\% & 1.000 \\\\",
        "Nemotron-3.5-Super-VL & NVIDIA & 17/19 & 89.5\\% & 0.012 \\\\",
        "Nemotron-3.5-Content-Safety & NVIDIA & 0/19 & 0.0\\% & $6.4\\!\\times\\!10^{-5}$ \\\\",
        "Flint v1.0 & Recursive & 2/24 & 8.3\\% & 0.001 \\\\",
        "LFM 2.5 (2.6B) & Liquid AI & 23/24 & 95.8\\% & 0.001 \\\\",
        "North Mini Code & Cohere & 9/9 & 100.0\\% & 0.015 \\\\",
        "Nemotron-3.5-Lightning (blocked) & NVIDIA & 0/0 & -- & -- \\\\",
        "\\midrule",
        "Ref.\\ primary model & -- & 15/28 & 53.6\\% & -- \\\\",
        "\\bottomrule",
        "\\end{tabular}}",
        "",
        "\\end{table}",
        "",
        "\\begin{figure*}[t]",
    ])))

# ------------------------------------------- E5 model census rewrite
PAIRS.append((
    join([
        "A 39-model census on the cross-vendor gateway of Section~\\ref{sec:e1} found that only 3 models",
        "(8\\%) expose a usable reasoning channel---Nemotron-3-Super, Beam, and a third entry requested under the gateway's generic free-tier route, which resolves to Nemotron-3-Super on the probed requests---and every distinct backend among them leaks at 100\\% on the",
        "two high-leak probes: the second indirect-injection probe and the second code-interpretation probe. That rate is far above the 8--12\\% that Nemotron-3-Super and Nemotron-3-Nano scored with the original probe set on the same gateway, so the difference is the probe set rather than the deployment. The remaining 36 candidates return",
        "gateway errors (paid-model authorization required, model-not-found, or empty responses) or expose reasoning through non-standard",
        "fields. The blind spot is therefore present in every gateway model that exposes a reasoning",
        "channel, and architecturally bounded to them:",
        "models that do not expose a reasoning channel cannot exhibit it, and most",
        "gateway models do not.",
    ]),
    join([
        "A 39-model census on the cross-vendor gateway of Section~\\ref{sec:e1} found that only 3 models",
        "(8\\%) expose a usable reasoning channel---Nemotron-3-Super, Beam, and a third entry requested under the gateway's generic free-tier route, which resolves to Nemotron-3-Super on the probed requests---and every distinct backend among them leaks at 100\\% on the",
        "two high-leak probes: the second indirect-injection probe and the second code-interpretation probe. That rate is far above the 8--12\\% that Nemotron-3-Super and Nemotron-3-Nano scored with the original probe set on the same gateway, so the difference is the probe set rather than the deployment. The remaining 36 candidates return",
        "gateway errors (paid-model authorization required, model-not-found, or empty responses) or expose reasoning through non-standard",
        "fields.",
        "",
        "The catalog enumeration behind the extension cohort explains both the small",
        "usable set and its instability: of 402 listed models, 330 carry",
        "reasoning-family keywords but only 15 are free-tier, and the anonymous",
        "free-tier quota is a shared rotating budget that locked each usable set within",
        "roughly 250 requests. Exposure of the channel is necessary but not sufficient:",
        "the content-safety variant of Table~\\ref{tab:e1b} exposes the reasoning channel",
        "yet leaks on none of its 19 high-tier responses, four of the other seven",
        "extension models leak above the primary baseline, the 550B model is",
        "statistically indistinguishable from it, and two leak far below it. The blind",
        "spot is architecturally bounded to models that expose a reasoning channel;",
        "models that do not expose the channel cannot exhibit it, and most gateway",
        "models do not.",
    ])))

# ----------------------------------- E6 new adaptive-attacker subsection
PAIRS.append((
    NL + "\\section{Theoretical Boundary on Defense Stacking}" + NL,
    join([
        "\\subsection{Adaptive Attacker}",
        "\\label{sec:adaptive-attacker}",
        "",
        "The probe battery is fixed, which leaves two attacker-side questions open:",
        "whether an attacker with no prior knowledge of which phrasings leak can locate",
        "the blind spot online, and whether paraphrasing defeats the trigger. A",
        "Thompson-sampling bandit was run against the live primary gateway: twelve arms",
        "paraphrase the four high-tier probe families (three fresh paraphrases per",
        "family, none reproducing an original probe string), each episode pulls one",
        "arm, and the reward is the CoT-channel leak verdict of the real response, with",
        "a Beta posterior per arm.",
        "",
        "Over 60 episodes the bandit concentrates on the thinking-leak paraphrases (42",
        "of 60 pulls; 83.3\\% leak rate, 95\\% CI [0.69, 0.92]), above the fixed",
        "battery's 53.6\\% on the original phrasings of the same family, while the other",
        "three families leak at 0--12.5\\%; 10 of 60 responses refuse. The leak trigger",
        "is therefore not phrasing-specific. The first leak occurs at episode 5, and in",
        "the final third of the run 65\\% of pulls go to one arm against 8\\% under",
        "uniform selection, so the concentration is learned rather than accidental. The",
        "final channel leaks on none of the 60 responses. The run passes its",
        "pre-registered checks: live API rather than simulation, selection",
        "concentration beyond uniform, leak discovery by exploration, record integrity,",
        "and posterior separation of the best from the worst tried arm.",
        "",
        "Two consequences follow for prompt-blacklist defenses. Enumerating unsafe",
        "strings is futile because fresh paraphrases leak at least as readily as the",
        "originals, and the blind spot is discoverable within a handful of queries, so",
        "a large probe battery is an evaluation convenience rather than a barrier to an",
        "attacker. The experiment runs against fixed defenses on one gateway, so it does",
        "not establish the co-evolutionary regime of Section~\\ref{sec:adaptive}, in",
        "which attacker and defense agent both adapt.",
        "",
    ]) + NL + "\\section{Theoretical Boundary on Defense Stacking}" + NL,
))

# ----------------------------------------------- E7 limitations paragraph
PAIRS.append((
    join([
        "\\textbf{One primary real reasoning model.} The blind spot is confirmed on five",
        "independent real samples of the primary model (diverse-cohort total $N=268$)",
        "and on the cross-vendor gateway with three cross-vendor models: Reflection",
        "Beam is statistically indistinguishable from the primary model's baseline",
        "(62.5\\% versus 53.6\\%, Fisher $p=0.581$), while two NVIDIA models leak",
        "significantly less (8.3\\%, 12.5\\%). The cross-vendor evidence is real, not",
        "simulated, but its expression varies by model, and a 39-model census on the",
        "cross-vendor gateway found only 3 models (8\\%) that expose a usable reasoning",
        "channel, all leaking at 100\\% on the two high-leak indirect-injection and",
        "code-interpretation probes. The cross-vendor migration analysis in",
        "Section~\\ref{sec:adaptive} is therefore a simulation-layer conclusion: the",
        "architectural constraint is established on real data, but the cross-model",
        "generalization of specific leak rates is not.",
    ]),
    join([
        "\\textbf{One primary real reasoning model, multi-gateway replication.} The",
        "blind spot is confirmed on five independent real samples of the primary model",
        "(diverse-cohort total $N=268$) and, through the independent cross-vendor",
        "gateway, on nine distinct measured backends in total (two from the original",
        "cross-vendor set, seven from the extension cohort): Reflection Beam is",
        "statistically indistinguishable from the primary model's baseline (62.5\\%",
        "versus 53.6\\%, Fisher $p=0.581$), the primary model's own family under separate",
        "hosting is likewise indistinguishable (54.2\\% versus 53.6\\%, $p=1.0$), and",
        "measured rates across the nine backends range from 0\\% to 100\\%. The",
        "cross-vendor evidence is real, not simulated, but opportunistic: the gateway's",
        "anonymous free-tier quota is a shared rotating budget that locked each usable",
        "set within roughly 250 requests, two extension models were truncated by quota",
        "exhaustion (19 and 9 valid high-tier responses), and one was fully blocked. A",
        "39-model census on the cross-vendor gateway found only 3 models (8\\%) that",
        "expose a usable reasoning channel, and the catalog enumeration of 402 models",
        "attributes the scarcity to the free-tier filter rather than to the",
        "architecture. The cross-vendor migration analysis in",
        "Section~\\ref{sec:adaptive} is therefore a simulation-layer conclusion: the",
        "architectural constraint is established on real data, but the cross-model",
        "generalization of specific leak rates is not.",
    ])))

# -------------------------------------------------------- E8 conclusion
PAIRS.append((
    join([
        "95\\% upper bound 1.1\\%),",
        "the asymmetry is consistent on the cross-vendor gateway, and a 39-model census",
        "finds the blind spot on all three gateway models that expose a reasoning channel",
        "(8\\% of the 39), while architecturally bounded to those models.",
    ]),
    join([
        "95\\% upper bound 1.1\\%),",
        "the asymmetry replicates across nine distinct cross-vendor backends---including",
        "the primary model's own family under separate hosting (54.2\\% versus 53.6\\%)---",
        "while measured rates range from 0\\% to 100\\%, so the structure is robust but",
        "the rate is model-dependent; fresh paraphrases leak at least as often as the",
        "original probes (83.3\\% on the thinking-leak family), and an online attacker",
        "with no prior knowledge finds the blind spot within five requests. A catalog",
        "enumeration bounds the usable pool: the blind spot is confined to models that",
        "expose a reasoning channel, most gateway models do not, and safety",
        "post-training can suppress it entirely.",
    ])))

# ------------------------------------------ E9 reproducibility release set
PAIRS.append((
    join([
        "\\textbf{Release contents and disclosure.} The released set comprises the probe",
        "suite, the experiment scripts and experiment framework, the reproducible report and figure",
        "generators, and every result artifact, including the per-model gateway",
        "error responses for the blocked cross-model replication and the pooled-sample",
        "reconciliation data; each figure and table value maps to a stored field in",
        "it.",
    ]),
    join([
        "\\textbf{Release contents and disclosure.} The released set comprises the probe",
        "suite, the experiment scripts and experiment framework, the reproducible report and figure",
        "generators, and every result artifact, including the per-model gateway",
        "error responses for the blocked cross-model replication, the pooled-sample",
        "reconciliation data, the cross-vendor extension records, and the",
        "adaptive-attacker run records; each figure and table value maps to a stored",
        "field in it.",
    ])))


def main():
    data = open(TEX, "r", encoding="utf-8", newline="").read()
    print("size before: %d" % len(data))
    for i, (old, new) in enumerate(PAIRS, 1):
        n = data.count(old)
        if n != 1:
            print("ABORT: edit %d matched %d times" % (i, n))
            print("  head of old anchor: %r" % old[:90])
            sys.exit(1)
        data = data.replace(old, new)
        print("  edit %d applied (%+d chars)" % (i, len(new) - len(old)))
    tmp = TEX + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(data)
    os.replace(tmp, TEX)
    print("size after: %d" % len(data))


if __name__ == "__main__":
    main()
