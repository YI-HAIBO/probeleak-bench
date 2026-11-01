"""Pass-35: P1+P2 fixes for p3_tifs.tex (atomic: count==1 per pair, tmp + os.replace).

CRLF file: multi-line old strings use \r\n.
Verified against JSON truth:
  - 15/28 = four high-tier probes (tl1, tl4, pe1, sr4) x 7 pooled reps (second+third samples);
    diverse cohort 39/268 = 15 + 5 (first sample) + 6 (E2b) + 13 (E4), all on the same four probes.
  - census third usable entry = openrouter/free -> resolves to nemotron-3-super on probed requests.
Links verified 2026-10-24: bvp.com/atlas full slug (200), learn.microsoft.com sfi/manage-agentic-risk (200),
  genai.owasp.org/llm-top-10/ (200); owasp.org/www-project... (404) and the old Microsoft URL (404) replaced.
"""
import os, sys

P = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'

EDITS = [
    # 3-1 (P2) pentesting -> penetration-testing
    (b"calls against operational databases, and pentesting tools now use multi-agent LLMs",
     b"calls against operational databases, and penetration-testing tools now use multi-agent LLMs"),
    # 2-5 (P2) drop the doubled hedge on industry surveys
    (b"vector~\\cite{grap2026, bessemer2026, microsoft2026}, and these self-reported\r\n"
     b"vendor surveys are cited only as context. The International AI Safety",
     b"vector~\\cite{grap2026, bessemer2026, microsoft2026}. The International AI Safety"),
    # 1-6 (P1) attribute the 7.63x figure in the introduction
    (b"      deployment measurement: the model's inflation bound is 4.48$\\times$, a\r\n"
     b"      previously reported 7.63$\\times$ gap exceeds the attainable range by\r\n"
     b"1.70$\\times$ (see Section~\\ref{sec:corr});",
     b"      deployment measurement: the model's inflation bound is 4.48$\\times$. An\r\n"
     b"      earlier cascade experiment with the same model reported a 7.63$\\times$ gap\r\n"
     b"      that exceeds the attainable range by 1.70$\\times$ (see Section~\\ref{sec:corr});"),
    # 2-6a (P2) "reported as such" #1
    (b"deployment shape rather than evidence against the claim; every failure below is\r\n"
     b"reported as such.",
     b"deployment shape rather than evidence against the claim; every failure below is\r\n"
     b"reported in that form."),
    # 1-5 / 14-2 (P1) leak-count denominator: 15 vs 39
    (b"pooled leak rate rather than from intuition: a 4-probe high tier (4 of the 35 records) carrying all\r\n"
     b"15 observed CoT leaks (15 of 28 high-tier probe-responses, the four high-tier probes\r\n"
     b"re-run across the three samples) and a 31-probe tier with none (0 of 168).",
     b"pooled leak rate rather than from intuition: a 4-probe high tier (4 of the 35 records) that carries\r\n"
     b"every CoT leak observed in the second and third samples (15 of 28 high-tier\r\n"
     b"probe-responses there, four probes over seven repetitions each) and a 31-probe\r\n"
     b"tier with none (0 of 168). The leaks counted in the diverse-probe cohort of\r\n"
     b"Section~\\ref{sec:cot} (39 of 268 across five campaigns) add the first sample, the\r\n"
     b"schema-hiding arm, and the consumer arm, and every one of them falls on the same\r\n"
     b"four probes."),
    # 1-7a / 2-1 / 3-2 (P1) "headline claim"
    (b"1.1\\%); this is the point estimate we report for the native blind spot and the basis for the headline claim. The",
     b"1.1\\%); this is the point estimate reported for the native blind spot throughout the paper. The"),
    # 2-2 / 5-4 (P1) pre-emptive criticism sentence
    (b"All evidence above comes from a single model, which is the most frequent\r\n"
     b"criticism of the native-blind-spot claim. The measurement was therefore replicated",
     b"All evidence above comes from a single model, so the measurement was\r\n"
     b"replicated"),
    # 2-4 (P2) emphatic "precisely the interaction"
    (b"depends on model-specific alignment, which is precisely the interaction a\r\n"
     b"single-model study cannot observe.",
     b"depends on model-specific alignment, an interaction a single-model study\r\n"
     b"cannot observe."),
    # 1-9 (P2) name the third census entry and its resolution
    (b"(8\\%) expose a usable reasoning channel---Nemotron-3-Super, Beam, and a third open-router entry---"
     b"but all three leak at 100\\% on the",
     b"(8\\%) expose a usable reasoning channel---Nemotron-3-Super, Beam, and a third entry requested "
     b"under the gateway's generic free-tier route, which resolves to Nemotron-3-Super on the probed "
     b"requests---and every distinct backend among them leaks at 100\\% on the"),
    # 2-3 (P2) emphatic "This is a direct test of"
    (b"reasoning trace, contains no credential. This is a direct test of the displacement argument: "
     b"when the final channel leaks, suppressing the reasoning channel eliminates the leak source, "
     b"but redacting the final answer alone does not. The stress-test reduction gate did not",
     b"reasoning trace, contains no credential. These two arms test the displacement argument: "
     b"when the final channel leaks, suppressing the reasoning channel eliminates the leak source, "
     b"whereas redacting the final answer alone does not. The stress-test reduction gate did not"),
    # 2-6b (P2) "reported as such" #2
    (b"hold ($\\tau$ shows zero reduction on this probe set) and is reported as such: $\\tau$ is effective against verbatim",
     b"hold ($\\tau$ shows zero reduction on this probe set): $\\tau$ is effective against verbatim"),
    # 1-8a (P1) consumer long sentence: strip the membership parens
    (b"sample, also CoT-only, is pooled into the same 32; these consumer-arm responses are part of the "
     b"diverse cohort ($N=268$) of Table~\\ref{tab:cohort}, and the consumer-stage verdicts below are a "
     b"separate measurement stage), the consumer reading the",
     b"sample, also CoT-only, is pooled into the same 32), the consumer reading the"),
    # 1-8b (P1) ...and state the membership as its own sentence
    (b"honeypot keys (up to all 15). These endpoints, $E_{final}=0$ and $E_{cot}=0.344$ ($E$ denotes consumer",
     b"honeypot keys (up to all 15). The 32 consumer-arm responses are part of the\r\n"
     b"diverse cohort ($N=268$) of Table~\\ref{tab:cohort}, and the consumer-stage\r\n"
     b"verdicts below are a separate measurement stage. These endpoints, $E_{final}=0$ and $E_{cot}=0.344$ "
     b"($E$ denotes consumer"),
    # 1-10 (P2) redundant probe-class parentheticals x2
    (b"measurements: the first thinking-leak probe (thinking leak) $v=0.00$---the leak persists at 100\\% (unchanged from the",
     b"measurements: the first thinking-leak probe $v=0.00$---the leak persists at 100\\% (unchanged from the"),
    (b"baseline)---and the fourth thinking-leak probe (thinking leak) $v=-1.00$---the leak doubles from 50\\% to",
     b"baseline)---and the fourth thinking-leak probe $v=-1.00$---the leak doubles from 50\\% to"),
    # 1-7b (P1) "headline 14.55%"
    (b"selection-pressured; the headline 14.55\\% rate comes from the diverse cohort,",
     b"selection-pressured; the 14.55\\% point estimate comes from the diverse cohort,"),
    # 9 (P1) bessemer2026 URL -> verified atlas link
    (b"\\url{https://bvp.com/resources/research/securing-ai-agents-2026} (industry",
     b"\\url{https://www.bvp.com/atlas/securing-ai-agents-the-defining-cybersecurity-challenge-of-2026} (industry"),
    # 9 (P1) microsoft2026 -> live Microsoft Learn page (old URL 404)
    (b"Microsoft, ``Securing agentic AI end-to-end,'' Microsoft Security, 2026,\r\n"
     b"available:\r\n"
     b"\\url{https://www.microsoft.com/security/business/ai-security/securing-agentic-ai}\r\n"
     b"(industry report; not peer-reviewed).",
     b"Microsoft, ``Reduce autonomous agentic AI risk,'' Microsoft Learn, 2026,\r\n"
     b"available:\r\n"
     b"\\url{https://learn.microsoft.com/security/zero-trust/sfi/manage-agentic-risk}\r\n"
     b"(technical guidance; not peer-reviewed)."),
    # 9 (P1) owasp2025 URL -> live 2025 list (old project URL 404)
    (b"available: \\url{https://owasp.org/www-project-top-10-for-llm-applications/}.",
     b"available: \\url{https://genai.owasp.org/llm-top-10/}."),
    # 9 (P1) promptkeeper2025 venue: Findings of EMNLP 2025
    (b"Z.~Jiang, Z.~Jin, and G.~He, ``PromptKeeper: Safeguarding system prompts for\r\n"
     b"LLMs,'' in \\emph{Proc.\\ Conf.\\ Empir.\\ Methods Nat.\\ Lang.\\ Process.\\ (EMNLP)},\r\n"
     b"2025.",
     b"Z.~Jiang, Z.~Jin, and G.~He, ``PromptKeeper: Safeguarding system prompts for\r\n"
     b"LLMs,'' in \\emph{Findings of the Association for Computational Linguistics:\r\n"
     b"EMNLP 2025}, 2025, pp.~2712--2728."),
]

data = open(P, 'rb').read()
for i, (old, new) in enumerate(EDITS, 1):
    n = data.count(old)
    if n != 1:
        sys.exit("EDIT %d: count=%d (expected 1) -- ABORT, no write" % (i, n))
    data = data.replace(old, new)
    print("EDIT %d ok (%d -> %d bytes)" % (i, len(old), len(new)))

tmp = P + '.tmp35'
open(tmp, 'wb').write(data)
os.replace(tmp, P)
print("WROTE", P, len(data), "bytes")
