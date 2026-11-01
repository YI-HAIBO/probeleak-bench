"""P2-3a: compress the 3 newly-added related-work sentences back toward 16 pages.

Iterative: each run replaces the verbose new sentences with tighter versions,
then the caller rebuilds and checks the page count.
"""
import subprocess, os, re

P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
s = open(P, encoding="utf-8").read()

# --- current (verbose) versions of the 3 new sentences, as they now sit in the file ---
S1_OLD = (
    "A complementary 2026 measurement shows that the reasoning channel is extractable at "
    "scale: replaying encrypted reasoning blocks into weaker sibling models decodes them "
    "verbatim, and scraping 315{,}320 such blocks from public repositories recovered 367 "
    "personally identifiable information artifacts and 182 credentials (62 API keys, 33 "
    "passwords, 24 access tokens, and 7 private keys), with 64 privacy artifacts visible "
    "only in the encrypted reasoning channel~\\cite{reasoningtrace2026}. This establishes "
    "that the reasoning channel is not merely a theoretical leak path but a demonstrated, "
    "large-scale exfiltration surface that survives encryption-by-obscurity. "
)
S1_NEW = (
    "From 315{,}320 encrypted reasoning blocks scraped from public repositories, a 2026 study "
    "recovered 367 personally identifiable information artifacts and 182 credentials (62 API "
    "keys, 33 passwords, 24 access tokens, 7 private keys), 64 of them visible only in the "
    "encrypted reasoning channel~\\cite{reasoningtrace2026}: the reasoning channel is a "
    "demonstrated, large-scale exfiltration surface, not merely a theoretical leak path. "
)

S2_OLD = (
    "benign deployment. A controlled factorial study isolates the scratchpad reasoning channel "
    "as an output-prefix attack vector and finds that injecting malicious reasoning alone is "
    "essentially inert ($\\approx$0\\% attack success), whereas the same reasoning combined "
    "with a trivial output prefix reaches up to 99\\% attack success on some "
    "models~\\cite{prefillchannel2026}. The effect is interface-dependent: hiding the scratchpad "
    "removes an API field but not the behavior, because a reasoning block can be fabricated "
    "inside the output prefix for models that never expose a reasoning channel. It shows that "
    "the channel's leakage behavior depends on how it is served, and that measuring it in "
    "isolation---as this paper does---is necessary rather than sufficient."
)
S2_NEW = (
    "benign deployment. A controlled factorial study isolates the scratchpad reasoning channel "
    "as an output-prefix attack vector and finds that malicious reasoning alone is inert "
    "($\\approx$0\\% success) while the same reasoning with a trivial output prefix reaches up "
    "to 99\\%~\\cite{prefillchannel2026}. The effect is interface-dependent---hiding the "
    "scratchpad removes an API field but not the behavior, since a reasoning block can be "
    "fabricated inside the output prefix for models that never expose a reasoning channel---so "
    "the channel's leakage depends on how it is served, and measuring it in isolation, as this "
    "paper does, is necessary rather than sufficient."
)

S3_OLD = (
    "such measures computable on large models via automatic differentiation. A 2026 reasoning "
    "firewall instead treats the CoT trace itself as untrusted input and localizes the point "
    "of fracture via step-level audit~\\cite{traceguard2026}: a compact 4B-parameter verifier "
    "reaches forensic precision on unseen reasoning-integrity attacks that rivals architectures "
    "two orders of magnitude larger, and its auditing transfers to attack families excluded "
    "from training. This is a consumer-side verification primitive, complementary to the "
    "producer-side mechanisms above."
)
S3_NEW = (
    "such measures computable on large models via automatic differentiation. A 2026 reasoning "
    "firewall treats the CoT trace itself as untrusted input and localizes the fracture point "
    "via step-level audit~\\cite{traceguard2026}: a compact 4B verifier reaches forensic "
    "precision on unseen reasoning-integrity attacks rivaling architectures two orders of "
    "magnitude larger, and its auditing transfers to held-out attack families. This "
    "consumer-side verification primitive complements the producer-side mechanisms above."
)

for old, new, label in [(S1_OLD, S1_NEW, "S1"), (S2_OLD, S2_NEW, "S2"), (S3_OLD, S3_NEW, "S3")]:
    assert s.count(old) == 1, "%s anchor count=%d" % (label, s.count(old))
    s = s.replace(old, new, 1)

open(P, "w", encoding="utf-8").write(s)
print("compressed 3 new sentences; new body words:", len(s.split()))