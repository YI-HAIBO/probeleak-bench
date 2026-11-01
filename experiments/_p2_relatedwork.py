"""P2-2: add 3 related-work citations (2026, same topic) to paper/p3_tifs.tex.

Three new bibitems + three prose insertions:
  reasoningtrace2026 (arXiv:2608.09867) -> Reasoning-channel privacy paragraph
  prefillchannel2026 (arXiv:2609.29775) -> Reasoning-channel privacy paragraph
  traceguard2026      (arXiv:2603.02436) -> Defenses and their composition paragraph
"""
import os

P = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
s = open(P, encoding="utf-8").read()

# ---- 1. three bibitems inserted just before \end{thebibliography} ----
bib_anchor = "\\end{thebibliography}"
assert s.count(bib_anchor) == 1, "bib anchor count != 1"

new_bibs = r"""
\bibitem{reasoningtrace2026}
A.~Panfilov, D.~Schmotz, I.~Shumailov, L.~Beurer-Kellner, J.~Schaeffer,
A.~Prabhu, J.~Geiping, and M.~Andriushchenko, ``Stealing reasoning traces
from proprietary LLM APIs,'' \emph{arXiv preprint arXiv:2608.09867}, 2026.
\bibitem{prefillchannel2026}
L.~Br{\v u}na, R.~Bridges, and A.~Ek, ``Prefilling the reasoning channel:
Output-prefix attacks on reasoning LLMs,'' \emph{arXiv preprint arXiv:2609.29775},
2026.
\bibitem{traceguard2026}
Z.~Guo, S.~Shi, H.~Li, S.~Yazdani, N.~Zhang, and R.~Tourani, ``TraceGuard:
Process-guided firewall against reasoning backdoors in large language models,''
\emph{arXiv preprint arXiv:2603.02436}, 2026.
"""
s = s.replace(bib_anchor, new_bibs + bib_anchor, 1)

# ---- 2. prose insertions ----
edits = []

# S1: reasoningtrace2026, before "This line of work studies the same phenomenon"
edits.append((
    "This line of work studies the same phenomenon from the privacy side rather",
    ("A complementary 2026 measurement shows that the reasoning channel is extractable at "
     "scale: replaying encrypted reasoning blocks into weaker sibling models decodes them "
     "verbatim, and scraping 315{,}320 such blocks from public repositories recovered 367 "
     "personally identifiable information artifacts and 182 credentials (62 API keys, 33 "
     "passwords, 24 access tokens, and 7 private keys), with 64 privacy artifacts visible "
     "only in the encrypted reasoning channel~\\cite{reasoningtrace2026}. This establishes "
     "that the reasoning channel is not merely a theoretical leak path but a demonstrated, "
     "large-scale exfiltration surface that survives encryption-by-obscurity. "
     "This line of work studies the same phenomenon from the privacy side rather")
))

# S2: prefillchannel2026, after the ShadowCoT sentence
edits.append((
    "which motivates measuring---rather than assuming---what the channel already leaks under benign deployment.",
    ("which motivates measuring---rather than assuming---what the channel already leaks under "
     "benign deployment. A controlled factorial study isolates the scratchpad reasoning channel "
     "as an output-prefix attack vector and finds that injecting malicious reasoning alone is "
     "essentially inert ($\\approx$0\\% attack success), whereas the same reasoning combined "
     "with a trivial output prefix reaches up to 99\\% attack success on some "
     "models~\\cite{prefillchannel2026}. The effect is interface-dependent: hiding the scratchpad "
     "removes an API field but not the behavior, because a reasoning block can be fabricated "
     "inside the output prefix for models that never expose a reasoning channel. It shows that "
     "the channel's leakage behavior depends on how it is served, and that measuring it in "
     "isolation---as this paper does---is necessary rather than sufficient.")
))

# S3: traceguard2026, after the geometric information-flow control sentence
# (anchor spans the hard line wrap between "makes" and "such")
edits.append((
    "doshi2026, storek2026, apppa2026}, and geometric information-flow control makes\n"
    "such measures computable on large models via automatic differentiation.",
    ("doshi2026, storek2026, apppa2026}, and geometric information-flow control makes\n"
     "such measures computable on large models via automatic differentiation. A 2026 reasoning "
     "firewall instead treats the CoT trace itself as untrusted input and localizes the point "
     "of fracture via step-level audit~\\cite{traceguard2026}: a compact 4B-parameter verifier "
     "reaches forensic precision on unseen reasoning-integrity attacks that rivals architectures "
     "two orders of magnitude larger, and its auditing transfers to attack families excluded "
     "from training. This is a consumer-side verification primitive, complementary to the "
     "producer-side mechanisms above.")
))

for old, new in edits:
    assert s.count(old) == 1, "anchor not unique/found: %r (count=%d)" % (old[:60], s.count(old))
    s = s.replace(old, new, 1)

open(P, "w", encoding="utf-8").write(s)
print("P2-2 applied: 3 bibitems + 3 prose insertions")
for k in ["reasoningtrace2026", "prefillchannel2026", "traceguard2026"]:
    print("  cite %-20s in tex: %s" % (k, s.count(k)))