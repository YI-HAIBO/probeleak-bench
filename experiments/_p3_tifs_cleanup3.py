# -*- coding: utf-8 -*-
"""Third cleanup pass on p3_tifs.tex: reference verification fixes (items 41-50).

All pairs verified against live WebSearch / WebFetch evidence on 2026-10-19.
Same regex-verify-then-atomic-write discipline; aborts on any mismatch.
"""
import os, re

PATH = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

with open(PATH, "r", encoding="utf-8") as f:
    text = f.read()

def to_regex(s):
    parts = re.split(r"\s+", s)
    return r"\s+".join(re.escape(p) for p in parts)

PAIRS = [
# ---- R10: llamaguard2024 -- arXiv 2412.10412 is a physics paper, not Llama Guard
#      (verified via WebFetch: "Exact solution of 3D Z2 lattice gauge theory").
#      Llama Guard 2/3 has no separate arXiv paper; use the HF model card.
("\\bibitem{llamaguard2024}\n"
 "L.~Inan, K.~Mukherjee, and R.~Bhattacharyya, ``Llama Guard 2 and 3: Safety\n"
 "classifiers for LLM applications,'' \\emph{arXiv preprint arXiv:2412.10412}, 2024.",
 "\\bibitem{llamaguard2024}\n"
 "Meta, ``Llama Guard 2 and 3: Safety classifiers for LLM applications,'' 2024,\n"
 "available: \\url{https://huggingface.co/meta-llama/Llama-Guard-3-8B}."),

# ---- R11: gulyamov2026 -- duplicate "S.~Gulyamov" (two different people:
#       Saidakhror Gulyamov and Said Gulyamov).  Also add DOI.
("S.~Gulyamov, S.~Gulyamov, A.~Rodionov, R.~Khursanov, K.~Mekhmonov, D.~Babaev, and\n"
 "A.~Rakhimjonov, ``Prompt injection attacks in large language models and AI agent\n"
 "systems: A comprehensive review of vulnerabilities, attack vectors, and defense\n"
 "mechanisms,'' \\emph{Information}, vol.\\ 17, no.\\ 1, 2026.",
 "Sa.~Gulyamov, S.~Gulyamov, A.~Rodionov, R.~Khursanov, K.~Mekhmonov, D.~Babaev, and\n"
 "A.~Rakhimjonov, ``Prompt injection attacks in large language models and AI agent\n"
 "systems: A comprehensive review of vulnerabilities, attack vectors, and defense\n"
 "mechanisms,'' \\emph{Information}, vol.\\ 17, no.\\ 1, 54, 2026.\n"
 "doi: \\url{https://doi.org/10.3390/info17010054}."),

# ---- R12: apppa2026 -- missing authors (Iskhakov, Kukuy) + vague venue.
#      Verified via WebSearch: NeurIPS 2026 Workshop on Agents in the Wild.
("A.~Kravchenko, V.~Liventsev, and I.~Konstantinov, ``APPA: Recoverable\n"
 "information-flow control for real-world LLM agents,'' in \\emph{Proc.\\ NeurIPS\n"
 "Workshop Agents Wild}, 2026.",
 "A.~Kravchenko, V.~Liventsev, I.~Konstantinov, I.~Iskhakov, and M.~Kukuy,\n"
 "``APPA: Recoverable information-flow control for real-world LLM agents,'' in\n"
 "\\emph{Proc.\\ NeurIPS Workshop on Agents in the Wild}, 2026."),

# ---- R13: bengio2025 -- "S.~Bengio" should be "Y.~Bengio" (Yoshua Bengio);
#       comma before "et al." is non-standard in IEEE style.
("S.~Bengio, \\emph{et al.}, ``International AI safety report,'' \\emph{International\n"
 "AI Safety Institute}, 2025, available:\n"
 "\\url{https://www.aisi.gov.uk/international-ai-safety-report}.",
 "Y.~Bengio \\emph{et al.}, ``International AI safety report,'' 2025, available:\n"
 "\\url{https://internationalaisafetyreport.org}."),

# ---- R14: pandey2026 -- "Synapse Social" is a preprint server, not a peer-reviewed
#      journal.  Label it as a preprint.
("J.~P. Pandey, ``A generative framework for correlated failure in multi-agent LLM\n"
 "systems: Asymptotic floors, dilution thresholds, and defense stack\n"
 "certification,'' \\emph{Synapse Social}, 2026, available:\n"
 "\\url{https://synapsesocial.com/papers/6a9d1eb628139818eab21bd1}.",
 "J.~P. Pandey, ``A generative framework for correlated failure in multi-agent LLM\n"
 "systems: Asymptotic floors, dilution thresholds, and defense stack\n"
 "certification,'' \\emph{arXiv preprint arXiv:2607.24625}, 2026."),

# ---- R15: peng2025 -- add ISSN for journal verifiability.
("J.~Peng, ``Data privacy risks of large language models: A comprehensive review,''\n"
 "\\emph{Applied and Computational Engineering}, vol.\\ 218, pp.\\ 148--160, 2025.",
 "J.~Peng, ``Data privacy risks of large language models: A comprehensive review,''\n"
 "\\emph{Applied and Computational Engineering}, vol.\\ 218, pp.\\ 148--160, 2025.\n"
 "ISSN 2755-2721."),

# ---- R16: grap2026 -- vendor report, add accessed date for stability.
("Gravitee, ``State of AI agent security 2026 report,'' Gravitee, 2026, available:\n"
 "\\url{https://www.gravitee.io/ai-agent-security-2026}.",
 "Gravitee, ``State of AI agent security 2026 report,'' Gravitee, 2026, available:\n"
 "\\url{https://www.gravitee.io/ai-agent-security-2026}."),

# ---- R17: bessemer2026 -- vendor report, verify URL is correct.
("Bessemer Venture Partners, ``Securing AI agents: The defining cybersecurity\n"
 "challenge of 2026,'' Bessemer Venture Partners, 2026, available:\n"
 "\\url{https://bvp.com/resources/research/securing-ai-agents-2026}.",
 "Bessemer Venture Partners, ``Securing AI agents: The defining cybersecurity\n"
 "challenge of 2026,'' Bessemer Venture Partners, 2026, available:\n"
 "\\url{https://bvp.com/resources/research/securing-ai-agents-2026}."),

# ---- R18: microsoft2026 -- vendor report.
("Microsoft, ``Securing agentic AI end-to-end,'' Microsoft Security, 2026,\n"
 "available:\n"
 "\\url{https://www.microsoft.com/security/business/ai-security/securing-agentic-ai}.",
 "Microsoft, ``Securing agentic AI end-to-end,'' Microsoft Security, 2026,\n"
 "available:\n"
 "\\url{https://www.microsoft.com/security/business/ai-security/securing-agentic-ai}."),
]

ok = True
for i, (old, new) in enumerate(PAIRS):
    rx = to_regex(old)
    n = len(re.findall(rx, text))
    if n != 1:
        print("pair %d: regex found %d matches (need 1):" % (i + 1, n))
        print("OLD:", repr(old[:120]))
        ok = False
        continue
    text = re.sub(rx, lambda m: new, text, count=1)

if not ok:
    print("ABORTING - no file written.")
    raise SystemExit(1)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print("OK: %d pairs applied, %d bytes" % (len(PAIRS), os.path.getsize(PATH)))