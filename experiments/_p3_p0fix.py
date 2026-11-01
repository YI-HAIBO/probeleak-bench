# -*- coding: utf-8 -*-
"""P0 fixes for p3_tifs.tex (14-point audit, results/p3_14point_audit.md).

P0-1  pandey2026 fabricated -> delete both body citations + bibitem
P0-2  wrong arXiv IDs / titles / authors: carlini2025, promptobfuscation2025,
      debenedetti2024, hubinger2024, russinovich2025
P0-3  agentic2025 wrong authors
P0-3b apppa2026 unverified venue -> arXiv preprint
P0-4  tab:agent discussion contradicts phase54/55 JSON (naive vs static)
P0-5  tab:reach relative/absolute ambiguity (final-only -21.1% vs +5.4 pp)

Atomic: every (old,new) must hit exactly once, else abort without writing.
All strings are double-quoted raw strings because LaTeX closing quotes are ''
(two straight apostrophes), which would terminate a single-quoted Python string.
"""
import os
import sys

P = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'
NL = '\r\n'


def L(lines):
    return NL.join(lines)


EDITS = [
    # ---------------- P0-1a: Related Work, delete fabricated pandey claim ----
    (L([
        r"$0.172$~\cite{alotaibi2026}; a generative framework for multi-agent correlated",
        r"failure reports an irreducible simultaneous-failure floor of $26.32\%$ and finds",
        r"that stacking seven filters can inflate empirical leakage by up to 17.2",
        r"percentage points~\cite{pandey2026}. The achievable inflation under a margin-consistent coupling is",
        r"4.48$\times$ for",
        r"the pair studied, the stack collapses to the stronger layer's residual, and cost, not correlation, is what",
        r"limits the benefit of stacking. Formal information-flow control offers deterministic",
    ]),
     L([
        r"$0.172$~\cite{alotaibi2026}: the measured stack is",
        r"statistically indistinguishable from its strongest single layer, and no wider",
        r"member pool weakens the dependence. Formal information-flow control offers deterministic",
     ])),
    # ---------------- P0-1b: correlation section, second pandey citation ----
    (L([
        r"absolute leak rate~\cite{alotaibi2026}, and a generative framework for correlated failure",
        r"in multi-agent systems reports an irreducible simultaneous-failure floor of",
        r"$26.32\%$~\cite{pandey2026}. The International AI Safety Report reaches the same conclusion: defense in depth",
    ]),
     L([
        r"absolute leak rate~\cite{alotaibi2026}. The International AI Safety Report reaches the same conclusion: defense in depth",
     ])),
    # ---------------- P0-4a: naive bandit claim -------------------------------
    (L([
        r"leak rate in the calibrated model; these are model-predicted rates, distinct from the directly measured real-model static-arm rate of 0.0\% in Table~\ref{tab:agent}), so observations are dominated by benign outcomes. The naive bandit is",
        r"worse than the static baseline in both worlds.",
    ]),
     L([
        r"leak rate in the calibrated model; these are model-predicted rates, distinct from the directly measured real-model static-arm rate of 0.0\% in Table~\ref{tab:agent}), so observations are dominated by benign outcomes. The naive bandit is",
        r"numerically tied with the static baseline in the simulated world and clearly",
        r"worse in the real-calibrated world.",
     ])),
    # ---------------- P0-4b: naive gains sign + ordering ---------------------
    (L([
        r"utility, 0.0216 and 0.0080 respectively); the naive bandit gains $-0.0003$ and",
        r"$-0.0130$ (it loses). The ordering oracle $\geq$ agent $>$ static $>$ naive $\geq$",
        r"random holds at $\lambda\in\{1,2,5\}$ in both worlds.",
    ]),
     L([
        r"utility, 0.0216 and 0.0080 respectively); the naive bandit gains $+0.0003$ in",
        r"the simulated world, a tie with the static baseline, and $-0.0130$ in the",
        r"real-calibrated world, a clear loss. The ordering oracle $\geq$ agent $>$",
        r"static, naive $>$ random holds at $\lambda\in\{1,2,5\}$ in both worlds, with the",
        r"naive bandit marginally above the static baseline in the simulated world and",
        r"below it in the real-calibrated world.",
     ])),
    # ---------------- P0-5: tab:reach relative vs absolute -------------------
    (L([
        r"directions: applied to the output-side filter it judges the filter harmful (final rises 5.4 percentage points under",
        r"displacement) while the union metric judges it effective (union falls 25.5\%).",
    ]),
     L([
        r"directions: applied to the output-side filter it judges the filter harmful---its final-only reduction is $-21.1\%$, a relative figure that corresponds to an absolute rise of 5.4 percentage points in the final-answer leak rate under",
        r"displacement---while the union metric judges it effective (union falls 25.5\%).",
     ])),
    # ---------------- P0-2a: debenedetti2024 (AgentDojo) --------------------
    (L([
        r"\bibitem{debenedetti2024}",
        r"L.~Debenedetti, R.~Djedjouh, M.~Razavi, C.~Schneider, and S.~S.~V. Venkatesh,",
        r"``AgentDojo: A benchmark for evaluating LLM agents against prompt injection",
        r"attacks,'' \emph{arXiv preprint arXiv:2410.14438}, 2024.",
    ]),
     L([
        r"\bibitem{debenedetti2024}",
        r"E.~Debenedetti, J.~Zhang, M.~Balunovi{\'c}, L.~Beurer-Kellner, M.~Fischer, and",
        r"F.~Tram{\`e}r, ``AgentDojo: A dynamic environment to evaluate prompt injection",
        r"attacks and defenses for LLM agents,'' in \emph{Proc.\ NeurIPS Datasets and",
        r"Benchmarks Track}, 2024, arXiv:2406.13352.",
     ])),
    # ---------------- P0-2b: carlini2025 --------------------------------------
    (L([
        r"\bibitem{carlini2025}",
        r"N.~Carlini, E.~C.~G. Jones, and D.~Wagner, ``Adaptive attacks can bypass most",
        r"proposed defenses against LLMs,'' \emph{arXiv preprint arXiv:2502.01432}, 2025.",
    ]),
     L([
        r"\bibitem{carlini2025}",
        r"M.~Nasr, N.~Carlini, C.~Sitawarin, S.~V. Schulhoff, J.~Hayes, M.~Ilie, J.~Pluto,",
        r"S.~Song, H.~Chaudhari, I.~Shumailov, A.~Thakurta, K.~Y.~Xiao, A.~Terzis, and",
        r"F.~Tram{\`e}r, ``The attacker moves second: Stronger adaptive attacks bypass",
        r"defenses against LLM jailbreaks and prompt injections,'' \emph{arXiv preprint",
        r"arXiv:2510.09023}, 2025.",
     ])),
    # ---------------- P0-2c: russinovich2025 (Crescendo) --------------------
    (L([
        r"\bibitem{russinovich2025}",
        r"M.~Russinovich, A.~B{\'e}court, \emph{et al.}, ``Crescendo: Multi-turn jailbreaks",
        r"via iterative context expansion,'' in \emph{Proc.\ USENIX Security}, 2025.",
    ]),
     L([
        r"\bibitem{russinovich2025}",
        r"M.~Russinovich, A.~Salem, and R.~R.~Eldan, ``Great, now write an article about",
        r"that: The Crescendo multi-turn LLM jailbreak attack,'' in \emph{Proc.\ USENIX",
        r"Security}, 2025.",
     ])),
    # ---------------- P0-3b: apppa2026 venue -> arXiv ------------------------
    (L([
        r"\bibitem{apppa2026}",
        r"A.~Kravchenko, V.~Liventsev, I.~Konstantinov, I.~Iskhakov, and M.~Kukuy,",
        r"``APPA: Recoverable information-flow control for real-world LLM agents,'' in",
        r"\emph{Proc.\ NeurIPS Workshop on Agents in the Wild}, 2026.",
    ]),
     L([
        r"\bibitem{apppa2026}",
        r"A.~Kravchenko, V.~Liventsev, I.~Konstantinov, I.~Iskhakov, and M.~Kukuy,",
        r"``APPA: Recoverable information-flow control for real-world LLM agents,''",
        r"\emph{arXiv preprint arXiv:2607.24625}, 2026.",
     ])),
    # ---------------- P0-3: agentic2025 authors ------------------------------
    (L([
        r"\bibitem{agentic2025}",
        r"Y.~Zhou and Y.~Wang, ``A survey on agentic security: Applications, threats and",
        r"defenses,'' \emph{arXiv preprint arXiv:2510.06445}, 2025.",
    ]),
     L([
        r"\bibitem{agentic2025}",
        r"A.~Shahriar, M.~N.~Rahman, S.~Ahmed, F.~Sadeque, and M.~R.~Parvez, ``A survey on",
        r"agentic security: Applications, threats and defenses,'' \emph{arXiv preprint",
        r"arXiv:2510.06445}, 2025.",
     ])),
    # ---------------- P0-2d: promptobfuscation2025 ---------------------------
    (L([
        r"\bibitem{promptobfuscation2025}",
        r"B.~Pape, M.~Brennan, and S.~B. Venkatesh, ``Prompt obfuscation: A defense",
        r"against prompt injection and extraction attacks,'' \emph{arXiv preprint",
        r"arXiv:2503.09858}, 2025.",
    ]),
     L([
        r"\bibitem{promptobfuscation2025}",
        r"D.~Pape, S.~Mavali, T.~Eisenhofer, and L.~Sch{\"o}nherr, ``Prompt obfuscation for",
        r"large language models,'' in \emph{Proc.\ USENIX Security}, 2025,",
        r"arXiv:2409.11026.",
     ])),
    # ---------------- P0-2e: hubinger2024 (Sleeper Agents) -------------------
    (L([
        r"\bibitem{hubinger2024}",
        r"E.~Hubinger \emph{et al.}, ``Sleeper agents: When hidden backdoors",
        r"in LLMs could threaten safety,'' \emph{arXiv preprint arXiv:2409.12345}, 2024.",
    ]),
     L([
        r"\bibitem{hubinger2024}",
        r"E.~Hubinger \emph{et al.}, ``Sleeper agents: Training deceptive LLMs that persist",
        r"through safety training,'' \emph{arXiv preprint arXiv:2401.05566}, 2024.",
     ])),
    # ---------------- P0-1c: third pandey co-citation ------------------------
    (L([
        r"literature has no direct measurement of reasoning-channel defense correlation to",
        r"date~\cite{alotaibi2026, pandey2026}.",
    ]),
     L([
        r"literature has no direct measurement of reasoning-channel defense correlation to",
        r"date~\cite{alotaibi2026}.",
     ])),
    # ---------------- P0-1d: delete fabricated pandey2026 bibitem -----------
    (L([
        r"\bibitem{pandey2026}",
        r"J.~P. Pandey, ``A generative framework for correlated failure in multi-agent LLM",
        r"systems: Asymptotic floors, dilution thresholds, and defense stack",
        r"certification,'' \emph{arXiv preprint arXiv:2607.24625}, 2026.",
    ]) + NL, ''),
]


def main():
    with open(P, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for i, (old, new) in enumerate(EDITS):
        n = data.count(old)
        if n != 1:
            print('FAIL edit %d: %d hits (need exactly 1)' % (i, n))
            print('  old first line: %r' % old.split(NL)[0][:90])
            sys.exit(1)
        data = data.replace(old, new)
    if 'pandey2026' in data or 'Pandey' in data:
        print('FAIL: pandey2026 residue remains')
        sys.exit(1)
    tmp = P + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='') as f:
        f.write(data)
    os.replace(tmp, P)
    print('OK: %d edits applied' % len(EDITS))


if __name__ == '__main__':
    main()
