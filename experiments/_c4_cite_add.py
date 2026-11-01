import io, os
p = r'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex'
with io.open(p, 'rb') as f:
    data = f.read()

# --- Anchor A: reasoning-channel privacy paragraph tail (C4 ShadowCoT) ---
old_A = (b"a privacy-preserving design direction~\\cite{huang2025}. We instead report per-channel\r\n"
         b"rates for it as a measurement surface.")
new_A = old_A + (b" The reasoning channel is also an active \\emph{attack} surface: ShadowCoT plants "
                 b"stealthy backdoors directly into the CoT reasoning path~\\cite{shadowcot2026}, "
                 b"which motivates measuring---rather than assuming---what the channel already "
                 b"leaks under benign deployment.")
assert data.count(old_A) == 1, f"A count={data.count(old_A)}"
data = data.replace(old_A, new_A, 1)

# --- Anchor B: jailbreaking paragraph (C4 DIA) ---
old_B = (b"obfuscation~\\cite{promptobfuscation2025}. Prompt-level defenses are outside the measurement target here,")
new_B = (b"obfuscation~\\cite{promptobfuscation2025}. Dialogue-injection attacks show that manipulating "
         b"historical context---not only the current prompt---can jailbreak LLMs~\\cite{dia2026}; "
         b"this measurement complements such work by isolating which channel (reasoning versus final) "
         b"carries leaked credentials when the agent is otherwise benign. Prompt-level defenses are outside the measurement target here,")
assert data.count(old_B) == 1, f"B count={data.count(old_B)}"
data = data.replace(old_B, new_B, 1)

# --- Anchor C: insert two new bibitems before \end{thebibliography} ---
old_C = (b"\\bibitem{agentsurvey2026}\r\n"
         b"Y.~Ling, S.~Yu, Z.~Chen, and C.~Fang, ``Toward Secure LLM Agents: Threat Surfaces,\r\n"
         b"Attacks, Defenses, and Evaluation,'' \\emph{arXiv preprint arXiv:2606.10749}, 2026.\r\n"
         b"\\end{thebibliography}")
new_C = (b"\\bibitem{agentsurvey2026}\r\n"
         b"Y.~Ling, S.~Yu, Z.~Chen, and C.~Fang, ``Toward Secure LLM Agents: Threat Surfaces,\r\n"
         b"Attacks, Defenses, and Evaluation,'' \\emph{arXiv preprint arXiv:2606.10749}, 2026.\r\n"
         b"\r\n"
         b"\\bibitem{shadowcot2026}\r\n"
         b"G.~Zhao, H.~Wu, X.~Zhang, and A.~V. Vasilakos, ``ShadowCoT: Cognitive hijacking\r\n"
         b"for stealthy reasoning backdoors in LLMs,'' \\emph{IEEE Transactions on\r\n"
         b"Information Forensics and Security}, vol.~21, pp.~4625--4639, 2026.\r\n"
         b"DOI: 10.1109/TIFS.2026.3688130.\r\n"
         b"\\bibitem{dia2026}\r\n"
         b"W.~Meng, F.~Zhang, W.~Yao, Z.~Guo, Y.~Li, C.~Wei, and W.~Chen, ``Dialogue\r\n"
         b"injection attack: Jailbreaking LLMs through context manipulation,'' \\emph{IEEE\r\n"
         b"Transactions on Information Forensics and Security}, vol.~21, pp.~1577--1592,\r\n"
         b"2026. DOI: 10.1109/TIFS.2026.3657898.\r\n"
         b"\\end{thebibliography}")
assert data.count(old_C) == 1, f"C count={data.count(old_C)}"
data = data.replace(old_C, new_C, 1)

tmp = p + '.tmp'
with io.open(tmp, 'wb') as f:
    f.write(data)
os.replace(tmp, p)
print("C4 applied: +2 bibitems (shadowcot2026, dia2026) and +2 body citations.")
