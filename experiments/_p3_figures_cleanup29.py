"""Pass-29: Remove non-LLM-attack-domain expressions from Related Work."""
import os, sys

TEX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "paper", "p3_tifs.tex")

with open(TEX, "r", encoding="utf-8") as f:
    tex = f.read()

edits = []

# --- Edit 1: Remove IP/antidistillation paragraph (L228-232) ---
old1 = ("latent-CoT reasoning suggests that hiding reasoning from language may itself be\n"
        "a privacy-preserving design direction~\\cite{huang2025}. A parallel line treats\n"
        "reasoning traces as intellectual property, proposing antidistillation sampling\n"
        "that poisons traces to degrade student models~\\cite{savani2025} and studying\n"
        "what transfers across model families~\\cite{tian2025}. Those results treat the\n"
        "reasoning trace as an asset to be protected or distilled; we instead report per-channel rates for it as a measurement surface.")
new1 = ("latent-CoT reasoning suggests that hiding reasoning from language may itself be\n"
        "a privacy-preserving design direction~\\cite{huang2025}. We instead report per-channel\n"
        "rates for it as a measurement surface.")
edits.append((old1, new1))

# --- Edit 2: Condense safety-alignment enumeration (L251-259) ---
old2 = ("\\textbf{Safety evaluation and alignment.} Standardized benchmarks span hundreds\n"
        "of behaviors and dozens of models~\\cite{mazeika2024}, with domain-specific\n"
        "extensions such as WMDP (Weapons of Mass Destruction Proxy) for dual-use knowledge~\\cite{wmdp2024}, safety\n"
        "classifiers including Llama Guard~\\cite{inan2023, llamaguard2024} that operate at\n"
        "the output boundary, constitutional classifiers that reduce universal jailbreak\n"
        "success below 5\\% over thousands of red-team hours~\\cite{conclaude2025},\n"
        "alignment methods from RLHF (reinforcement learning from human feedback) to direct preference optimization~\\cite{dpo2023}, and\n"
        "agent benchmarks such as AgentDojo for tool-using robustness~\\cite{debenedetti2024}\n"
        "and SafetyBench~\\cite{safetybench2024}; none reports leak rates separately for\n"
        "the reasoning channel and for the final answer.")
new2 = ("\\textbf{Safety evaluation and alignment.} Standardized benchmarks span hundreds\n"
        "of behaviors and dozens of models~\\cite{mazeika2024}, with agent benchmarks\n"
        "such as AgentDojo for tool-using robustness~\\cite{debenedetti2024}; none reports\n"
        "leak rates separately for the reasoning channel and for the final answer.")
edits.append((old2, new2))

for old, new in edits:
    cnt = tex.count(old)
    if cnt != 1:
        print(f"ABORT: expected 1 occurrence of {repr(old[:60])}, found {cnt}")
        sys.exit(1)
    tex = tex.replace(old, new)
    print(f"OK: replaced {repr(old[:50])}...")

tmp = TEX + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(tex)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, TEX)
print(f"Written {TEX} ({len(tex)} bytes)")
print("Pass-29 complete.")