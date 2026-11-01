"""Pass-40:落地 Editor_Review_v1_TIFS_20261025.md 的 C1-C9 修改（C7 降级表述）。

铁律：
- 每条 edit 独立函数，src.count(old) != 1 即 FAIL 并中止全部写入（不允许部分成功）。
- 普通字符串（非 raw），真换行写 \\n，LaTeX 反斜杠双写 \\\\。
- 写回用 tmp + os.replace，保持 bare-LF（open newline=''）。
- 全部命中后才写；写完由调用方 re-read + grep 复验。
"""
import os, sys

TEX = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"

EDITS = []

def add(name, old, new):
    EDITS.append((name, old, new))

# ---- C1 + C4: abstract (2) 重新表述（实测→校准模型取值；删 "measured stack collapses"）----
add("A_abstract2",
    "repetition. (2) A calibrated-model bound caps defense stacking at 4.48-fold the\n"
    "independence prediction, and the measured stack collapses to its stronger layer.\n"
    "(3) Output-side filtering depends on consumer visibility:",
    "repetition. (2) A calibrated-model bound caps defense stacking at 4.48-fold the\n"
    "independence prediction, and the deployed two-layer stack reaches zero residual. (3)\n"
    "Output-side filtering depends on consumer visibility:")

# ---- C5c: 行业锚点 "primary vector" 与源文件不符 ----
add("B_industry_vector",
    "incident, with uncontrolled database access named as the primary\n"
    "vector~\\cite{grap2026, bessemer2026, microsoft2026}. The International AI Safety",
    "incident (data leakage at 50.1\\% and input manipulation at 49.6\\% being the\n"
    "leading categories)~\\cite{grap2026, bessemer2026, microsoft2026}. The International AI Safety")

# ---- C5b: rbac2026 commercial models 过度概括 + 上界性质 ----
add("C_rbac_commercial",
    "control (RBAC), open-weight models violate access policy on 45--64\\% of\n"
    "queries and even strong commercial models violate it in the double\n"
    "digits~\\cite{rbac2026}. On defenses, policy-conditioned constrained decoding (PCC-SQL)",
    "control (RBAC), open-weight models violate access policy on 45--64\\% of\n"
    "queries (an upper bound, since the benchmark's deny labels are keyed to the gold\n"
    "SQL's access footprint) and commercial models violate it in 2.6--20.5\\% depending\n"
    "on benchmark~\\cite{rbac2026}. On defenses, policy-conditioned constrained decoding (PCC-SQL)")

# ---- C4 + C1: intro item (2)/(3) 的 4.51x 标签 ----
add("D_intro_item2_451",
    "      that exceeds the attainable range by 1.70$\\times$ (see Section~\\ref{sec:corr}); the measured two-layer stack\n"
    "      of $\\tau$ (literal key redaction) and the output-side filter (sentence-level output-side\n"
    "      suppression) collapses to\n"
    "      its stronger layer's residual (a 4.51$\\times$ discount on 13 real\n"
    "      CoT-positive traces).",
    "      that exceeds the attainable range by 1.70$\\times$ (see Section~\\ref{sec:corr}); in the\n"
    "      calibrated model the two-layer stack of $\\tau$ (literal key redaction) and the\n"
    "      output-side filter (sentence-level output-side suppression) collapses to\n"
    "      its stronger layer's residual (a 4.51$\\times$ discount at correlation saturation),\n"
    "      while on 13 real CoT-positive traces both layers' failure rates are zero, so the\n"
    "      collapse is a model prediction rather than an observation.")

# ---- C3a: 删除 peng2025 引用（改引 leaky2025 承接论点）----
add("E_peng_cite1",
    "leakage, model inversion, and side-channel observation~\\cite{peng2025}; and",
    "leakage, model inversion, and side-channel observation~\\cite{leaky2025}; and")

# ---- C3b: 第二处 peng2025 引用 ----
add("F_peng_cite2",
    "data leakage, model inversion, and side-channel observation~\\cite{peng2025}.",
    "data leakage, model inversion, and side-channel observation~\\cite{leaky2025}.")

# ---- C4: §V 开头 4.51x 标签 ----
add("G_secV_451_opening",
    "measurements exist they are reported separately: the 4.51$\\times$ deployment\n"
    "discount of the two-layer $\\tau$ and output-side filter stack comes from the real-trace defense test, which measured both\n"
    "layers on 13 CoT-positive traces, and the stacked-defense residual of the consumer arm is",
    "measurements exist they are reported separately: the 4.51$\\times$ deployment\n"
    "discount of the two-layer $\\tau$ and output-side filter stack is the calibrated model's joint\n"
    "residual at correlation saturation ($\\hat\\rho=1.0$); the real-trace defense test, which measured both\n"
    "layers on 13 CoT-positive traces, and the stacked-defense residual of the consumer arm is")

# ---- C2: §V 新增 architectural vs common-cause 对位段 ----
add("H_secV_commoncause",
    "section bounds this correlation for reasoning-channel defenses specifically.\n\n"
    "At the deployed configuration",
    "section bounds this correlation for reasoning-channel defenses specifically.\n\n"
    "\\textbf{Relation to the measured defense-correlation literature.} The shared-blindspot\n"
    "mixture above models correlation as a single latent factor. Alotaibi et al.\\ measure the\n"
    "same quantity on a seven-layer guardrail stack and report two further properties this\n"
    "analysis does not address: the dependence is predominantly \\emph{common-cause} rather\n"
    "than architectural---stratifying on behavior difficulty dissolves most of the association,\n"
    "though it survives permutation inference, majority-vote grader labels, and externally\n"
    "calibrated thresholds---and the assembled stack refuses four in five benign prompts while\n"
    "remaining statistically indistinguishable from its strongest single layer. Two\n"
    "distinctions keep the present analysis from being a re-measurement of that work. First,\n"
    "it is scoped to the reasoning channel rather than to general guardrails: the layers\n"
    "compared here ($\\tau$ and the output-side filter) operate on the model's own streams,\n"
    "whereas the Alotaibi stack wraps the model externally. Second, the 4.48$\\times$ figure is\n"
    "a \\emph{parameterized upper bound} on the independence gap under a margin-consistent\n"
    "coupling, not a measured gap. We have not replicated the behavior-difficulty\n"
    "stratification, so $\\hat\\rho=1.0$ may partly reflect common-cause structure rather than\n"
    "architectural dependence; this is recorded as a limitation in Section~\\ref{sec:limitations}.\n\n"
    "At the deployed configuration")

# ---- C1 + C4: conclusion defense stacking 段 ----
add("I_conclusion_stacking",
    "is a probe-set property, not a model property. Second, shared blind spots cap the\n"
    "benefit of defense stacking at a 4.48$\\times$ inflation of the independence\n"
    "prediction and collapse the stack to its stronger layer, with cost rather than\n"
    "correlation as the binding constraint.",
    "is a probe-set property, not a model property. Second, in the calibrated model shared\n"
    "blind spots cap the benefit of defense stacking at a 4.48$\\times$ inflation of the\n"
    "independence prediction and collapse the stack to its stronger layer; on real traces both\n"
    "layers' failure rates are zero, so the collapse is a model prediction rather than an\n"
    "observation, with cost rather than correlation as the binding constraint.")

# ---- m8: 单位澄清（mode vs request）----
add("J_mode_unit",
    "selective: 10 of the 12 modes produced\n"
    "\\emph{zero} CoT leaks, while only indirect injection (4/12) and code\n"
    "interpretation (2/9) leaked, suggesting the blind spot was specific to certain",
    "selective: 10 of the 12 modes produced\n"
    "\\emph{zero} CoT leaks, while only indirect injection (4 of its 12 requests) and code\n"
    "interpretation (2 of its 9) leaked, suggesting the blind spot was specific to certain")

# ---- m5: "only 3 models" -> "only 3 entries ... 2 distinct backends" ----
add("K_census_3models",
    "found that only 3 models\n"
    "(8\\%) expose a usable reasoning channel---Nemotron-3-Super, Beam, and a third entry requested under the gateway's generic free-tier route, which resolves to Nemotron-3-Super on the probed requests---and every distinct backend among them leaks at 100\\% on the",
    "found that only 3 entries\n"
    "(8\\%) expose a usable reasoning channel---Nemotron-3-Super, Beam, and a third entry requested under the gateway's generic free-tier route, which resolves to Nemotron-3-Super on the probed requests, so 2 distinct backends---and every distinct backend among them leaks at 100\\% on the")

# ---- C5a: rbac2026 bib 删 SIGMOD 2027 声明 ----
add("L_rbac_bib",
    "role-based access control,'' \\emph{arXiv preprint arXiv:2607.22115}, 2026, to appear in Proc.\\ ACM Int.\\ Conf.\\ Manage.\\ Data (SIGMOD), 2027.",
    "role-based access control,'' \\emph{arXiv preprint arXiv:2607.22115}, 2026.")

# ---- C3c: 删除 peng2025 bibitem 块 ----
add("M_delete_peng_bibitem",
    "\\bibitem{peng2025}\n"
    "J.~Peng, ``Data privacy risks of large language models: A comprehensive review,''\n"
    "\\emph{Applied and Computational Engineering}, vol.\\ 218, pp.\\ 148--160, 2025.\n"
    "ISSN 2755-2721 (EWA Publishing).\n"
    "\\bibitem{huang2025}",
    "\\bibitem{huang2025}")

# ---- O: 删除死代码 \bibliographystyle{IEEEtran} ----
add("N_delete_bibstyle",
    "\\bibliographystyle{IEEEtran}\n"
    "\\begin{thebibliography}{99}",
    "\\begin{thebibliography}{99}")

# ---- C6: Related Work 补引 247 篇综述 ----
add("P_add_survey_cite",
    "content~\\cite{greshake}; and autonomous-agent surveys describe the tool-using agent stack targeted by the threat model~\\cite{agentsurvey}.\n\n"
    "\\section{Background and Threat Model}",
    "content~\\cite{greshake}; and autonomous-agent surveys describe the tool-using agent stack targeted by the threat model~\\cite{agentsurvey}. A 2026 survey of 247 papers on LLM agent security organises the field around information flow, delegated authority, and persistent state~\\cite{agentsurvey2026}; it does not treat the reasoning channel as a separately measured surface, which is the measurement target here.\n\n"
    "\\section{Background and Threat Model}")

# ---- C6: 补 agentsurvey2026 bibitem ----
add("Q_add_survey_bibitem",
    "autonomous agents,'' \\emph{arXiv preprint arXiv:2308.11432}, 2024.\n"
    "\\end{thebibliography}",
    "autonomous agents,'' \\emph{arXiv preprint arXiv:2308.11432}, 2024.\n"
    "\\bibitem{agentsurvey2026}\n"
    "Y.~Ling, S.~Yu, Z.~Chen, and C.~Fang, ``Toward Secure LLM Agents: Threat Surfaces,\n"
    "Attacks, Defenses, and Evaluation,'' \\emph{arXiv preprint arXiv:2606.10749}, 2026.\n"
    "\\end{thebibliography}")

# ---- C7: Limitations 良性样本 + c* 稳健性 ----
add("R_limitations_benign",
    "confusion matrix are deployment assumptions (the benign sample comprises 4\n"
    "records; sensitivity sweeps over observer quality change the oracle gap by\n"
    "only 0.0018), and split-across-boundary leakage remains parameterized rather",
    "confusion matrix are deployment assumptions (the benign sample comprises 4\n"
    "records; sensitivity sweeps over observer quality change the oracle gap by\n"
    "only 0.0018), and split-across-boundary leakage remains parameterized rather\n"
    "than observed. The equivalence-class threshold $c^{*}=0.50$ was selected on 8\n"
    "benign controls (a 12.5\\% false-positive rate of 1/8), so it is sensitive to a\n"
    "single benign sample and the defense recommendation is stated conditional on that\n"
    "sample size.")

# ---- C8: Limitations "fifteen backends across three gateway operators" 限定 ----
add("S_limitations_three_ops",
    "cross-vendor set, eight from the extension cohort across two quota windows,\n"
    "five from a third aggregator gateway):",
    "cross-vendor set, eight from the extension cohort across two quota windows,\n"
    "five from a third aggregator gateway): only two of the three operators provide\n"
    "clean probe-attributed comparisons, because on the third gateway several backends\n"
    "recite honeypot credentials in response to benign controls.")

# ---- C8: conclusion "fifteen distinct backends on three gateways" 限定 ----
add("T_conclusion_three_gateways",
    "the asymmetry replicates across fifteen distinct backends on three gateways---including",
    "the asymmetry replicates across fifteen distinct backends on three gateways (two of\n"
    "which provide clean probe-attributed comparisons)---including")

# ================= 执行 =================
src = open(TEX, encoding="utf-8", newline="").read()
# 文件为统一 CRLF；先归一化为 LF 以便用 \\n 写锚点，写回时再转 CRLF
assert src.count("\r\n") == src.count("\n"), "mixed line endings"
src = src.replace("\r\n", "\n")
orig = src
for name, old, new in EDITS:
    c = src.count(old)
    if c != 1:
        print("FAIL %s: count=%d (need 1)" % (name, c))
        sys.exit(1)
    src = src.replace(old, new, 1)

# replace_all: carlini2025 -> nasr2025（1 cite + 1 bibitem）
n_carlini = src.count("carlini2025")
if n_carlini != 2:
    print("FAIL carlini2025: count=%d (need 2)" % n_carlini)
    sys.exit(1)
src = src.replace("carlini2025", "nasr2025")

# 溯源复核：被删/被改的锚点不应再出现
for banned in ["peng2025", "uncontrolled database access named as the primary",
               "to appear in Proc.\\ ACM Int.\\ Conf.\\ Manage.\\ Data (SIGMOD), 2027.",
               "the measured two-layer stack", "bibliographystyle{IEEEtran}"]:
    if banned in src:
        print("FAIL leftover: %r" % banned)
        sys.exit(1)

# 新增锚点应存在
for required in ["\\cite{agentsurvey2026}", "\\bibitem{agentsurvey2026}",
                 "common-cause", "2.6--20.5\\%", "50.1\\% and input manipulation at 49.6\\%"]:
    if required not in src:
        print("FAIL missing new anchor: %r" % required)
        sys.exit(1)

tmp = TEX + ".p40.tmp"
open(tmp, "w", encoding="utf-8", newline="").write(src.replace("\n", "\r\n"))
os.replace(tmp, TEX)
print("OK: %d atomic edits + 1 replace_all applied; %d -> %d bytes"
      % (len(EDITS) + 1, len(orig), len(src)))