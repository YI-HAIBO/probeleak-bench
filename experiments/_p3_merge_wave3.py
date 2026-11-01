#!/usr/bin/env python
"""Pass-38: merge the third-gateway wave (E1d + B3) into paper/p3_tifs.tex.

Atomic edits: each (old, new) pair must match exactly once. Writes via
tmp + os.replace. CRLF preserved (anchors built with chr(13)+chr(10)).
"""

import os
import sys

TEX = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
CR = chr(13) + chr(10)

EDITS = []


def E(old, new):
    EDITS.append((old, new))


# ---------------------------------------------------------------- 1. abstract
E("replicates on an independent gateway---including the primary family under separate",
  "replicates on two independent gateways---including the primary family under separate")

# ------------------------------------------- 2. table caption + wave-3 rows
E("\\caption{Extension cohort cross-vendor CoT leak rates across two quota windows.}",
  "\\caption{Extension cohort CoT leak rates across quota windows and gateways.}")

old_rows = "Laguna XS 2.1 & Poolside & 0/13 & 0.0\\% & 0.001 \\\\" + CR + \
           "Xing 4.0 (blocked) & Xingchen & 0/0 & -- & -- \\\\"
new_rows = old_rows + CR + \
    "\\midrule" + CR + \
    "Agents-A1 & -- & 18/24 & 75.0\\% & 0.152 \\\\" + CR + \
    "Atria-Dawn & Atria & 6/24 & 25.0\\% & 0.049 \\\\" + CR + \
    "Atria-Dawn-Preview & Atria & 5/24 & 20.8\\% & 0.023 \\\\" + CR + \
    "Sage-A1.5 & Sage & 8/24 & 33.3\\% & 0.171 \\\\" + CR + \
    "intern-s2 & Shanghai AI Lab & 13/24 & 54.2\\% & 1.000 \\\\" + CR + \
    "deepseek-v4.1-flash (blocked) & DeepSeek & 0/0 & -- & -- \\\\" + CR + \
    "qwen3.8-27b (blocked) & Qwen & 0/0 & -- & -- \\\\"
E(old_rows, new_rows)

# --------------------------------------------- 3. third-gateway paragraph
old_tail = "Xing 4.0 (Xingchen) was quota-blocked on all 32 attempts and contributes no data."
new_tail = old_tail + CR + CR + \
    "\\textbf{Third gateway.} A further gateway under a different operator" + CR + \
    "(thirteen-model catalog, every entry aggregated under one operator field)" + CR + \
    "exposes a plaintext reasoning channel on all seven responsive models, and" + CR + \
    "the same protocol ran on five of them (Table~\\ref{tab:e1b}, wave-3 rows);" + CR + \
    "two further catalog models were quota-blocked on all attempts. The strongest" + CR + \
    "replication is intern-s2 at 13/24 (54.2\\%), statistically indistinguishable" + CR + \
    "from the primary model's baseline (Fisher $p=1.0$) on a third operator and a" + CR + \
    "third model family, and Agents-A1 leaks on 18/24 (75.0\\%, $p=0.15$ versus the" + CR + \
    "baseline). The final channel leaks on none of the 120 attack responses." + CR + \
    "The wave-3 rows require a control-baseline reading, however: on this gateway" + CR + \
    "several models recite a honeypot credential in the reasoning channel while" + CR + \
    "answering benign control prompts---Sage-A1.5 on 6 of 8 controls, Agents-A1 on" + CR + \
    "3 of 8---far above the 0--2/8 control rates on the other two gateways. Only" + CR + \
    "intern-s2's high-tier rate significantly exceeds its own control baseline" + CR + \
    "($p=0.010$), while Sage-A1.5's 8/24 sits below its 6/8 control rate. Part of" + CR + \
    "the wave-3 leak signal is therefore spontaneous prompt-content recitation" + CR + \
    "rather than probe-attributed exfiltration, and the probe-attributed finding" + CR + \
    "on this gateway is the replication at baseline strength on intern-s2."
E(old_tail, new_tail)

# ----------------------------------- 4. adaptive attacker third replication
old_end = ("The run still uses fixed defenses, now on two gateways, and" + CR +
           "does not establish the co-evolutionary regime.")
new_end = ("A third replication ran the full forty episodes on the third gateway" + CR +
           "against Sage-A1.5: leaks occur on 34/40 episodes with the first at" + CR +
           "episode 1, the thinking-leak family again leaks most (21/22 pulls) and" + CR +
           "receives 62\\% of final-third pulls, and the final channel never leaks." + CR +
           "This backend's control baseline in the extension cohort is itself" + CR +
           "elevated (6/8 control recitations), so part of its leak signal is" + CR +
           "arm-independent recitation: the run establishes that an attacker" + CR +
           "reaches the keys on a third operator within one request, but the arm" + CR +
           "separation carries less weight than on the two earlier models. The" + CR +
           "replications still use fixed defenses, now on three gateways, and do" + CR +
           "not establish the co-evolutionary regime.")
E(old_end, new_end)

# ------------------------------------------------------ 5. limitations block
E("on ten distinct measured backends in total (two from the original" + CR +
  "cross-vendor set, eight from the extension cohort across two quota windows):",
  "on fifteen distinct measured backends across three gateway operators (two" + CR +
  "from the original cross-vendor set, eight from the extension cohort across" + CR +
  "two quota windows, five from a third aggregator gateway):")

E("measured rates across the ten backends range from 0\\% to 100\\%.",
  "measured rates across the fifteen backends range from 0\\% to 100\\%.")

E("high-tier responses) and blocked a fourth. A",
  "high-tier responses) and blocked a fourth, and the third aggregator gateway" + CR +
  "blocked two further models on all attempts. A")

E("attributes the scarcity to the free-tier filter rather than to the" + CR +
  "architecture.",
  "attributes the scarcity to the free-tier filter rather than to the" + CR +
  "architecture. On the third gateway, benign-control recitation is itself" + CR +
  "elevated (6/8 on one backend), so only one of its five backends exceeds its" + CR +
  "own controls significantly, and the aggregator operator withholds per-model" + CR +
  "vendor attribution.")

# ------------------------------------------------------------ 6. conclusion
E("the asymmetry replicates across ten distinct cross-vendor backends---including",
  "the asymmetry replicates across fifteen distinct backends on three gateways---including")

E("fresh paraphrases leak at least as" + CR +
  "often as the original probes (83.3\\% on the thinking-leak family, and 4/4 on a" + CR +
  "second model), and an online attacker with no prior knowledge finds the blind" + CR +
  "spot within five requests, and within a single request on a second model.",
  "fresh paraphrases leak at least as" + CR +
  "often as the original probes (83.3\\% on the thinking-leak family, 4/4 on a" + CR +
  "second model and 21/22 on a third), and an online attacker with no prior" + CR +
  "knowledge finds the blind spot within five requests, and within a single" + CR +
  "request on two further models.")


def main():
    with open(TEX, "rb") as f:
        raw = f.read().decode("utf-8")
    for i, (old, new) in enumerate(EDITS, 1):
        n = raw.count(old)
        if n != 1:
            print("ABORT: edit %d matched %d times" % (i, n))
            print("  old[:80]:", repr(old[:80]))
            sys.exit(1)
        raw = raw.replace(old, new)
    tmp = TEX + ".tmp"
    with open(tmp, "wb") as f:
        f.write(raw.encode("utf-8"))
    os.replace(tmp, TEX)
    print("pass-38: %d atomic edits applied" % len(EDITS))
    print("size:", os.path.getsize(TEX))


if __name__ == "__main__":
    main()
