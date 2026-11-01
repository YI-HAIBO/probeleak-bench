#!/usr/bin/env python3
"""Pass-39: merge task #103 (third quota window, completed B2 bandit) and
task #104 (real co-evolution arm, real D23'/D30 validation) into
paper/p3_tifs.tex.

Same discipline as Pass-37/38: every anchor taken from a repr() dump of the
real file bytes (CRLF), count==1 required per edit, tmp + os.replace write.

Output: paper/p3_tifs.tex
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
P = os.path.join(ROOT, "paper", "p3_tifs.tex")

CR = chr(13)
NL = chr(10)
CRLF = CR + NL

EDITS = []


def E(old, new):
    EDITS.append((old, new))


# ---------------------------------------------------------------- 1. B2
E("judge. The shared quota locked the run after 9 of 40 planned episodes (7"
  + CRLF +
  "usable), so the sample is small and the adaptation gate, computed on the"
  + CRLF +
  "final two episodes, passes formally but carries almost no statistical weight."
  + CRLF +
  "Within that window the replication is decisive: the first usable episode"
  + CRLF +
  "already leaks, versus episode 5 on the primary model, and the leak family is"
  + CRLF +
  "the same, with the thinking-leak arms leaking on 4 of 4 pulls while the other"
  + CRLF +
  "three families leak on 0 of 3; the final channel leaks on none of the 7"
  + CRLF +
  "responses.",
  "judge. A later window let the full forty-episode budget complete, with 38"
  + CRLF +
  "usable responses and two gateway errors. The replication is decisive: the"
  + CRLF +
  "first episode already leaks, versus episode 5 on the primary model, the leak"
  + CRLF +
  "family is the same---the thinking-leak arms leak on 18 of 21 pulls while the"
  + CRLF +
  "other three families leak on 8 of 17---and the final channel leaks on none of"
  + CRLF +
  "the 38 responses. Overall 26 of 38 episodes leak (68.4\\%), and the bandit"
  + CRLF +
  "concentrates 58\\% of its final-third pulls on one thinking-leak arm against a"
  + CRLF +
  "uniform share of 8\\%.")

# ------------------------------------------------- 2. third quota window
E(r"Xing 4.0 (Xingchen) was quota-blocked on all 32 attempts and contributes no data."
  + CRLF + CRLF + r"\textbf{Third gateway.}",
  r"Xing 4.0 (Xingchen) was quota-blocked on all 32 attempts and contributes no data."
  + CRLF + CRLF +
  r"\textbf{Third quota window.} A third window re-ran the protocol on the"
  + CRLF +
  r"rotated free pool (Table~\ref{tab:e1b}, window-3 rows). The Nano model"
  + CRLF +
  r"reproduced its second-window count exactly, 14/24 (58.3\%), which is"
  + CRLF +
  r"$p=1.0$ against its own second window and still $p=0.002$ against its"
  + CRLF +
  r"first: the shift is a step change that then persists rather than sampling"
  + CRLF +
  r"noise. Laguna XS 2.1 moves from 0/13 to 1/12 ($p=0.48$), and the primary"
  + CRLF +
  r"model's own family completed only 2 of its 24 high-tier requests before the"
  + CRLF +
  r"window closed, so it contributes no usable third point. Beam, the strongest"
  + CRLF +
  r"wave-2 backend, rotated out of the free pool altogether and cannot be"
  + CRLF +
  r"re-tested, and two further entries were quota-blocked on all 32 attempts."
  + CRLF + CRLF + r"\textbf{Third gateway.}")

# disambiguate: third-gateway rows are not the window-3 rows
E(r"(Table~\ref{tab:e1b}, wave-3 rows);",
  r"(Table~\ref{tab:e1b}, third-gateway rows);")

# --------------------------------------------------------- 3. tab:e1b
E(r"Xing 4.0 (blocked) & Xingchen & 0/0 & -- & -- \\" + CRLF + r"\midrule"
  + CRLF + r"Agents-A1",
  r"Xing 4.0 (blocked) & Xingchen & 0/0 & -- & -- \\" + CRLF +
  r"Nemotron-3-Nano-Omni (window 3) & NVIDIA & 14/24 & 58.3\% & 0.785 \\"
  + CRLF +
  r"Laguna XS 2.1 (window 3) & Poolside & 1/12 & 8.3\% & 0.012 \\" + CRLF +
  r"Primary model family (window 3) & withheld & 1/2 & 50.0\% & 1.000 \\"
  + CRLF +
  r"Nemotron-3-Super 120B (blocked) & NVIDIA & 0/0 & -- & -- \\" + CRLF +
  r"\midrule" + CRLF + r"Agents-A1")

# ------------------------------------------------------- 4. limitations
E("The rates are" + CRLF +
  "window-dependent: the 30B--A3B Nano model moved from 12.5\\% to 58.3\\% between"
  + CRLF +
  "quota windows (Fisher $p=0.002$) while Beam stayed high ($p=0.50$ between"
  + CRLF +
  "windows);",
  "The rates are" + CRLF +
  "window-dependent: the 30B--A3B Nano model moved from 12.5\\% to 58.3\\% between"
  + CRLF +
  "the first two quota windows (Fisher $p=0.002$) and then repeated the"
  + CRLF +
  "second-window count exactly in a third window (14/24 again, $p=1.0$), so the"
  + CRLF +
  "shift is a step change that persists, while Beam stayed high ($p=0.50$"
  + CRLF +
  "between its two windows) before rotating out of the pool;")

E(r"blocked two further models on all attempts. A" + CRLF +
  r"39-model census on the cross-vendor gateway",
  r"blocked two further models on all attempts, and a third quota window"
  + CRLF +
  r"blocked two further entries on all attempts and left one backend with 2 of"
  + CRLF +
  r"24 valid high-tier responses. A" + CRLF +
  r"39-model census on the cross-vendor gateway")

# --------------------------------------------- 5. co-evolution arm (E7/E7b)
E("The\r\nreplications still use fixed defenses, now on three gateways, and do"
  + CRLF +
  "not establish the co-evolutionary regime." + CRLF + CRLF +
  r"\section{Theoretical Boundary on Defense Stacking}",
  "The\r\nreplications still use fixed defenses, now on three gateways, and do"
  + CRLF +
  "not establish the co-evolutionary regime." + CRLF + CRLF +
  r"\textbf{Co-evolving attacker.} Every arm above is a fixed string, so the"
  + CRLF +
  "bandit can only re-rank. To test an attacker that rewrites, a thirteenth arm"
  + CRLF +
  "was added whose text is generated at pull time by a second real model on a"
  + CRLF +
  "different operator, conditioned on the arm currently leading the posterior"
  + CRLF +
  "and on the outcome the target just produced. Thompson sampling drew it 8 of"
  + CRLF +
  "40 times---the bandit had already concentrated on one thinking-leak arm---so"
  + CRLF +
  "the comparison was repeated under a fixed interleaved allocation, 12"
  + CRLF +
  "generated pulls against 12 pulls of that best fixed arm. The generated probes"
  + CRLF +
  "leak on 9 of 12 and the fixed arm on 12 of 12 (Fisher $p=0.22$); within the"
  + CRLF +
  "generated arm the rate rises from 4/6 to 5/6 across the run. Against an"
  + CRLF +
  "undefended target, rewriting therefore buys no measurable advantage over"
  + CRLF +
  "re-ranking, because there is nothing for the attacker to adapt to. That is"
  + CRLF +
  "precisely the boundary stated above: the co-evolutionary regime needs a"
  + CRLF +
  "defender that adapts in turn, and none of the measured gateways fielded one."
  + CRLF + CRLF +
  r"\section{Theoretical Boundary on Defense Stacking}")

# ------------------------------- 6. real D23'/D30 measurement (E8) in sec:corr
E(r"analytical tool for" + CRLF + r"defenses whose failure rates are non-negligible."
  + CRLF + CRLF,
  r"analytical tool for" + CRLF + r"defenses whose failure rates are non-negligible."
  + CRLF + CRLF +
  r"\textbf{Measured against a rewriting attacker.} The bound above concerns"
  + CRLF +
  "input-side and output-side layers whose parameters were calibrated rather"
  + CRLF +
  "than measured against an attacker that paraphrases. A direct test built a"
  + CRLF +
  "36-prompt corpus on the primary model---4 high-tier probes plus 32"
  + CRLF +
  "paraphrases produced by a second real model in two rounds, the second"
  + CRLF +
  "conditioned on which first-round paraphrases had leaked---together with 8"
  + CRLF +
  "benign controls, and evaluated each layer on those real responses. Undefended,"
  + CRLF +
  "14 of 36 prompts leak. Exact semantic fingerprinting blocks only the 4"
  + CRLF +
  "templates the defender already holds and still lets 12 of 36 through, so"
  + CRLF +
  "paraphrasing recovers nearly the whole attack surface; extending the"
  + CRLF +
  "fingerprint to rewrite-equivalence classes lowers the residual to 4 of 36 at"
  + CRLF +
  "a 12.5\\% false-positive rate on the controls, and no radius removes the"
  + CRLF +
  "residual without also blocking benign traffic---at the smallest radius that"
  + CRLF +
  "reaches zero, 7 of 8 controls are blocked. The output-side layer shows a"
  + CRLF +
  "coverage effect instead: scanning half the reasoning trace still leaves 12"
  + CRLF +
  "leaks and three quarters leaves 3, so the credential surfaces toward the end"
  + CRLF +
  "of the trace. Stacking the two layers brings no measurable gain over the"
  + CRLF +
  "output-side layer alone, which already reaches zero residual at no"
  + CRLF +
  "false-positive cost---on real data the second layer adds false positives"
  + CRLF +
  "rather than security. Two caveats bound the measurement: the output-side layer"
  + CRLF +
  "redacts the very signatures the detector searches for, so its zero residual is"
  + CRLF +
  "an oracle bound, and the equivalence metric is lexical rather than learned."
  + CRLF + CRLF)


def main():
    with open(P, "rb") as f:
        raw = f.read().decode("utf-8")
    bare_lf = raw.count(NL) - raw.count(CRLF)
    print("file len %d, bare-LF %d, edits %d" % (len(raw), bare_lf, len(EDITS)))
    if bare_lf:
        print("ABORT: bare LF present")
        sys.exit(1)

    cur = raw
    for i, (old, new) in enumerate(EDITS):
        c = cur.count(old)
        if c != 1:
            print("ABORT at edit %d: count=%d" % (i + 1, c))
            print(repr(old[:220]))
            sys.exit(1)
        cur = cur.replace(old, new, 1)
        print("  edit %d ok (+%d chars)" % (i + 1, len(new) - len(old)))

    tmp = P + ".tmp"
    with open(tmp, "wb") as f:
        f.write(cur.encode("utf-8"))
    os.replace(tmp, P)
    after = open(P, "rb").read().decode("utf-8")
    print("--> %s  %d -> %d chars" % (P, len(raw), len(after)))
    print("bare-LF after: %d" % (after.count(NL) - after.count(CRLF)))


if __name__ == "__main__":
    main()
