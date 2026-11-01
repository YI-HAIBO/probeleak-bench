"""Align COVER_LETTER.md wording with p3_tifs.tex (Pass-39+).

Each edit is asserted to hit exactly once; the write is atomic
(.tmp -> os.replace) so the letter can never be left half-edited.
"""
import os, sys

LET = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "paper", "COVER_LETTER.md")

s = open(LET, encoding="utf-8").read()
orig = s

EDITS = [
    # --- catalog wording: match the paper's enumeration sentence ---------
    ("402-model catalog enumeration attributes the scarcity to the "
     "free-tier filter\nrather than to model architecture.",
     "catalog enumeration of 402 listed models (330 carrying "
     "reasoning-family keywords, only 15 free-tier)\nattributes the "
     "scarcity to the free-tier filter rather than to model architecture."),

    # --- cohort split: the paper writes these as fractions --------------
    ("the repetition and\nstress cohort is selection-conditioned (103/103)",
     "the repetition and\nstress cohort is selection-conditioned (103/103)"),

    # --- E8 paragraph: mirror the manuscript's exact figures ------------
    ("**Defence evidence is real, and bounded.** We measured the defenses "
     "against a\nreal attacker rather than against a template set. A second "
     "model on a different\ngateway generated a 36-prompt paraphrase corpus "
     "plus 8 benign controls, all judged\nagainst the same real responses. "
     "Undefended, 14 of 36 leak (38.9%). Exact\nfingerprint matching removes "
     "only the known templates, 12 of 36. Rewrite\nequivalence classes at "
     "radius c = 0.50 lower leakage to 4 of 36 at a 12.5%\ncontrol "
     "false-positive rate, and no radius eliminates the residual without\n"
     "blocking benign traffic: c = 0.75 reaches 0 of 36 but at an 87.5% "
     "control\nfalse-positive rate. A full-trace output-side firewall "
     "reaches 0 of 36 at a 0%\ncontrol false-positive rate, and stacking the "
     "two yields no measurable gain over\nthe output-side layer alone. Two "
     "bounds are stated in the text rather than\nsmoothed over: that firewall "
     "redacts the honeypot signatures themselves, so its\nzero is an upper "
     "bound, and the equivalence metric is lexical rather than\n"
     "embedding-based.",

     "**Defence evidence is real, and bounded.** We measured the defenses "
     "against a\nreal attacker rather than against a template set. A second "
     "real model produced a\n36-prompt corpus on the primary model --- 4 "
     "high-tier probes plus 32\nparaphrases in two rounds, the second "
     "conditioned on which first-round paraphrases\nhad leaked --- together "
     "with 8 benign controls, and every layer was evaluated on\nthose real "
     "responses. Undefended, 14 of 36 prompts leak (38.9%). Exact semantic\n"
     "fingerprinting blocks only the four templates the defender already "
     "holds and still\nlets 12 of 36 through, so paraphrasing recovers "
     "nearly the whole attack surface.\nExtending the fingerprint to "
     "rewrite-equivalence classes lowers the residual to\n4 of 36 at a 12.5% "
     "false-positive rate on the controls, and no radius removes the\n"
     "residual without also blocking benign traffic: at the smallest radius "
     "that reaches\nzero, 7 of 8 controls are blocked. The output-side layer "
     "shows a coverage effect\ninstead --- scanning half the reasoning trace "
     "still leaves 12 leaks and three\nquarters leaves 3, so the credential "
     "surfaces toward the end of the trace --- and\nreaches zero residual at "
     "no false-positive cost. Stacking the two layers brings no\nmeasurable "
     "gain over the output-side layer alone, so on real data the second "
     "layer\nadds false positives rather than security. Two caveats bound "
     "the measurement and\nare stated in the text rather than smoothed over: "
     "the output-side layer redacts the\nvery signatures the detector "
     "searches for, so its zero residual is an oracle bound,\nand the "
     "equivalence metric is lexical rather than learned."),
]

for old, new in EDITS:
    n = s.count(old)
    if n != 1:
        print("ABORT: edit hits %d times (want 1): %r"
              % (n, old[:70]))
        sys.exit(1)
    s = s.replace(old, new)
    print("ok: %r" % old[:60])

if s == orig:
    print("no change")
else:
    tmp = LET + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)
    os.replace(tmp, LET)
    print("\nwritten:", LET, len(s), "chars")
