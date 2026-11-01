#!/usr/bin/env python3
"""Repair the Pass-39 README section (backticks were eaten by the shell shim).

Written as a file, not an inline -c, precisely because the inline form let
the shell treat the backtick-quoted paths as command substitution.
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
README = os.path.join(ROOT, "submission_2026-10-21", "README.md")

BT = chr(96)          # backtick, build the markdown spans without literals
def m(p):
    return BT + p + BT

SEC = """
## Pass-39 update

Task #103 (third quota window) and task #104 (real co-evolution arm, real
defense measurement) are now merged.

- Third quota window (""" + m("../results/e1e_third_window_v1.json") + """,
  """ + m("../results/e1e_b2_report.md") + """): the 30B--A3B Nano model repeated its
  second-window count exactly (14/24, 58.3 percent; p=1.0 against the
  second window, still p=0.002 against the first), so the drift is a step
  change that persists; Laguna XS 2.1 moved from 0/13 to 1/12 (p=0.48);
  Beam rotated out of the free pool; two further entries were blocked on
  all attempts. Table tab:e1b gained the window-3 rows.
- The adaptive-attacker replication on Nemotron-3.5-Lightning now runs the
  full forty episodes (""" + m("../results/b2_adaptive_replication_v1.json") + """):
  26/38 usable episodes leak (68.4 percent), the first leaks, the
  thinking-leak arms leak on 18/21 pulls and the final channel on none.
- Real co-evolution arm (""" + m("../results/e7_coevo_bandit_v1.json") + """,
  """ + m("../results/e7b_coevo_headtohead_v1.json") + """): a thirteenth arm whose text
  is generated at pull time by a second real model on a different
  operator. Under a fixed interleaved allocation the generated probes leak
  on 9/12 against 12/12 for the best fixed arm (Fisher p=0.22): rewriting
  buys nothing measurable over re-ranking on an undefended target.
- Real defense measurement (""" + m("../results/e8_real_defense_validation_v1.json") + """,
  """ + m("../results/e7_e8_report.md") + """): on a 36-prompt attacker-generated corpus
  plus 8 benign controls, undefended leakage is 14/36, exact fingerprinting
  still lets 12/36 through, rewrite-equivalence classes lower it to 4/36
  at a 12.5 percent control false-positive rate, and no radius removes the
  residual without blocking benign traffic; the output-side layer needs a
  full-trace scan (half leaves 12 leaks, three quarters leaves 3).
  Stacking shows no measurable gain over the output-side layer alone. Both
  caveats (oracle redaction, lexical equivalence metric) are stated in the
  text.
"""


def main():
    s = open(README, encoding="utf-8").read()
    i = s.find("## Pass-39 update")
    if i < 0:
        print("no Pass-39 section; appending")
        s = s.rstrip() + "\n" + SEC
    else:
        s = s[:i].rstrip() + "\n" + SEC
    s = s.replace("(15 pages, IEEEtran journal class)",
                  "(16 pages, IEEEtran journal class)")
    open(README, "w", encoding="utf-8").write(s)
    print("README ->", len(s), "chars")
    j = s.find("## Pass-39 update")
    print(s[j:j + 520])


if __name__ == "__main__":
    main()
