#!/usr/bin/env python3
r"""Submission-readiness audit for paper/p3_tifs.tex (IEEE TIFS).

Checks the items an IEEE TIFS submission is actually screened for, from the
compiled artefacts rather than from assumption:

  * abstract word count (TIFS expects a short abstract; long ones are trimmed)
  * total body word count
  * figure / table / equation / reference counts
  * every \\label has a matching \\ref (and vice versa)
  * every \\cite key exists in the bibliography
  * every \\includegraphics path resolves on disk
  * IEEEtran 1.8b API traps (\journal, keywords env) are not present

Usage:  python experiments/tifs_audit.py
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAPER = os.path.join(ROOT, "paper")
TEX = os.path.join(PAPER, "p3_tifs.tex")
PDF = os.path.join(PAPER, "p3_tifs.pdf")
LOG = os.path.join(PAPER, "p3_tifs.log")

OUT = []


def add(s):
    OUT.append(s)
    print(s)


def words(text):
    # strip LaTeX control words, then count whitespace-separated tokens
    t = re.sub(r"\\[a-zA-Z]+\*?", " ", text)
    t = re.sub(r"[{}%$]", " ", t)
    return [w for w in t.split() if re.search(r"[A-Za-z0-9]", w)]


def main():
    tex = open(TEX, encoding="utf-8").read()
    m = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", tex, re.S)
    abstract = m.group(1) if m else ""
    n_abs = len(words(abstract))
    add("abstract words        : %d  %s" % (
        n_abs, "OK (<=200)" if n_abs <= 200 else "TOO LONG (>200)"))

    body = re.sub(r"\\begin\{thebibliography\}.*?\\end\{thebibliography\}",
                  "", tex, flags=re.S)
    n_body = len(words(body))
    add("body words (no refs)  : %d" % n_body)

    add("figures               : %d" % len(re.findall(r"\\begin\{figure", tex)))
    add("tables                : %d" % len(re.findall(r"\\begin\{table", tex)))
    add("equations             : %d" % len(re.findall(r"\\begin\{equation", tex)))
    add("references            : %d" % len(re.findall(r"\\bibitem\{", tex)))

    # label / ref cross-check
    labels = set(re.findall(r"\\label\{([^}]+)\}", tex))
    refs = set(re.findall(r"\\ref\{([^}]+)\}", tex))
    add("labels / refs         : %d / %d" % (len(labels), len(refs)))
    miss_r = refs - labels
    miss_l = labels - refs
    add("  refs without label  : %s" % (sorted(miss_r) or "none"))
    add("  unused labels       : %s" % (sorted(miss_l) or "none"))

    # cite keys vs bibitems
    cited = set()
    for g in re.findall(r"\\cite\{([^}]+)\}", tex):
        for k in g.split(","):
            cited.add(k.strip())
    bib = set(re.findall(r"\\bibitem\{\s*([^}\s]+)", tex))
    add("cite keys / bibitems  : %d / %d" % (len(cited), len(bib)))
    add("  cited but undefined : %s" % (sorted(cited - bib) or "none"))
    add("  defined but uncited : %s" % (sorted(bib - cited) or "none"))

    # graphics paths
    bad = []
    for rel in re.findall(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", tex):
        if not os.path.exists(os.path.join(PAPER, rel)):
            bad.append(rel)
    add("figure files          : %s" % ("all present" if not bad else bad))

    # IEEEtran 1.8b API traps
    traps = []
    if re.search(r"^\\journal\{", tex, re.M):
        traps.append("\\journal{} (removed in IEEEtran 1.8b)")
    if re.search(r"\\begin\{keywords\}", tex):
        traps.append("keywords environment (use \\IEEEkeywords{})")
    if "\\begin{document}" not in tex:
        traps.append("missing \\begin{document}")
    add("IEEEtran 1.8b traps   : %s" % (traps or "none"))

    # compile log
    if os.path.exists(LOG):
        log = open(LOG, encoding="utf-8", errors="replace").read()
        add("compile log fatal   : %s"
            % ([l for l in log.splitlines() if l.startswith("!")] or "none"))
        add("compile log overfull: %d" % len(re.findall(r"Overfull", log)))
        add("compile log undef   : %d"
            % len(re.findall(r"undefined", log, re.I)))
    if os.path.exists(PDF):
        add("PDF                 : %d bytes" % os.path.getsize(PDF))
    return 0


if __name__ == "__main__":
    sys.exit(main())
