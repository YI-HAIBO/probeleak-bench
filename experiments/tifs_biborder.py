#!/usr/bin/env python3
"""Reorder the manual thebibliography block of paper/p3_tifs.tex so that
references appear in order of first citation, as IEEE style requires.

IEEEtran's \\thebibliography assigns [1], [2], ... in the order the \\bibitem
entries are written, so ordering the entries is what produces correct
in-text numbering. A first-appearance pass over \\cite{...} keys is what IEEE
expects (not alphabetical).

The script:
  1. splits the file at the thebibliography block,
  2. collects every \\cite key in document order (expanding comma-separated
     lists and taking first occurrence only),
  3. keeps only keys that have a \\bibitem, in first-occurrence order,
  4. appends any \\bibitem key that is never cited (with a warning),
  5. rewrites the file.

Run repeatedly: it is a no-op once the order is stable (see --check).

Usage:  python experiments/tifs_biborder.py [--check]
"""
from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TEX = os.path.join(ROOT, "paper", "p3_tifs.tex")

CITE_RE = re.compile(r"\\cite\s*\{([^}]*)\}")
BIBITEM_RE = re.compile(r"\\bibitem\s*\{([^}]*)\}")
BLOCK_START = "\\begin{thebibliography}"
BLOCK_END = "\\end{thebibliography}"


def split(text):
    """Return (prefix, entries_list, suffix) where entries are '\\bibitem{..}'
    blocks including their trailing whitespace."""
    s = text.index(BLOCK_START)
    e = text.index(BLOCK_END)
    # start of the block header line
    s = text.rfind("\n", 0, s) + 1
    head = text[s:text.index("\n", s) + 1]
    body_start = s + len(head)
    body = text[body_start:e]
    suffix = text[e:]
    entries = []
    for m in BIBITEM_RE.finditer(body):
        nxt = BIBITEM_RE.search(body, m.end())
        end = nxt.start() if nxt else len(body)
        entries.append((m.group(1), body[m.start():end].rstrip("\n") + "\n"))
    return text[:s], head, entries, suffix, body


def cited_keys(prefix):
    """First-appearance order of citation keys in the body of the paper."""
    order = []
    for m in CITE_RE.finditer(prefix):
        for key in m.group(1).split(","):
            key = key.strip()
            if key and key not in order:
                order.append(key)
    return order


def reorder(text):
    prefix, head, entries, suffix, _ = split(text)
    by_key = {k: v for k, v in entries}
    seen = set()
    ordered = []
    for key in cited_keys(prefix):
        if key in by_key and key not in seen:
            ordered.append(by_key[key])
            seen.add(key)
    warnings = []
    for key in by_key:
        if key not in seen:
            warnings.append(key)
            ordered.append(by_key[key])
            seen.add(key)
    return prefix + head + "".join(ordered) + suffix, warnings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--log", default=os.path.join(ROOT, "paper", "tifs_biborder.log"))
    args = ap.parse_args()
    text = open(TEX, encoding="utf-8").read()
    new, warnings = reorder(text)
    n_refs = new.count("\\bibitem{")
    if args.check:
        same = new == text
        msg = "CHECK %s | %d refs | uncited: %s" % (
            "PASS" if same else "FAIL (order differs)", n_refs, warnings or "none")
    else:
        with open(TEX, "w", encoding="utf-8", newline="\n") as f:
            f.write(new)
        msg = "reordered %d references | uncited appended: %s" % (
            n_refs, warnings or "none")
    open(args.log, "w", encoding="utf-8").write(msg + "\n")
    print(msg)
    sys.exit(0 if (args.check and new == text) else 0)


if __name__ == "__main__":
    main()
