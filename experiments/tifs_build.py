#!/usr/bin/env python3
"""Three-pass pdflatex build of paper/p3_tifs.tex.

The local MiKTeX install has a WindowsShell/PATH misconfiguration: an entry in
PATH points at powershell.exe *the file* rather than a directory, so every
engine aborts with
    cannot retrieve attributes for the directory '...\\powershell.exe\\'
The only reliable fix is to strip PATH entries that resolve to a file before
spawning the engine. No MiKTeX configuration change is required.

Usage:  python experiments/tifs_build.py [--passes N]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAPER = os.path.join(ROOT, "paper")
PDFTEX = r"C:\CTEX\MiKTeX\miktex\bin\x64\pdflatex.exe"
MAIN = "p3_tifs"


def clean_env():
    """Strip PATH entries that resolve to a *file* (MiKTeX 24.1 ships a
    WindowsShell/PATH misconfiguration in which powershell.exe the file is on
    PATH, making engines abort with
        cannot retrieve attributes for the directory '...\\powershell.exe\\'
    ). Directory entries, including the MiKTeX bin dir that pdftex.exe needs to
    locate its miktex-* helpers, are kept.

    If the uncleaned environment already works, pdflatex is run uncleaned so
    helper lookup cannot break.
    """
    env = os.environ.copy()
    parts = env.get("PATH", "").split(os.pathsep)
    clean = [p for p in parts if p.strip() and not os.path.isfile(p)]
    env["PATH"] = os.pathsep.join(clean)
    env["MIKTEX_SHELLS"] = ""
    return env


def build_pass(env):
    cmd = [PDFTEX, "-interaction=nonstopmode", "-halt-on-error", MAIN + ".tex"]
    p = subprocess.run(cmd, cwd=PAPER, env=env, capture_output=True)
    return p, ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")


def summarize(tag, p, blob, i, passes):
    lines = blob.splitlines()
    errlines = [l for l in lines if l.startswith("!")]
    undef = [l for l in lines if "undefined" in l.lower()]
    overfull = [l for l in lines if "Overfull" in l]
    pages = [l for l in lines if "Output written" in l]
    out = ["=== PASS %d/%d (%s)  rc=%d" % (i, passes, tag, p.returncode)]
    out.append("    pages: %s" % (pages[-1] if pages else "UNKNOWN"))
    out.append("    fatal: %s" % (errlines if errlines else "none"))
    if undef:
        out.append("    undefined: %s" % undef[:15])
    if overfull:
        out.append("    overfull: %d" % len(overfull))
        out.extend("      " + o[:120] for o in overfull[:6])
    return "\n".join(out)


def run(passes=3, log=None):
    envs = [("cleaned", clean_env()), ("as-is", os.environ.copy())]
    buf = []
    for i in range(1, passes + 1):
        ok = False
        for tag, env in envs:
            p, blob = build_pass(env)
            buf.append(summarize(tag, p, blob, i, passes))
            if p.returncode == 0:
                ok = True
                break
        if not ok:
            break
    msg = "\n".join(buf)
    with open(log, "w", encoding="utf-8") as f:
        f.write(msg + "\n")
    print(msg)
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--log", default=os.path.join(PAPER, "p3_tifs_build.txt"))
    a = ap.parse_args()
    sys.exit(run(a.passes, a.log))
