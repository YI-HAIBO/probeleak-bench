"""Rename the new co-evolution-vs-adaptive-defense experiment from E9 to E10.

`results/e9_production_baseline_v1.json` already exists from an earlier
session, so the label E9 referred to two different experiments. This
renames the files and rewrites every internal token consistently so the
checkpoint ids, corpus pids and JSON paths all still agree with each other
(a rerun must resume, not regenerate).

Idempotent: running it twice is a no-op once the tokens are renamed.
"""
import io
import os
import shutil
import sys

ROOT = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval"
EXP = os.path.join(ROOT, "experiments")
RES = os.path.join(ROOT, "results")

# (old, new) -- order matters: longest/most specific first.
TOKENS = [
    ("e9_coevo_vs_adaptive_defense", "e10_coevo_vs_adaptive_defense"),
    ("e9_report_gen.py", "e10_report_gen.py"),
    ("e9_report.md", "e10_report.md"),
    ("_e9_preflight", "_e10_preflight"),
    ("e9_r", "e10_r"),          # covers gen_e9_r... and e9_r... pids
    ("E9", "E10"),              # prose only; uppercase, no clash
]

FILES = {
    os.path.join(EXP, "e9_coevo_vs_adaptive_defense.py"):
        os.path.join(EXP, "e10_coevo_vs_adaptive_defense.py"),
    os.path.join(EXP, "_e9_preflight.py"):
        os.path.join(EXP, "_e10_preflight.py"),
    os.path.join(EXP, "e9_report_gen.py"):
        os.path.join(EXP, "e10_report_gen.py"),
    os.path.join(RES, "e9_coevo_vs_adaptive_defense_v1.json"):
        os.path.join(RES, "e10_coevo_vs_adaptive_defense_v1.json"),
    os.path.join(RES, "e9_coevo_vs_adaptive_defense_checkpoint.ndjson"):
        os.path.join(RES, "e10_coevo_vs_adaptive_defense_checkpoint.ndjson"),
    os.path.join(RES, "e9_report.md"):
        os.path.join(RES, "e10_report.md"),
}


def rewrite(path):
    with io.open(path, "r", encoding="utf-8", newline="") as fh:
        s = fh.read()
    n_total = 0
    for old, new in TOKENS:
        n = s.count(old)
        if n:
            s = s.replace(old, new)
            n_total += n
            print("    %-52s %-8d -> %s (%d)" % (
                os.path.basename(path), n, old, n))
    if n_total:
        with io.open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(s)
    return n_total


def main():
    n_files = 0
    for old, new in FILES.items():
        if not os.path.exists(old):
            if os.path.exists(new):
                print("already renamed: %s" % os.path.basename(old))
            else:
                print("MISSING (skip): %s" % old)
            continue
        shutil.move(old, new)
        print("moved: %s -> %s" % (os.path.basename(old), os.path.basename(new)))
        n_files += 1
    print("files moved: %d" % n_files)
    print()
    n_tok = 0
    for path in sorted(set(FILES.values())):
        if not os.path.exists(path):
            continue
        print(os.path.basename(path))
        n_tok += rewrite(path)
    print()
    print("tokens rewritten: %d" % n_tok)
    return 0


if __name__ == "__main__":
    sys.exit(main())
