# -*- coding: utf-8 -*-
"""Pass-8: layout repairs introduced/exposed by Pass-7.

1. Table IV header `$p$ (vs.\\ reference)` overflows the column; restore the
   short header and define it in the footnote instead.
2. Table V (tab:agent) is the one pre-existing overfull box: an `lcc` tabular
   whose unwrappable `c` cells exceed \\columnwidth. Switch to p{} columns and
   move the long parenthetical out of the cell into the footnote.

Atomic write: any mismatch aborts and nothing is written.
"""
import io
import os
import re
import sys

PATH = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'


def to_regex(s):
    return r'\s+'.join(re.escape(t) for t in re.split(r'\s+', s) if t)


PAIRS = [
    # --- Table IV: short header, definition moved into the footnote ---------
    ("Model & Vendor & CoT leaks & Rate & $p$ (vs.\\ reference) \\\\",
     "Model & Vendor & CoT leaks & Rate & $p$ vs.\\ ref.\\\\"),

    ("{\\raggedright\\footnotesize Reference: dots3-note-prev pooled (B1+B3 arm A + E6); two-sided Fisher exact $p$ is computed against the reference.",
     "{\\raggedright\\footnotesize Reference row: dots3-note-prev pooled (B1+B3 arm A + E6). The `$p$ vs.\\ ref.' column is the two-sided Fisher exact $p$ of that model's leak count against the reference row."),

    # --- Table V: p{} columns, long parenthetical moved to the footnote -----
    ("\\begin{tabular}{lcc}\n\\toprule\nArm & Simulated & Real-calibrated \\\\\n\\midrule\nRandom & $-0.4482$ (23.6\\%) & $-0.3481$ (10.7\\%) \\\\\nStatic best single & $-0.1314$ (24.4\\%) & $-0.0294$ (0.0\\%, the no-defense\nconfiguration; its negative utility is observer false-positive cost) \\\\",
     "{\\setlength{\\tabcolsep}{4pt}%\n\\begin{tabular}{@{}p{2.3cm}p{2.75cm}p{2.75cm}@{}}\n\\toprule\nArm & Simulated & Real-calibrated \\\\\n\\midrule\nRandom & $-0.4482$ (23.6\\%) & $-0.3481$ (10.7\\%) \\\\\nStatic best single & $-0.1314$ (24.4\\%) & $-0.0294$ (0.0\\%) \\\\"),

    ("\\end{tabular}\n\\vspace{-4pt}\n{\\raggedright\\footnotesize Utility per request at $\\lambda=2$;",
     "\\end{tabular}}\n\\vspace{-4pt}\n{\\raggedright\\footnotesize Utility per request at $\\lambda=2$;"),
]


def main():
    with io.open(PATH, encoding='utf-8') as f:
        text = f.read()

    applied = 0
    for idx, (old, new) in enumerate(PAIRS, 1):
        rx = to_regex(old)
        n = len(re.findall(rx, text))
        if n != 1:
            sys.stderr.write('ABORT pair %d: regex found %d matches\n' % (idx, n))
            sys.stderr.write('OLD: %r\n' % old)
            return 1
        text = re.sub(rx, lambda m: new, text, count=1)
        applied += 1

    tmp = PATH + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, PATH)
    sys.stdout.write('OK: %d pairs applied, %d bytes\n'
                     % (applied, os.path.getsize(PATH)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
