# -*- coding: utf-8 -*-
"""Pass-9: last two wording/quote fixes."""
import io
import os
import re
import sys

PATH = r'C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex'


def to_regex(s):
    return r'\s+'.join(re.escape(t) for t in re.split(r'\s+', s) if t)


PAIRS = [
    ("the model's own refusals are thus complementary but individually insufficient:",
     "the gateway and the model's own refusals cover different requests and are\nindividually insufficient:"),
    ("The `Experiments' column counts the campaigns contributing to each cohort (5 per cohort, 10 in total).",
     "The ``Experiments'' column counts the campaigns contributing to each cohort (5 per cohort, 10 in total)."),
]


def main():
    with io.open(PATH, encoding='utf-8') as f:
        text = f.read()
    applied = 0
    for idx, (old, new) in enumerate(PAIRS, 1):
        rx = to_regex(old)
        n = len(re.findall(rx, text))
        if n != 1:
            sys.stderr.write('ABORT pair %d: %d matches\n' % (idx, n))
            return 1
        text = re.sub(rx, lambda m: new, text, count=1)
        applied += 1
    tmp = PATH + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, PATH)
    sys.stdout.write('OK: %d pairs applied, %d bytes\n' % (applied, os.path.getsize(PATH)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
