import os
path = 'C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/.workbuddy/memory/2026-10-22.md'
addition = """

## p3 Pass-28 (cleanup28.py, 1 script, 2 edits, done) -- remove parentheses from titles

User: "标题不要包含括号". Searched for textnormal{(} in tex, found 2 hits, both section
title subtitles in parentheses:
- L703-704: section{Theoretical Boundary on Defense Stacking textnormal{(calibrated-model analysis)}}
- L931-932: section{Adaptive Defense Under Weak Signal textnormal{(model-driven analysis)}}

Fix: removed both textnormal{(...)} subtitle lines, titles are now clean:
- "Theoretical Boundary on Defense Stacking"
- "Adaptive Defense Under Weak Signal"

Verification:
- tifs_build.py 3-pass rc=0, 14 pages, 549,970 B (down from 15 after Pass-27 caption fix)
- tifs_audit.py all gates pass: abstract 199 words, 7 figs 6 tables 1 eq, 53 refs,
  53/53 cite closed, fatal 0/overfull 0/undef 0
"""
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()
with open(path, 'w', encoding='utf-8') as f:
    f.write(content + addition)
print('appended Pass-28 record')