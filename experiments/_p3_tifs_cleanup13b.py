#!/usr/bin/env python3
"""Pass-13 cleanup B: Rule 6 (question-style section headings -> statements),
Rule 8 (code identifiers: reasoning_content / content / dots3-note-prev /
FAKE_ / key_value / openrouter/free / ANSWER: <...> / bare URLs -> prose).

verify-then-apply: every OLD must be present exactly once before any write.
"""
import os, sys

PATH = r"C:/Users/Yi/WorkBuddy/2026-10-10-18-49-43/llm-attack-eval/paper/p3_tifs.tex"

pairs = [
    # ---- Rule 6: question headings ---------------------------------------
    ("\\section{Is There a Native Blind Spot in the Reasoning Channel?}",
     "\\section{The Native Blind Spot in the Reasoning Channel}"),
    ("\\section{What Is the Theoretical Boundary on Defense Stacking?\n"
     "\\textnormal{(calibrated-model analysis)}}",
     "\\section{The Theoretical Boundary on Defense Stacking\n"
     "\\textnormal{(calibrated-model analysis)}}"),
    ("\\section{Does Output-Side Filtering Reduce Total Leakage?}",
     "\\section{Output-Side Filtering and Total Leakage}"),
    ("\\section{Can a Defender Adapt Under Weak Signal?\n"
     "\\textnormal{(model-driven analysis)}}",
     "\\section{Adaptive Defense Under Weak Signal\n"
     "\\textnormal{(model-driven analysis)}}"),
    ("\\textbf{Whose leakage matters?}",
     "\\textbf{Consumer-side visibility determines which leaks matter.}"),
    # ---- Rule 8: code identifiers -----------------------------------------
    # reasoning_content / content
    ("models expose \\texttt{reasoning\\_content} alongside the final answer.",
     "models expose a reasoning trace alongside the final answer."),
    ("streams---a private reasoning trace (\\texttt{reasoning\\_content}) and a final",
     "streams---a private reasoning trace and a final"),
    ("\\texttt{reasoning\\_content} and the final answer. Output-side filtering (D30,",
     "the reasoning trace and the final answer. Output-side filtering (D30,"),
    ("asserts that\n\\texttt{reasoning\\_content} is non-empty for essentially all responses, so a",
     "asserts that\nthe reasoning trace is non-empty for essentially all responses, so a"),
    ("which returns both \\texttt{content} and\n\\texttt{reasoning\\_content}; the model is identified only as",
     "which returns both the final answer and\nthe reasoning trace; the model is identified only as"),
    ("reads \\texttt{reasoning\\_content} and the final answer separately: B1",
     "reads the reasoning trace and the final answer separately: B1"),
    ("asserts that\n\\texttt{reasoning\\_content} is non-empty for essentially all responses in all",
     "asserts that\nthe reasoning trace is non-empty for essentially all responses in all"),
    ("leak in \\texttt{reasoning\\_leak} rather than \\texttt{cot\\_leak}. None of the",
     "leak in a field named reasoning_leak rather than cot_leak. None of the"),
    ("itself.} $\\texttt{reasoning\\_content}$ does not exist in the",
     "itself.} The reasoning trace does not exist in the"),
    ("do not persist \\texttt{reasoning\\_content} in production logs, or",
     "do not persist the reasoning trace in production logs, or"),
    ("credential leaks appear in \\texttt{reasoning\\_content} on 14.55\\% of",
     "credential leaks appear in the reasoning trace on 14.55\\% of"),
    # dots3-note-prev (both \\texttt and prose forms)
    ("\\texttt{dots3-note-prev} per our disclosure agreement.",
     "the primary model under a disclosure agreement with the operator."),
    ("the model listing exposes exactly one model (\\texttt{dots3-note-prev}); all 25",
     "the model listing exposes exactly one model (the primary model); all 25"),
    ("reasoning). We use the dots3-note-prev high-tier pooled estimate (15/28, where 28 is the total",
     "reasoning). We use the primary model's high-tier pooled estimate (15/28, where 28 is the total"),
    ("Ref.\\ dots3-note-prev & -- & 15/28 & 53.6\\% & -- \\\\",
     "Ref.\\ primary model & -- & 15/28 & 53.6\\% & -- \\\\"),
    ("The dashed reference line is the dots3-note-prev high-tier pooled",
     "The dashed reference line is the primary model's high-tier pooled"),
    ("high-leak probe responses collected on dots3-note-prev (E4 producer arm,",
     "high-leak probe responses collected on the primary model (E4 producer arm,"),
    ("model is identified only as \\texttt{dots3-note-prev} under a disclosure agreement",
     "model is identified only as the primary model under a disclosure agreement"),
    ("five independent real samples of dots3-note-prev (B1, B3, E2b, E6,",
     "five independent real samples of the primary model (B1, B3, E2b, E6,"),
    ("statistically indistinguishable from the dots3-note-prev baseline at",
     "statistically indistinguishable from the primary model's baseline at"),
    ("only\n      dots3-note-prev exposes a parseable \\texttt{reasoning\\_content} field;",
     "only\n      the primary model exposes a parseable reasoning channel field;"),
    # FAKE_
    ("planted in the database (all keys carry a \\texttt{FAKE\\_} prefix; no real",
     "planted in the database (all keys carry a FAKE prefix; no real"),
    ("All 15 keys carry a\n\\texttt{FAKE\\_} prefix, so an attribution chain",
     "All 15 keys carry a FAKE prefix, so an attribution chain"),
    ("credentials bearing a \\texttt{FAKE\\_} prefix in a dedicated test database; no\nreal",
     "credentials bearing a FAKE prefix in a dedicated test database; no\nreal"),
    # key_value
    ("refusal text mentioning\n\\texttt{key\\_value} (a database field name the model paraphrased)---a string-level false positive",
     "refusal text mentioning a database field name it paraphrased---a string-level false positive"),
    # openrouter/free
    ("and a third open-router entry (\\texttt{openrouter/free})---but all three leak",
     "and a third open-router entry---but all three leak"),
    # ANSWER: <brief answer>
    ("constrained-decoding prompt (forcing the format \\texttt{ANSWER: \\textless brief\nanswer\\textgreater})---each against",
     "constrained-decoding prompt (forcing a structured-answer format)---each against"),
    # bare URLs
    ("on a second, independent gateway\n(\\url{https://api.kilo.ai/api/gateway}, provider AtlasCloud) using the same",
     "on a second, independent gateway (provider AtlasCloud) using the same"),
    ("(AtlasCloud, \\url{https://api.kilo.ai/api/gateway}). Points are per-model CoT",
     "(AtlasCloud). Points are per-model CoT"),
]

with open(PATH, "r", encoding="utf-8") as f:
    text = f.read()

errors = []
for i, (old, new) in enumerate(pairs):
    n = text.count(old)
    if n != 1:
        errors.append(f"pair {i}: expected 1 occurrence, found {n}\nOLD={old!r}")

if errors:
    sys.stderr.write("VERIFY FAILED -- no write performed:\n")
    sys.stderr.write("\n".join(errors))
    sys.exit(1)

for old, new in pairs:
    text = text.replace(old, new, 1)

tmp = PATH + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, PATH)
print(f"APPLIED {len(pairs)} replacements; new size {os.path.getsize(PATH)} bytes")