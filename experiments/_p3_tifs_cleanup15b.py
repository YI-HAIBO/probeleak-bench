#!/usr/bin/env python3
"""Pass-15b: define undefined terms and clarify confusing passages.
  - 'verdict triple' definition
  - 'extended reasoning' definition
  - 'five-strategy ladder' definition
  - 'binding branch' definition
  - 'naive recomputations' clarification
  - 'trace identifiers preserved' clarification
  - HTTP status codes: add brief explanation on first use
  - JSON: expand on first use
verify-then-apply, atomic write."""

import os, re, sys, shutil

SRC = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\paper\p3_tifs.tex"
NL = chr(10)

EDITS = []

# --- 'verdict triple' definition (first use in Reproducibility failure) -----
EDITS.append((
    "it compares" + NL + "the verdict triple across repeats of the same probe, so its unit is the probe",
    "it compares" + NL + "the three-part verdict (final-answer leak, reasoning-channel leak, refusal) across repeats of the same probe, so its unit is the probe",
    1,
))

# --- 'extended reasoning' definition (first use in displacement problem) ----
EDITS.append((
    "the worst combination, thinking leak under extended reasoning, falls",
    "the worst combination, thinking leak under a prompt that elicits extended reasoning, falls",
    1,
))

# --- 'five-strategy ladder' definition (red-team run) ------------------------
EDITS.append((
    "a five-strategy ladder (indirect injection,\nkey extraction from exposed CoT, code interpretation, multi-turn escalation,\ntranslation exfiltration)",
    "a five-strategy ladder (indirect injection, key extraction from exposed CoT, code interpretation, multi-turn escalation, translation exfiltration)",
    1,
))

# --- 'binding branch' definition (earlier measurement correction) -----------
EDITS.append((
    "its binding branch\nrewrote the per-layer marginals at $\\rho=1$",
    "its binding branch (the $\\rho=1$ case, which is the branch that determines the achievable maximum)\nrewrote the per-layer marginals at $\\rho=1$",
    1,
))

# --- 'naive recomputations' clarification -----------------------------------
EDITS.append((
    "Three successive naive recomputations of this\none statistic disagreed by up to 5.2 percentage points because each applied a different record filter: per-sample counts\ninclude only attack-kind traffic, whereas the naive scans also counted benign,\nnegative-control, and ablation records; in addition the stress test stores the reasoning leak under a field\nname that differs from the one used by other runs. None of the\nnaive variants reconciles with the underlying records, and none is\nreported in this paper.",
    "Three successive naive recomputations of this\none statistic disagreed by up to 5.2 percentage points because each applied a different record filter: per-sample counts\ninclude only attack-kind traffic, whereas the naive scans also counted benign,\nnegative-control, and ablation records; in addition the stress test stores the reasoning leak under a field\nname that differs from the one used by other runs. None of the\nnaive variants reconciles with the underlying records, and none is\nreported in this paper. By \\emph{naive recomputations} we mean pooled-rate estimates that apply an undocumented filter to the raw records, without the reconciliation script that maps every reported figure to its JSON field (Section~\\ref{sec:reproducibility}).",
    1,
))

# --- 'trace identifiers preserved' clarification ----------------------------
EDITS.append((
    "with per-model error bodies and\ntrace identifiers preserved.",
    "with per-model error bodies and\ntrace identifiers preserved (each response carries a unique identifier that allows the operator to correlate the error with the request, though the identifiers are not released).",
    1,
))

# --- HTTP status codes: first use in Anti-cherry-picking (line ~408) --------
EDITS.append((
    "the third role-play probe entirely gateway-blocked by HTTP 403 and one\nfurther request failing",
    "the third role-play probe entirely gateway-blocked by the upstream content-safety layer (HTTP 403, Forbidden) and one\nfurther request failing",
    1,
))

# --- HTTP status codes: second use in Public-benchmark cross-validation ----
EDITS.append((
    "Eight requests succeeded and eight were blocked\nby the gateway with HTTP 403 (tool-use side-effect, instruction-conflict,\nprompt-injection, and context-extraction modes).",
    "Eight requests succeeded and eight were blocked\nby the gateway with HTTP 403 (Forbidden; the upstream content-safety layer rejects the request before it reaches the model, for tool-use side-effect, instruction-conflict,\nprompt-injection, and context-extraction modes).",
    1,
))

# --- HTTP status codes: in Cross-model generality --------------------------
EDITS.append((
    "all 25\nprobed candidate identifiers returned HTTP 400 (``model is not configured'') or\nHTTP 403 (``key not bound to this model''), with per-model error bodies and",
    "all 25\nprobed candidate identifiers returned HTTP 400 (Bad Request; ``model is not configured'') or\nHTTP 403 (Forbidden; ``key not bound to this model''), with per-model error bodies and",
    1,
))

# --- HTTP status codes: in Model census ------------------------------------
EDITS.append((
    "gateway errors (HTTP 401 paid-model authorization required, HTTP 404 model-not-found, or empty responses)",
    "gateway errors (HTTP 401 Unauthorized, paid-model authorization required; HTTP 404 Not Found, model-not-found; or empty responses)",
    1,
))

# --- HTTP status codes: in Limitations -------------------------------------
EDITS.append((
    "others return HTTP 400 or 403 with response bodies that distinguish",
    "others return HTTP 400 (Bad Request) or HTTP 403 (Forbidden) with response bodies that distinguish",
    1,
))

# --- HTTP status codes: in operational-baseline probe set ------------------
EDITS.append((
    "24 successful responses from 27 requests; 3 failed\nwith HTTP 502).",
    "24 successful responses from 27 requests; 3 failed\nwith HTTP 502 (Bad Gateway, the upstream gateway returned an invalid response).",
    1,
))

# --- JSON: first use in Reproducibility discipline --------------------------
EDITS.append((
    "Every experiment runs under fixed,\nisolated random streams (separate seeds for request-class, outcome, and\nexploration), and every report and dashboard is produced by an idempotent\ngenerator that re-reads the JSON artifacts; re-running any generator reproduces\nthe report byte for byte (verified by content-based comparison).",
    "Every experiment runs under fixed,\nisolated random streams (separate seeds for request-class, outcome, and\nexploration), and every report and dashboard is produced by an idempotent\ngenerator that re-reads the JSON artifacts (structured records storing per-response verdicts, gate results, and digests); re-running any generator reproduces\nthe report byte for byte (verified by content-based comparison).",
    1,
))

# --- 'non-zero' terminology: replace with plain language -------------------
EDITS.append((
    "The simulation treats each layer as having\na non-zero failure rate $b_i$, so that $\\rho$ can be estimated.",
    "The simulation treats each layer as having\na positive failure rate $b_i$, so that $\\rho$ can be estimated.",
    1,
))

EDITS.append((
    "the best nonzero\ndefense has net benefit",
    "the best positive-benefit\ndefense has net benefit",
    1,
))

# (removed: 'oracle's nonzero residual' was part of a heading already
#  de-emphasised in Pass-15a; the phrase no longer appears in body text.)

# --- 'exits non-zero' command-line term in Reproducibility -----------------
EDITS.append((
    "expose a check mode that exits\nnon-zero if a regenerated artifact differs from the stored one.",
    "expose a check mode that signals failure (by a non-zero exit status) if a regenerated artifact differs from the stored one.",
    1,
))


def main():
    if not os.path.exists(SRC):
        print("FATAL: source missing", file=sys.stderr)
        return 2
    s = open(SRC, encoding="utf-8").read()
    orig = s
    for i, (old, new, exp) in enumerate(EDITS):
        c = s.count(old)
        if c != exp:
            print(f"VERIFY FAIL edit#{i}: count={c} expected={exp}  OLD={old[:80]!r}", file=sys.stderr)
            return 1
    for i, (old, new, exp) in enumerate(EDITS):
        s = s.replace(old, new, exp)
    if s == orig:
        print("NO CHANGE", file=sys.stderr)
        return 1
    if s.count("{") != s.count("}"):
        print(f"BRACE UNBALANCED: {{={s.count('{')} }}={s.count('}')}", file=sys.stderr)
        return 1
    tmp = SRC + ".tmp15b"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(s)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(SRC, tmp)
    os.replace(tmp, SRC)
    print(f"OK 15b: {len(EDITS)} edits applied, {len(orig)} -> {len(s)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())