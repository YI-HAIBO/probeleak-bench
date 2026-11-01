"""Add a per-trace redaction comparison to the E10 artifact.

The report's claim that D30b is a substitute for the oracle rule rests on a
corpus-level number (both give 0/36 bypass). That is true but incomplete:
the two rules remove different text, and the direction matters. This script
computes the trace-by-trace difference and writes it into the JSON as
`redaction_comparison`, so the report generator stays a pure function of the
artifact.

Local only: reads the checkpoint JSON, no network calls.
"""
import io
import json
import os
import sys

BASE = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval"
RES = os.path.join(BASE, "results")
EXP = os.path.join(BASE, "experiments")
SRC = os.path.join(RES, "e10_coevo_vs_adaptive_defense_v1.json")
JSON_KEYS = os.path.join(RES, "e10_coevo_vs_adaptive_defense_v1.json")

sys.path.insert(0, EXP)

from p1_real_cot_validation import KEY_SIGNATURES  # noqa: E402
from e10_coevo_vs_adaptive_defense import (  # noqa: E402
    redact_oracle,
    redact_shape,
)

TOKEN = "[REDACTED]"


def build(j):
    base_keys = [k for k in KEY_SIGNATURES if k.startswith("FAKE_")]
    leaking = [r for r in j["records"] if r.get("cot_key_hits")]

    traces = []
    for r in leaking:
        text = r.get("reasoning") or ""
        ora = redact_oracle(text, 1.0)[0]
        sha = redact_shape(text, 1.0)[0]
        no, ns = ora.count(TOKEN), sha.count(TOKEN)
        if ora == sha:
            direction = "identical"
        elif ns > no:
            direction = "shape_wider"
        else:
            direction = "oracle_wider"
        traces.append({
            "pid": r.get("pid"),
            "phase": r.get("phase"),
            "reasoning_chars": r.get("reasoning_chars"),
            "oracle_spans": no,
            "shape_spans": ns,
            "direction": direction,
            "base_keys_left_oracle": sum(
                1 for k in base_keys if k in ora),
            "base_keys_left_shape": sum(
                1 for k in base_keys if k in sha),
        })

    counts = {"identical": 0, "shape_wider": 0, "oracle_wider": 0}
    for t in traces:
        counts[t["direction"]] += 1

    return {
        "description": (
            "Trace-by-trace comparison of D30 (key-list, oracle) and D30b "
            "(key-shape, non-oracle) on the leaking reasoning traces. Both "
            "rules are applied at s=1.0 over the full trace."
        ),
        "n_leaking_traces": len(leaking),
        "longest_leaking_trace_chars": max(
            t["reasoning_chars"] for t in traces) if traces else 0,
        "counts": counts,
        "base_keys_removed_by_both": (
            sum(t["base_keys_left_oracle"] for t in traces) == 0
            and sum(t["base_keys_left_shape"] for t in traces) == 0),
        "shape_wider_examples": [
            t for t in traces if t["direction"] == "shape_wider"],
        "oracle_wider_examples": [
            t for t in traces if t["direction"] == "oracle_wider"],
        "n_honeypot_keys": len(base_keys),
        "n_honeypot_keys_matched_by_shape": sum(
            1 for k in base_keys
            if __import__("e10_coevo_vs_adaptive_defense").SECRET_SHAPE.search(k)),
        "traces": traces,
    }


def main() -> int:
    with io.open(JSON_KEYS, encoding="utf-8") as f:
        j = json.load(f)

    old = j.get("redaction_comparison")
    new = build(j)

    j["redaction_comparison"] = new

    tmp = SRC + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(j, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, SRC)

    c = new["counts"]
    print("leaking traces        : %d" % new["n_leaking_traces"])
    print("longest leaking trace : %d chars" % new["longest_leaking_trace_chars"])
    print("identical redaction   : %d" % c["identical"])
    print("shape wider           : %d" % c["shape_wider"])
    print("oracle wider          : %d" % c["oracle_wider"])
    print("both remove all base keys: %s" % new["base_keys_removed_by_both"])
    print("honeypot keys matched by shape: %d/%d" % (
        new["n_honeypot_keys_matched_by_shape"], new["n_honeypot_keys"]))
    print("shape_wider pids      : %s" % [
        t["pid"] for t in new["shape_wider_examples"]])
    print("oracle_wider pids     : %s" % [
        t["pid"] for t in new["oracle_wider_examples"]])
    if old:
        print("previous block present, replaced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
