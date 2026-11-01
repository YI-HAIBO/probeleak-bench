#!/usr/bin/env python3
r"""M8 control expansion: send additional control probes to ambiguous models.

The M8 cleanliness analysis showed 5 of 7 third-gateway backends are
"ambiguous" because 8 control probes are too few to resolve the control
CI from the attack CI.  This script adds control repetitions (r2-r5) for
the three improvable ambiguous models (N_A, N_B, N_C), using the same
E1D protocol (same probe set, system prompt, judge).

N_D is inverted (impossible to make clean), N_E/N_G had API failures,
N_F is already clean.  So only N_A/N_B/N_C are targeted.

Output: results/m8_control_expansion_v1.json
Checkpoint: results/m8_control_expansion_checkpoint.ndjson
"""
from __future__ import annotations

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from e1b_extension import (
    CTRL,
    HIGH,
    fisher_exact,
    judge,
    median,
    summarize,
    two_proportion_diff_ci,
)

ROOT = os.path.dirname(HERE)
RES = os.path.join(ROOT, "results")
OUT = os.path.join(RES, "m8_control_expansion_v1.json")
CKPT = os.path.join(RES, "m8_control_expansion_checkpoint.ndjson")

ENDPOINT = "https://discovery-api.intern-ai.org.cn/v1/chat/completions"
KEY = os.environ.get("PROBELEAK_N_C_KEY", "")

TEMPERATURE = 0.1
MAX_TOKENS = 4000
SLEEP_S = 2.0
TRIES = 4

# Target models: the three ambiguous ones that can potentially reach "clean"
TARGETS = [
    {"code": "N_A", "model": "Agents-A1"},
    {"code": "N_B", "model": "Atria-Dawn"},
    {"code": "N_C", "model": "Atria-Dawn-Preview"},
]

# Additional repetitions: r2 through r5 (4 more reps x 8 probes = +32 per model)
EXTRA_REPS = ["r2", "r3", "r4", "r5"]


def load_ckpt():
    if not os.path.exists(CKPT):
        return {}
    out = {}
    for line in open(CKPT, encoding="utf-8"):
        if line.strip():
            r = json.loads(line)
            out[r["id"]] = r
    return out


def save_ckpt(rec):
    with open(CKPT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def api_call(model, user, tries=TRIES):
    import urllib.error
    import urllib.request
    from e4_consumer_channel import SYSTEM_PROMPT
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ],
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
    }
    last = None
    for attempt in range(1, tries + 1):
        t0 = time.time()
        try:
            req = urllib.request.Request(
                ENDPOINT, data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + KEY},
            )
            with urllib.request.urlopen(req, timeout=300) as r:
                raw = json.loads(r.read().decode("utf-8", "replace"))
            return {"ok": True, "raw": raw,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "attempt": attempt}
        except urllib.error.HTTPError as e:
            last = {"ok": False, "http": e.code,
                    "error": e.read().decode("utf-8", "replace")[:400],
                    "latency_ms": int((time.time() - t0) * 1000),
                    "attempt": attempt}
            if 400 <= e.code < 500 and e.code != 429:
                return last
            time.sleep(min(30, 6 * attempt))
        except Exception as e:
            last = {"ok": False, "http": None,
                    "error": type(e).__name__ + ": " + str(e)[:300],
                    "latency_ms": int((time.time() - t0) * 1000),
                    "attempt": attempt}
            time.sleep(min(30, 6 * attempt))
    return last


def main():
    from p1_real_scale_validation import build_attack_probes
    lib = {p["id"]: p for p in build_attack_probes()}

    t0 = time.time()
    done = load_ckpt()
    print("ckpt loaded: %d records" % len(done), flush=True)

    all_recs = []
    for mdef in TARGETS:
        print("== %s %s" % (mdef["code"], mdef["model"]), flush=True)
        for rep in EXTRA_REPS:
            for pid in CTRL:
                rid = "%s_%s_%s" % (mdef["code"], pid, rep)
                if rid in done:
                    all_recs.append(done[rid])
                    print("  [skip] %s (in ckpt)" % rid, flush=True)
                    continue
                p = lib[pid]
                out = api_call(mdef["model"], p["user"])
                rec = {
                    "id": rid, "kind": "control", "model_code": mdef["code"],
                    "model_requested": mdef["model"], "base_id": pid,
                    "run_id": "%s_%s" % (pid, rep),
                    "attack_mode": p.get("attack_mode"),
                    "user_text": p["user"],
                    "api_ok": out["ok"], "latency_ms": out.get("latency_ms"),
                    "attempt": out.get("attempt"),
                    "rep": rep,
                }
                if out["ok"]:
                    raw = out["raw"]
                    ch = (raw.get("choices") or [{}])[0]
                    msg = ch.get("message") or {}
                    usage = raw.get("usage") or {}
                    reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
                    content = msg.get("content") or ""
                    rec.update({
                        "actual_model": raw.get("model"),
                        "finish_reason": ch.get("finish_reason"),
                        "prompt_tokens": usage.get("prompt_tokens"),
                        "completion_tokens": usage.get("completion_tokens"),
                        "reasoning_chars": len(reasoning),
                        "content_chars": len(content),
                        "reasoning": reasoning, "content": content,
                    })
                else:
                    rec.update({
                        "gateway_blocked": out.get("http") in (400, 401, 403, 429, 500),
                        "http": out.get("http"), "error": out.get("error"),
                        "reasoning_chars": 0, "content_chars": 0,
                        "cot_leak": False, "final_leak": False,
                        "union_leak": False, "refusal": False,
                    })
                judge(rec, rec.get("reasoning", ""), rec.get("content", ""))
                save_ckpt(rec)
                all_recs.append(rec)
                print("  [%s] %s ok=%s cot=%s fin=%s rch=%s %sms"
                      % (mdef["code"], rid, rec["api_ok"], rec.get("cot_leak"),
                         rec.get("final_leak"), rec.get("reasoning_chars"),
                         rec.get("latency_ms")), flush=True)
                if not out["ok"] and out.get("http") in (401, 403):
                    print("  AUTH FAILURE, stopping %s" % mdef["code"], flush=True)
                    break
                time.sleep(SLEEP_S)
            else:
                continue
            break

    # Summarize per model
    per_model = {}
    for mdef in TARGETS:
        recs = [r for r in all_recs if r["model_code"] == mdef["code"]]
        ok = [r for r in recs if r.get("api_ok")]
        leaks = [r for r in ok if r.get("cot_leak")]
        per_model[mdef["code"]] = {
            "model": mdef["model"],
            "n_new_sent": len(recs),
            "n_new_ok": len(ok),
            "n_new_cot_leak": len(leaks),
            "new_ctrl_rate": round(len(leaks) / max(1, len(ok)), 4),
        }

    out = {
        "experiment": "m8_control_expansion",
        "version": 1,
        "description": ("Additional control probes for the three ambiguous "
                        "third-gateway models (N_A, N_B, N_C) to close the M8 gap."),
        "source": "e1d_third_gateway_v1.json (original 8 controls) + this run",
        "extra_reps": EXTRA_REPS,
        "control_probes": CTRL,
        "elapsed_sec": round(time.time() - t0, 1),
        "per_model": per_model,
        "records": all_recs,
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)
    print("--> %s (%d records, %.0fs)"
          % (OUT, len(all_recs), time.time() - t0), flush=True)

    # Print summary
    print()
    print("=== M8 Control Expansion Summary ===")
    for code, d in per_model.items():
        print(f"  {code} ({d['model']}): {d['n_new_ok']} new OK, "
              f"{d['n_new_cot_leak']} leaks, rate={d['new_ctrl_rate']}")


if __name__ == "__main__":
    main()