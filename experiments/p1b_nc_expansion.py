#!/usr/bin/env python3
r"""P1b: expand N_C (Atria-Dawn-Preview) controls from 40 to 64.

M8 v2 left N_C ambiguous: 1/40 controls vs 5/24 attack, control CI overlaps
the attack CI; the paper notes it "would need approximately 58" controls.
This script adds three further repetitions (r6, r7, r8; 3 x 8 = 24 new
control probes) under the identical E1D protocol (same probe set, system
prompt, judge, temperature), reaching 64 controls total.

The gateway key is read from the N_C_KEY environment variable; it is never
written into the source.

Output:  results/p1b_nc_expansion_v1.json
Checkpoint: results/p1b_nc_expansion_checkpoint.ndjson
"""
from __future__ import annotations

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from e1b_extension import (  # noqa: E402
    CTRL,
    fisher_exact,
    judge,
    summarize,
)

ROOT = os.path.dirname(HERE)
RES = os.path.join(ROOT, "results")
OUT = os.path.join(RES, "p1b_nc_expansion_v1.json")
CKPT = os.path.join(RES, "p1b_nc_expansion_checkpoint.ndjson")

ENDPOINT = "https://discovery-api.intern-ai.org.cn/v1/chat/completions"
KEY = os.environ.get("N_C_KEY", "")
MODEL = "Atria-Dawn-Preview"
CODE = "N_C"

TEMPERATURE = 0.1
MAX_TOKENS = 4000
SLEEP_S = 2.0
TRIES = 4
EXTRA_REPS = ["r6", "r7", "r8"]


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
    if not KEY:
        raise SystemExit("set N_C_KEY env var")

    from p1_real_scale_validation import build_attack_probes
    lib = {p["id"]: p for p in build_attack_probes()}

    # carry forward the 40 existing controls (8 original + 32 from r2-r5)
    prior = []
    p1 = os.path.join(RES, "m8_control_expansion_v1.json")
    if os.path.exists(p1):
        d = json.load(open(p1, encoding="utf-8"))
        prior = [r for r in d.get("records", [])
                 if r.get("model_code") == CODE and r.get("api_ok")]
    e1d = os.path.join(RES, "e1d_third_gateway_v1.json")
    if os.path.exists(e1d):
        d = json.load(open(e1d, encoding="utf-8"))
        for r in d.get("records", []):
            if (r.get("model_requested") == MODEL and r.get("kind") == "control"
                    and r.get("api_ok")):
                prior.append(r)
    print("prior usable N_C controls: %d" % len(prior), flush=True)

    t0 = time.time()
    done = load_ckpt()
    print("ckpt loaded: %d records" % len(done), flush=True)

    new_recs = []
    for rep in EXTRA_REPS:
        for pid in CTRL:
            rid = "%s_%s_%s" % (CODE, pid, rep)
            if rid in done:
                new_recs.append(done[rid])
                print("  [skip] %s (in ckpt)" % rid, flush=True)
                continue
            p = lib[pid]
            out = api_call(MODEL, p["user"])
            rec = {
                "id": rid, "kind": "control", "model_code": CODE,
                "model_requested": MODEL, "base_id": pid,
                "run_id": "%s_%s" % (pid, rep),
                "attack_mode": p.get("attack_mode"),
                "user_text": p["user"],
                "api_ok": out["ok"], "latency_ms": out.get("latency_ms"),
                "attempt": out.get("attempt"), "rep": rep,
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
            new_recs.append(rec)
            print("  [%s] %s ok=%s cot=%s fin=%s rch=%s %sms"
                  % (CODE, rid, rec["api_ok"], rec.get("cot_leak"),
                     rec.get("final_leak"), rec.get("reasoning_chars"),
                     rec.get("latency_ms")), flush=True)
            if not out["ok"] and out.get("http") in (401, 403):
                print("  AUTH FAILURE, stopping" , flush=True)
                break
            time.sleep(SLEEP_S)
        else:
            continue
        break

    # merge prior + new
    all_ctrl = prior + new_recs
    ok = [r for r in all_ctrl if r.get("api_ok")]
    leaks = [r for r in ok if r.get("cot_leak")]
    n_ok, n_leak = len(ok), len(leaks)

    # attack side from e1d
    atk = []
    if os.path.exists(e1d):
        d = json.load(open(e1d, encoding="utf-8"))
        atk = [r for r in d.get("records", [])
               if r.get("model_requested") == MODEL and r.get("kind") != "control"
               and r.get("api_ok")]
    a_ok = [r for r in atk if r.get("api_ok")]
    a_leaks = [r for r in a_ok if r.get("cot_leak")]
    n_a, n_al = len(a_ok), len(a_leaks)

    summary = summarize(ok, CTRL) if ok else None
    atk_probe_ids = sorted({r.get("base_id") or r.get("run_id", "")
                            for r in a_ok})
    atk_summary = summarize(a_ok, atk_probe_ids) if a_ok else None
    p_val = None
    if ok and a_ok:
        k_c = sum(1 for r in ok if r.get("cot_leak"))
        k_a = sum(1 for r in a_ok if r.get("cot_leak"))
        p_val = fisher_exact(k_c, len(ok) - k_c, k_a, len(a_ok) - k_a)

    out = {
        "experiment": "p1b_nc_expansion",
        "version": 1,
        "description": ("Expand N_C (Atria-Dawn-Preview) controls from 40 to "
                        "64 to resolve the last ambiguous third-gateway "
                        "backend; identical E1D protocol."),
        "model": MODEL,
        "model_code": CODE,
        "extra_reps": EXTRA_REPS,
        "control_probes": CTRL,
        "n_prior_controls": len(prior),
        "n_new_sent": len(new_recs),
        "n_new_ok": sum(1 for r in new_recs if r.get("api_ok")),
        "n_new_leak": sum(1 for r in new_recs if r.get("api_ok")
                          and r.get("cot_leak")),
        "controls": {"n": n_ok, "leaks": n_leak,
                     "rate": round(n_leak / n_ok, 6) if n_ok else None,
                     "summary": summary},
        "attack": {"n": n_a, "leaks": n_al,
                   "rate": round(n_al / n_a, 6) if n_a else None,
                   "summary": atk_summary},
        "fisher_p": p_val,
        "elapsed_sec": round(time.time() - t0, 1),
        "records": new_recs,
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)
    print("--> %s (%.0fs)" % (OUT, time.time() - t0), flush=True)
    print()
    print("=== P1b N_C control expansion ===")
    print("controls: %d prior + %d new = %d usable, %d leaks (rate %s)"
          % (len(prior), len(new_recs), n_ok, n_leak,
             out["controls"]["rate"]))
    print("attack:   %d usable, %d leaks (rate %s)"
          % (n_a, n_al, out["attack"]["rate"]))
    print("fisher p: %s" % p_val)
    if summary and atk_summary:
        print("control CI:  %s" % (summary.get("cot_leak_wilson95"),))
        print("attack CI:   %s" % (atk_summary.get("cot_leak_wilson95"),))


if __name__ == "__main__":
    main()
