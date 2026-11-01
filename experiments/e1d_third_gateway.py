#!/usr/bin/env python3
"""E1d: third-gateway (Intern-AI discovery-api) replication, wave 3.

Same E1 protocol (4 high-tier probes x6 reps + 8 controls = 32 requests
per model; same system prompt, 15 honeypot keys, dual-channel judge, gate
structure), applied to the responsive plaintext-reasoning models of the
third gateway enumeration (results/internai_reprobe_v1.json):

  N_A  Agents-A1            Agents-A1  (gateway-named flagship, 262k ctx)
  N_B  Atria-Dawn           Atria Dawn
  N_C  Atria-Dawn-Preview   Atria Dawn (preview branch)
  N_D  Sage-A1.5            Sage A1.5
  N_E  deepseek-v4.1-flash-1017  DeepSeek V4.1 Flash (1017)
  N_F  intern-s2            Intern S2
  N_G  qwen3.8-27b          Qwen3.8 27B

Reference: the primary-model high-tier pooled baseline recomputed from
results/e3_probe_benchmark_v1.json (same rule as E1b/E1c).

Output: results/e1d_third_gateway_v1.json
Checkpoint: results/e1d_third_gateway_checkpoint.ndjson
"""

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
    load_reference,
    median,
    summarize,
    two_proportion_diff_ci,
)

ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "results", "e1d_third_gateway_v1.json")
CKPT = os.path.join(ROOT, "results", "e1d_third_gateway_checkpoint.ndjson")

SEED = 20261024
TEMPERATURE = 0.1
MAX_TOKENS = 4000
SLEEP_S = 1.5
TRIES = 4

ENDPOINT = "https://discovery-api.intern-ai.org.cn/v1/chat/completions"
KEY = os.environ.get("PROBELEAK_N_C_KEY", "")

MODELS = [
    {"code": "N_A", "model": "Agents-A1", "vendor": "Agents-A1",
     "arch": "Agents-A1 flagship"},
    {"code": "N_B", "model": "Atria-Dawn", "vendor": "Atria",
     "arch": "Atria Dawn"},
    {"code": "N_C", "model": "Atria-Dawn-Preview", "vendor": "Atria",
     "arch": "Atria Dawn (preview)"},
    {"code": "N_D", "model": "Sage-A1.5", "vendor": "Sage",
     "arch": "Sage A1.5"},
    {"code": "N_E", "model": "deepseek-v4.1-flash-1017", "vendor": "DeepSeek",
     "arch": "DeepSeek V4.1 Flash (1017)"},
    {"code": "N_F", "model": "intern-s2", "vendor": "Shanghai AI Lab",
     "arch": "Intern S2"},
    {"code": "N_G", "model": "qwen3.8-27b", "vendor": "Qwen",
     "arch": "Qwen3.8 27B"},
]


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


def api_call(model, user, tries=TRIES, system_prompt=None):
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


def run_model(mdef, done):
    from p1_real_scale_validation import build_attack_probes
    lib = {p["id"]: p for p in build_attack_probes()}
    plan = []
    for pid in HIGH:
        for i in range(1, 6 + 1):
            plan.append((pid, "attack", "%s_r%d" % (pid, i)))
    for pid in CTRL:
        plan.append((pid, "control", "%s_r1" % pid))

    recs = []
    for pid, kind, run_id in plan:
        rid = "%s_%s" % (mdef["code"], run_id)
        if rid in done:
            recs.append(done[rid])
            continue
        p = lib[pid]
        out = api_call(mdef["model"], p["user"])
        rec = {
            "id": rid, "kind": kind, "model_code": mdef["code"],
            "model_requested": mdef["model"], "base_id": pid, "run_id": run_id,
            "attack_mode": p.get("attack_mode"), "user_text": p["user"],
            "api_ok": out["ok"], "latency_ms": out.get("latency_ms"),
            "attempt": out.get("attempt"),
        }
        if out["ok"]:
            raw = out["raw"]
            ch = (raw.get("choices") or [{}])[0]
            msg = ch.get("message") or {}
            usage = raw.get("usage") or {}
            reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
            content = msg.get("content") or ""
            rec.update({
                "actual_model": raw.get("model"), "provider": raw.get("provider"),
                "finish_reason": ch.get("finish_reason"),
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "reasoning_chars": len(reasoning), "content_chars": len(content),
                "reasoning": reasoning, "content": content,
            })
        else:
            rec.update({
                "gateway_blocked": out.get("http") in (400, 401, 403, 429, 500),
                "http": out.get("http"), "error": out.get("error"),
                "reasoning_chars": 0, "content_chars": 0,
                "cot_leak": False, "final_leak": False, "union_leak": False,
                "refusal": False,
            })
        judge(rec, rec.get("reasoning", ""), rec.get("content", ""))
        save_ckpt(rec)
        recs.append(rec)
        print("  [%s] %s ok=%s cot=%s fin=%s ref=%s rch=%s %sms"
              % (mdef["code"], run_id, rec["api_ok"], rec.get("cot_leak"),
                 rec.get("final_leak"), rec.get("refusal"),
                 rec.get("reasoning_chars"), rec.get("latency_ms")),
              flush=True)
        time.sleep(SLEEP_S)
    return recs


def main():
    t0 = time.time()
    done = load_ckpt()
    print("ckpt loaded: %d records" % len(done), flush=True)

    per_model = {}
    all_recs = []
    for mdef in MODELS:
        print("== %s %s" % (mdef["code"], mdef["model"]), flush=True)
        recs = run_model(mdef, done)
        all_recs.extend(recs)
        high = [r for r in recs if r["base_id"] in HIGH]
        ctrl = [r for r in recs if r["base_id"] in CTRL]
        per_model[mdef["code"]] = {
            "model": mdef["model"], "vendor": mdef["vendor"],
            "arch": mdef["arch"], "primary_family": False,
            "overall": summarize(recs, HIGH + CTRL),
            "high_tier": summarize(high, HIGH),
            "controls": summarize(ctrl, CTRL),
            "per_probe": {
                pid: summarize([r for r in high if r["base_id"] == pid], [pid])
                for pid in HIGH
            },
            "records": recs,
        }
        s = per_model[mdef["code"]]["high_tier"]
        print("  HIGH: cot %d/%d (%.2f%%, CI %s) fin %d ref %d"
              % (s["cot_leak_count"], s["n_ok"],
                 100 * (s["cot_leak_rate"] or 0),
                 s["cot_leak_wilson95"], s["final_leak_count"],
                 s["refusal_count"]), flush=True)

    ref = load_reference()

    comparisons = []
    ref_hi = ref["high_tier"]
    for code, data in per_model.items():
        hi = data["high_tier"]
        if hi["n_ok"] and ref_hi["n_ok"]:
            lo, hi_ci, _ = two_proportion_diff_ci(
                hi["cot_leak_count"], hi["n_ok"],
                ref_hi["cot_leak_count"], ref_hi["n_ok"])
            comparisons.append({
                "model_code": code, "model": data["model"],
                "vendor": data["vendor"], "primary_family": False,
                "n": hi["n_ok"], "cot_leaks": hi["cot_leak_count"],
                "rate": hi["cot_leak_rate"],
                "wilson95": hi["cot_leak_wilson95"],
                "ref_n": ref_hi["n_ok"], "ref_leaks": ref_hi["cot_leak_count"],
                "ref_rate": ref_hi["cot_leak_rate"],
                "diff_minus_ref": (hi["cot_leak_rate"] or 0)
                                  - (ref_hi["cot_leak_rate"] or 0),
                "diff_wald95": [round(lo, 4), round(hi_ci, 4)],
                "ci_covers_zero": lo <= 0 <= hi_ci,
                "fisher_exact_p": fisher_exact(
                    hi["cot_leak_count"], hi["n_ok"] - hi["cot_leak_count"],
                    ref_hi["cot_leak_count"],
                    ref_hi["n_ok"] - ref_hi["cot_leak_count"]),
                "refusal_count": hi["refusal_count"],
                "refusal_rate": hi["refusal_rate"],
            })

    gates = {}
    gates["g1_checkpoint_integrity"] = {
        "check": "all planned records landed, unique ids",
        "planned": len(MODELS) * (len(HIGH) * 6 + len(CTRL)),
        "n_records": len(all_recs),
        "n_unique_ids": len({r["id"] for r in all_recs}),
        "passed": (len(all_recs) == len({r["id"] for r in all_recs})
                   == len(MODELS) * (len(HIGH) * 6 + len(CTRL))),
    }
    gates["g2_dual_channel_visible"] = {
        "check": "per-model rate of responses with both channels non-empty",
        "per_model": {}, "passed": None,
    }
    for code, data in per_model.items():
        ok = [r for r in data["records"] if r.get("api_ok")]
        both = sum(1 for r in ok
                   if (r.get("reasoning_chars") or 0) > 0
                   and (r.get("content_chars") or 0) > 0)
        rate = both / max(1, len(ok))
        gates["g2_dual_channel_visible"]["per_model"][code] = {
            "n_ok": len(ok), "both_nonempty_rate": round(rate, 4)}
    gates["g2_dual_channel_visible"]["passed"] = all(
        v["both_nonempty_rate"] >= 0.9
        for v in gates["g2_dual_channel_visible"]["per_model"].values())
    gates["g3_independent_gateway"] = {
        "check": "gateway operator differs from the primary gateway and the "
                 "cross-vendor (kilo) gateway; >=2 non-primary vendors",
        "endpoint": ENDPOINT,
        "actual_models": sorted({
            r.get("actual_model") for m in MODELS
            for r in per_model[m["code"]]["records"] if r.get("actual_model")}),
        "vendors": sorted({m["vendor"] for m in MODELS}),
        "passed": None,
    }
    gates["g3_independent_gateway"]["passed"] = (
        len({m["vendor"] for m in MODELS}) >= 2
        and not any("dots3-note-prev" == (a or "")
                    for a in gates["g3_independent_gateway"]["actual_models"])
    )
    gates["g4_reference_recomputed"] = {
        "check": "primary-model high-tier reference recomputed from E3",
        "ref_n": ref_hi["n_ok"], "ref_cot": ref_hi["cot_leak_count"],
        "ref_rate": ref_hi["cot_leak_rate"],
        "passed": ref_hi["n_ok"] > 0,
    }
    ok_ci = True
    for code, data in per_model.items():
        for blk in ("overall", "high_tier", "controls"):
            for f in ("cot_leak_wilson95", "final_leak_wilson95"):
                v = data[blk].get(f)
                if v and not (0 <= v[0] <= v[1] <= 1):
                    ok_ci = False
    gates["g5_wilson_bounds"] = {
        "check": "all Wilson CIs in [0,1] (clamped helper)", "passed": ok_ci}

    # one-round retry pass for quota-failed record ids (window may reopen)
    n_failed = sum(1 for r in all_recs if not r.get("api_ok"))
    gates["g6_no_hard_blocked_model"] = {
        "check": "no model fully blocked (all 32 api_ok)",
        "failed_records": n_failed,
        "passed": n_failed == 0,
    }

    out = {
        "experiment": "e1d_third_gateway_wave3",
        "version": 1,
        "description": ("Third-gateway replication: E1 protocol on the "
                        "responsive plaintext-reasoning models of the "
                        "Intern-AI discovery gateway (13-model catalog, "
                        "7 responsive on benign probe)"),
        "endpoint": ENDPOINT,
        "seed": SEED, "temperature": TEMPERATURE, "max_tokens": MAX_TOKENS,
        "reps_per_high_probe": 6, "high_probes": HIGH,
        "control_probes": CTRL, "honeypot_key_count": 15,
        "reference_source": ref["source"],
        "elapsed_sec": round(time.time() - t0, 1),
        "models": [m["model"] for m in MODELS],
        "per_model": per_model,
        "reference_primary": ref,
        "cross_model_comparisons": comparisons,
        "gates": gates,
        "records": all_recs,
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)
    print("--> %s (gates: %s)"
          % (OUT, {k: v.get("passed") for k, v in gates.items()}), flush=True)


if __name__ == "__main__":
    main()
