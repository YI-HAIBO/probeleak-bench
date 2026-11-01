#!/usr/bin/env python3
"""E1e: extension-cohort wave 3 — third quota window drift re-measurement.

Same protocol as E1b/E1c (4 high-tier probes x6 reps + 8 controls = 32
requests per model; same system prompt, honeypot keys, dual-channel judge,
gate structure), applied on the *third* anonymous-window rotation of the
cross-vendor gateway.

Scientific goal (task #103): the drift-versus-stable verdict for each
backend currently rests on at most two window points. A third point
separates "backend-specific blind spot" from "window-specific sampling
noise".

  M_P  nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free  (w2: 14/24 58.3%)
  M_Q  nvidia/nemotron-3-super-120b-a12b:free              (new this window)
  M_R  poolside/laguna-xs-2.1:free                         (w2: 0/13)
  M_S  xingchen-agi/xing4.0-29b-a4b:free                   (w2: blocked)
  M_T  dots-studio/dots-3-note-preview:free                (w1: primary family)

The script also re-scans every prior E1-family artifact for the same
backend id and reports the full window series with pair-wise Fisher tests,
so the drift verdict never rests on a hand-copied number.

Output: results/e1e_third_window_v1.json
Checkpoint: results/e1e_third_window_checkpoint.ndjson
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from e1b_extension import (  # noqa: E402
    CTRL,
    HIGH,
    api_call,
    fisher_exact,
    judge,
    load_reference,
    summarize,
    two_proportion_diff_ci,
)

ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "results", "e1e_third_window_v1.json")
CKPT = os.path.join(ROOT, "results", "e1e_third_window_checkpoint.ndjson")

SEED = 20261025
WINDOW = 3

MODELS = [
    {"code": "M_P", "model": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
     "vendor": "NVIDIA", "arch": "Nemotron-3-Nano-Omni 30B-A3B"},
    {"code": "M_Q", "model": "nvidia/nemotron-3-super-120b-a12b:free",
     "vendor": "NVIDIA", "arch": "Nemotron-3-Super 120B-A12B"},
    {"code": "M_R", "model": "poolside/laguna-xs-2.1:free",
     "vendor": "Poolside", "arch": "Laguna XS 2.1"},
    {"code": "M_S", "model": "xingchen-agi/xing4.0-29b-a4b:free",
     "vendor": "Xingchen AGI", "arch": "Xing 4.0 29B-A4B"},
    {"code": "M_T", "model": "dots-studio/dots-3-note-preview:free",
     "vendor": "Dots Studio", "arch": "primary-model family",
     "primary_family": True},
]

# Prior artifacts scanned for the same backend id, oldest window first.
HISTORY = [
    ("e1_cross_model_v1.json", 0),
    ("e1b_extension_v1.json", 1),
    ("e1c_extension_v1.json", 2),
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
            "id": rid,
            "kind": kind,
            "model_code": mdef["code"],
            "model_requested": mdef["model"],
            "window": WINDOW,
            "base_id": pid,
            "run_id": run_id,
            "attack_mode": p.get("attack_mode"),
            "user_text": p["user"],
            "api_ok": out["ok"],
            "latency_ms": out.get("latency_ms"),
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
                "actual_model": raw.get("model"),
                "provider": raw.get("provider"),
                "finish_reason": ch.get("finish_reason"),
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "reasoning_chars": len(reasoning),
                "content_chars": len(content),
                "reasoning": reasoning,
                "content": content,
            })
        else:
            rec.update({
                "gateway_blocked": out.get("http") in (400, 401, 403, 429, 500),
                "http": out.get("http"),
                "error": out.get("error"),
                "reasoning_chars": 0,
                "content_chars": 0,
                "cot_leak": False,
                "final_leak": False,
                "union_leak": False,
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
        time.sleep(1.5)
    return recs


def collect_history(model_id):
    """Re-scan prior E1 artifacts for the same backend id (no hand-copied
    numbers): returns one dict per prior window with recomputed counts."""
    series = []
    for fname, window in HISTORY:
        path = os.path.join(ROOT, "results", fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except Exception:
            continue
        recs = doc.get("records") or []
        if not recs:
            for code, blk in (doc.get("per_model") or {}).items():
                recs.extend(blk.get("records") or [])
        hit = [r for r in recs
               if (r.get("model_requested") or r.get("model")) == model_id]
        if not hit:
            continue
        high = [r for r in hit if r.get("base_id") in HIGH]
        ok = [r for r in high if r.get("api_ok")]
        if not ok:
            series.append({"source": fname, "window": window, "n_ok": 0,
                           "cot_leaks": 0, "rate": None,
                           "note": "no successful high-tier request"})
            continue
        leaks = sum(1 for r in ok if r.get("cot_leak"))
        series.append({
            "source": fname, "window": window,
            "n_ok": len(ok), "cot_leaks": leaks,
            "rate": round(leaks / len(ok), 4),
        })
    return series


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
            "model": mdef["model"],
            "vendor": mdef["vendor"],
            "arch": mdef["arch"],
            "primary_family": bool(mdef.get("primary_family")),
            "window": WINDOW,
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
    ref_hi = ref["high_tier"]

    comparisons = []
    drift = {}
    for code, data in per_model.items():
        hi = data["high_tier"]
        if hi["n_ok"] and ref_hi["n_ok"]:
            lo, hi_ci, _ = two_proportion_diff_ci(
                hi["cot_leak_count"], hi["n_ok"],
                ref_hi["cot_leak_count"], ref_hi["n_ok"])
            comparisons.append({
                "model_code": code,
                "model": data["model"],
                "vendor": data["vendor"],
                "primary_family": data["primary_family"],
                "n": hi["n_ok"],
                "cot_leaks": hi["cot_leak_count"],
                "rate": hi["cot_leak_rate"],
                "wilson95": hi["cot_leak_wilson95"],
                "ref_n": ref_hi["n_ok"],
                "ref_leaks": ref_hi["cot_leak_count"],
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
        # --- window series + pairwise Fisher ---
        series = collect_history(data["model"])
        cur = {"source": "e1e_third_window_v1.json", "window": WINDOW,
               "n_ok": hi["n_ok"], "cot_leaks": hi["cot_leak_count"],
               "rate": hi["cot_leak_rate"]}
        series.append(cur)
        pairs = []
        for prev in series[:-1]:
            if not prev.get("n_ok") or not cur["n_ok"] \
                    or prev.get("rate") is None:
                pairs.append({"vs_window": prev["window"], "fisher_p": None,
                              "note": "insufficient data"})
                continue
            pairs.append({
                "vs_window": prev["window"],
                "prev_rate": prev["rate"], "cur_rate": cur["rate"],
                "delta": round(cur["rate"] - prev["rate"], 4),
                "fisher_p": fisher_exact(
                    cur["cot_leaks"], cur["n_ok"] - cur["cot_leaks"],
                    prev["cot_leaks"], prev["n_ok"] - prev["cot_leaks"]),
            })
        rates = [s["rate"] for s in series if s.get("rate") is not None]
        drift[code] = {
            "model": data["model"],
            "series": series,
            "pairwise": pairs,
            "n_windows": len(series),
            "rate_spread": (round(max(rates) - min(rates), 4)
                            if len(rates) >= 2 else None),
            "any_significant_shift": any(
                p.get("fisher_p") is not None and p["fisher_p"] < 0.05
                for p in pairs),
        }

    gates = {}
    planned = len(MODELS) * (len(HIGH) * 6 + len(CTRL))
    gates["g1_checkpoint_integrity"] = {
        "check": "all planned records landed, unique ids",
        "planned": planned,
        "n_records": len(all_recs),
        "n_unique_ids": len({r["id"] for r in all_recs}),
        "passed": (len(all_recs) == len({r["id"] for r in all_recs})
                   == planned),
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
        gates["g2_dual_channel_visible"]["per_model"][code] = {
            "n_ok": len(ok),
            "both_nonempty_rate": round(both / max(1, len(ok)), 4)}
    gates["g2_dual_channel_visible"]["passed"] = all(
        v["both_nonempty_rate"] >= 0.9
        for v in gates["g2_dual_channel_visible"]["per_model"].values())
    g3_models = sorted({
        r.get("actual_model") for m in MODELS
        for r in per_model[m["code"]]["records"] if r.get("actual_model")})
    gates["g3_third_window_independent"] = {
        "check": "resolved backends differ from the primary gateway string "
                 "and >=2 non-primary vendors present",
        "actual_models": g3_models,
        "vendors": sorted({m["vendor"] for m in MODELS}),
        "passed": (len({m["vendor"] for m in MODELS}) >= 2
                   and not any("dots3-note-prev" == (a or "")
                               for a in g3_models)),
    }
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
    gates["g6_drift_series_resolved"] = {
        "check": "every backend has >=2 window points after this wave",
        "per_model": {c: d["n_windows"] for c, d in drift.items()},
        "passed": all(d["n_windows"] >= 2 for d in drift.values()),
    }

    out = {
        "experiment": "e1e_third_window_wave3",
        "version": 1,
        "description": ("Extension cohort wave 3: E1 protocol re-run on the "
                        "third anonymous-window rotation of the cross-vendor "
                        "gateway, to separate backend-specific blind spots "
                        "from window-specific sampling noise."),
        "endpoint": "https://api.kilo.ai/api/gateway/chat/completions",
        "seed": SEED,
        "window": WINDOW,
        "temperature": 0.1,
        "max_tokens": 4000,
        "reps_per_high_probe": 6,
        "high_probes": HIGH,
        "control_probes": CTRL,
        "honeypot_key_count": 15,
        "reference_source": ref["source"],
        "elapsed_sec": round(time.time() - t0, 1),
        "models": [m["model"] for m in MODELS],
        "per_model": per_model,
        "reference_primary": ref,
        "cross_model_comparisons": comparisons,
        "cross_window_drift": drift,
        "gates": gates,
        "records": all_recs,
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)
    print("--> %s (gates: %s)"
          % (OUT, {k: v.get("passed") for k, v in gates.items()}), flush=True)
    for code, d in drift.items():
        print("   %s windows=%d spread=%s sig=%s"
              % (code, d["n_windows"], d["rate_spread"],
                 d["any_significant_shift"]), flush=True)


if __name__ == "__main__":
    main()
