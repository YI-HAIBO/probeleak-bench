#!/usr/bin/env python3
r"""P1c: expand the real benign sample from 4 records to 40+ per gateway.

The paper's Limitations states that false-positive rates, latency, and the
observer confusion matrix "are deployment assumptions (the benign sample
comprises 4 records)".  The 4 records are the benign probes that survived
in the real defense experiments (E2 contributed 3, E6 contributed 1).

This script sends 40 realistic benign CRM-Assistant requests -- the traffic
the deployment is supposed to serve -- through the real gateways under the
*identical* CRM deployment system prompt used by E2/E4 (honeypot credentials
in context) and applies the *identical* string judge used by E1D/E4, so the
benign false-positive rate is directly comparable with the attack-arm leak
rates.  It records, per response:

  cot recitation of a honeypot credential (string-judge "leak" on benign)
  final recitation, refusal, latency, reasoning/content sizes

Gateways (keys read from env, never written to source):
  PRIMARY_KEY  -> https://note3-prev-api.askdiandian.com  (dots3-note-prev)
  N_C_KEY      -> https://discovery-api.intern-ai.org.cn  (Atria-Dawn-Preview)

Output:     results/p1c_benign_traffic_v1.json
Checkpoint: results/p1c_benign_traffic_checkpoint.ndjson
"""
from __future__ import annotations

import json
import math
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from e1b_extension import judge, summarize  # noqa: E402
from e4_consumer_channel import SYSTEM_PROMPT  # noqa: E402
from p1_benign_fpr import BENIGN  # noqa: E402  (the 40 benign CRM requests)

ROOT = os.path.dirname(HERE)
RES = os.path.join(ROOT, "results")
OUT = os.path.join(RES, "p1c_benign_traffic_v1.json")
CKPT = os.path.join(RES, "p1c_benign_traffic_checkpoint.ndjson")

GATEWAYS = [
    {"code": "G1_primary", "label": "dots3-note-prev (primary real gateway)",
     "endpoint": "https://note3-prev-api.askdiandian.com/v1/chat/completions",
     "model": "dots3-note-prev", "env": "PRIMARY_KEY"},
    {"code": "G3_nc", "label": "Atria-Dawn-Preview (third gateway)",
     "endpoint": "https://discovery-api.intern-ai.org.cn/v1/chat/completions",
     "model": "Atria-Dawn-Preview", "env": "N_C_KEY"},
]

TEMPERATURE = 0.1
MAX_TOKENS = 4000
SLEEP_S = 2.0
TRIES = 4


def load_ckpt():
    if not os.path.exists(CKPT):
        return {}
    """Only *successful* records are treated as done; failed ones are
    retried on the next run (the gateway returns 429 while its shared
    quota is locked, and those entries would otherwise be frozen in)."""
    out = {}
    for line in open(CKPT, encoding="utf-8"):
        if line.strip():
            r = json.loads(line)
            if r.get("api_ok"):
                out[r["id"]] = r
    return out


def save_ckpt(rec):
    with open(CKPT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def api_call(endpoint, key, model, user, tries=TRIES):
    import urllib.error
    import urllib.request
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
                endpoint, data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + key},
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


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(c - h, 6), round(c + h, 6)]


def one_sided_upper(k, n, alpha=0.05):
    if n == 0:
        return None
    if k == 0:
        return round(1 - alpha ** (1.0 / n), 6)
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        p_le = sum(math.comb(n, i) * mid ** i * (1 - mid) ** (n - i)
                   for i in range(k + 1))
        if p_le > alpha:
            lo = mid
        else:
            hi = mid
    return round((lo + hi) / 2, 6)


def median(xs):
    ys = sorted(xs)
    n = len(ys)
    if n == 0:
        return None
    if n % 2:
        return ys[n // 2]
    return (ys[n // 2 - 1] + ys[n // 2]) / 2.0


def main():
    missing = [g["env"] for g in GATEWAYS if not os.environ.get(g["env"])]
    if missing:
        raise SystemExit("set env vars: %s" % ", ".join(missing))

    done = load_ckpt()
    print("ckpt loaded: %d records" % len(done), flush=True)

    per_gateway = {}
    t0 = time.time()
    stop = False
    for g in GATEWAYS:
        if stop:
            break
        code, endpoint, model = g["code"], g["endpoint"], g["model"]
        key = os.environ.get(g["env"])
        recs = []
        print("\n=== %s :: %s ===" % (code, g["label"]), flush=True)
        for i, text in enumerate(BENIGN, 1):
            rid = "%s_B%02d" % (code, i)
            if rid in done:
                recs.append(done[rid])
                print("  [skip] %s (in ckpt)" % rid, flush=True)
                continue
            out = api_call(endpoint, key, model, text)
            rec = {
                "id": rid, "kind": "benign", "gateway_code": code,
                "model_requested": model, "benign_id": "B%02d" % i,
                "user_text": text,
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
                })
            judge(rec, rec.get("reasoning", ""), rec.get("content", ""))
            save_ckpt(rec)
            recs.append(rec)
            print("  [%s] %s ok=%s cot=%s fin=%s ref=%s %sms"
                  % (code, rid, rec["api_ok"], rec.get("cot_leak"),
                     rec.get("final_leak"), rec.get("refusal"),
                     rec.get("latency_ms")), flush=True)
            if not out["ok"] and out.get("http") in (401, 403):
                print("  AUTH FAILURE on %s, skipping rest of this gateway"
                      % code, flush=True)
                stop = True
                break
            time.sleep(SLEEP_S)
        per_gateway[code] = recs

    # ---- summaries
    summary = {}
    for code, recs in per_gateway.items():
        ok = [r for r in recs if r.get("api_ok")]
        n = len(ok)
        k_cot = sum(1 for r in ok if r.get("cot_leak"))
        k_fin = sum(1 for r in ok if r.get("final_leak"))
        k_ref = sum(1 for r in ok if r.get("refusal"))
        lats = [r["latency_ms"] for r in ok if r.get("latency_ms")]
        rchars = [r["reasoning_chars"] for r in ok]
        cchars = [r["content_chars"] for r in ok]
        summary[code] = {
            "label": next(g["label"] for g in GATEWAYS if g["code"] == code),
            "n_sent": len(recs), "n_ok": n,
            "n_api_failed": len(recs) - n,
            "cot_recitation": {"k": k_cot, "n": n,
                               "rate": round(k_cot / n, 6) if n else None,
                               "wilson95": wilson(k_cot, n),
                               "one_sided_upper95": one_sided_upper(k_cot, n)},
            "final_recitation": {"k": k_fin, "n": n,
                                 "rate": round(k_fin / n, 6) if n else None,
                                 "one_sided_upper95": one_sided_upper(k_fin, n)},
            "refusal": {"k": k_ref, "n": n,
                        "rate": round(k_ref / n, 6) if n else None},
            "latency_ms": {"median": median(lats),
                           "p90": sorted(lats)[int(0.9 * (len(lats) - 1))]
                           if lats else None,
                           "min": min(lats) if lats else None,
                           "max": max(lats) if lats else None},
            "reasoning_chars_median": median(rchars),
            "content_chars_median": median(cchars),
            "all_recitations_cot_only": k_fin == 0 and k_cot > 0,
        }

    # E2/E6-style prior benign records already in the paper (for the total)
    prior_note = ("The 4 prior real benign records are the 3 benign probes "
                  "in E2 (results/e2_real_schema_hiding_v1.json) plus the 1 "
                  "benign record in E6 (results/e6_real_scale_expansion_v1"
                  ".json); this run adds 40 benign requests per gateway.")

    out = {
        "experiment": "p1c_benign_traffic",
        "version": 1,
        "description": ("Expand the real benign sample from 4 records to 40 "
                        "benign CRM requests per gateway, under the identical "
                        "CRM deployment system prompt and string judge used "
                        "by E2/E4/E1D; measures benign false-positive rate, "
                        "refusal and latency on real traffic."),
        "system_prompt_chars": len(SYSTEM_PROMPT),
        "temperature": TEMPERATURE,
        "n_benign_prompts": len(BENIGN),
        "judge": "e1b_extension.judge (identical string judge as E1D/E4)",
        "prior_benign_records": prior_note,
        "gateways": summary,
        "elapsed_sec": round(time.time() - t0, 1),
        "records": {code: recs for code, recs in per_gateway.items()},
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)

    print("\n--> %s (%.0fs)" % (OUT, time.time() - t0), flush=True)
    print("\n=== P1c benign traffic expansion ===")
    for code, s in summary.items():
        print("[%s] %s" % (code, s["label"]))
        print("  ok %d/%d | CoT recitation %d/%d = %s (upper %s)"
              % (s["n_ok"], s["n_sent"], s["cot_recitation"]["k"], s["n_ok"],
                 s["cot_recitation"]["rate"],
                 s["cot_recitation"]["one_sided_upper95"]))
        print("  final recitation %d/%d | refusal %d/%d = %s"
              % (s["final_recitation"]["k"], s["n_ok"], s["refusal"]["k"],
                 s["n_ok"], s["refusal"]["rate"]))
        print("  latency median %s ms (p90 %s)"
              % (s["latency_ms"]["median"], s["latency_ms"]["p90"]))


if __name__ == "__main__":
    main()
