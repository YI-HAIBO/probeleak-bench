#!/usr/bin/env python3
"""Window watch: one-shot availability sentinel for every gateway backend.

The study's cross-vendor evidence is opportunistic: the anonymous free-tier
pools rotate, so models that are locked today are the only ones that could
later supply a fourth quota window, a missing primary-family point, or the
third gateway's benign-control replication. This script answers two questions
in one pass, without spending quota on experiments:

  1. Which backends are usable right now, and which are still locked?
  2. If a locked backend reopens, what exactly should be run next?

Each backend gets one minimal request (8 output tokens). The response is
classified, compared with the previous watch run if one exists, and written
to results/window_watch_v1.json. Re-running is idempotent: it appends a new
timestamped observation to the same history list rather than overwriting it.

No probe result feeds any experiment. This is a traffic-light, nothing more.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "results", "window_watch_v1.json")

# ---------------------------------------------------------------- gateways
# endpoint, key, label. Keys are already present in the experiment scripts;
# they are never printed here, only used.
PRIMARY_EP = "https://note3-prev-api.askdiandian.com/v1/chat/completions"
PRIMARY_KEY = os.environ.get("PROBELEAK_PRIMARY_KEY", "")

KILO_EP = "https://api.kilo.ai/api/gateway/chat/completions"
KILO_KEY = "anonymous"

INTERN_EP = "https://discovery-api.intern-ai.org.cn/v1/chat/completions"
INTERN_KEY = os.environ.get("PROBELEAK_N_C_KEY", "")

PRIMARY_MODEL = "dots3-note-prev"

# --------------------------------------------------------------- registry
# Each entry: operator, code, model id, why it matters, and the follow-up
# command to run the moment the backend reopens. FOLLOWUP is deliberately a
# script name plus the concrete gap, so nothing has to be re-derived later.
BACKENDS = [
    {"operator": "primary", "code": "M0", "endpoint": PRIMARY_EP,
     "key": PRIMARY_KEY, "model": PRIMARY_MODEL,
     "gap": "primary research target; must stay live for any new measurement",
     "followup": "none (target of record)"},

    {"operator": "kilo-free", "code": "M_P", "endpoint": KILO_EP,
     "key": KILO_KEY,
     "model": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
     "gap": "drift series 12.5% -> 58.3% -> 58.3%; a 4th point decides step "
            "vs. plateau",
     "followup": "e1e_third_window.py (WINDOW=4) then re-run e1e_b2_report_gen.py"},

    {"operator": "kilo-free", "code": "M_Q", "endpoint": KILO_EP,
     "key": KILO_KEY,
     "model": "nvidia/nemotron-3-super-120b-a12b:free",
     "gap": "never measured: quota-blocked on all 3 attempts so far",
     "followup": "e1e_third_window.py (subset M_Q only)"},

    {"operator": "kilo-free", "code": "M_R", "endpoint": KILO_EP,
     "key": KILO_KEY, "model": "poolside/laguna-xs-2.1:free",
     "gap": "drift series 0/13 -> 1/12; two window points only",
     "followup": "e1e_third_window.py (subset M_R only)"},

    {"operator": "kilo-free", "code": "M_S", "endpoint": KILO_EP,
     "key": KILO_KEY, "model": "xingchen-agi/xing4.0-29b-a4b:free",
     "gap": "never measured: blocked in window 2",
     "followup": "e1e_third_window.py (subset M_S only)"},

    {"operator": "kilo-free", "code": "M_T", "endpoint": KILO_EP,
     "key": KILO_KEY, "model": "dots-studio/dots-3-note-preview:free",
     "gap": "primary family via a second gateway; 3rd window left only "
            "1/24 valid high-tier responses",
     "followup": "e1e_third_window.py (subset M_T only)"},

    {"operator": "kilo-free", "code": "M_B", "endpoint": KILO_EP,
     "key": KILO_KEY, "model": "nvidia/nemotron-3-nano-omni-30b-a3b:free",
     "gap": "pre-reasoning-suffix variant; useful as an architecture control",
     "followup": "e1e_third_window.py (add to MODELS)"},

    {"operator": "kilo-free", "code": "M_E", "endpoint": KILO_EP,
     "key": KILO_KEY, "model": "nvidia/nemotron-3.5-lightning:free",
     "gap": "B2 cross-model replication ran only 9 of 40 episodes in "
            "window 2; E7/E7b/E8 attacker corpus came from it",
     "followup": "e1c_extension.py (finish 40 episodes) then "
                 "e7_coevo_bandit.py / e8_real_defense_validation.py"},

    {"operator": "intern-ai", "code": "N_A", "endpoint": INTERN_EP,
     "key": INTERN_KEY, "model": "Agents-A1",
     "gap": "18/24 = 75.0% in E1d; no benign-control replication",
     "followup": "e1d_third_gateway.py with CTRL_REPEATS>=3"},

    {"operator": "intern-ai", "code": "N_B", "endpoint": INTERN_EP,
     "key": INTERN_KEY, "model": "Atria-Dawn",
     "gap": "low leak in E1d; no control replication",
     "followup": "e1d_third_gateway.py with CTRL_REPEATS>=3"},

    {"operator": "intern-ai", "code": "N_C", "endpoint": INTERN_EP,
     "key": INTERN_KEY, "model": "Atria-Dawn-Preview",
     "gap": "low leak in E1d; no control replication",
     "followup": "e1d_third_gateway.py with CTRL_REPEATS>=3"},

    {"operator": "intern-ai", "code": "N_D", "endpoint": INTERN_EP,
     "key": INTERN_KEY, "model": "Sage-A1.5",
     "gap": "benign-control recitation 6/8 is itself elevated, so the "
            "HIGH-vs-CTRL contrast rests on only 8 controls (CI very wide)",
     "followup": "e1d_third_gateway.py with CTRL_REPEATS>=3 (priority)"},

    {"operator": "intern-ai", "code": "N_E", "endpoint": INTERN_EP,
     "key": INTERN_KEY, "model": "deepseek-v4.1-flash-1017",
     "gap": "never measured: quota-locked on all attempts",
     "followup": "e1d_third_gateway.py (subset N_E only)"},

    {"operator": "intern-ai", "code": "N_F", "endpoint": INTERN_EP,
     "key": INTERN_KEY, "model": "intern-s2",
     "gap": "13/24 = 54.2%, p=1.0 vs primary baseline; no control replication",
     "followup": "e1d_third_gateway.py with CTRL_REPEATS>=3"},

    {"operator": "intern-ai", "code": "N_G", "endpoint": INTERN_EP,
     "key": INTERN_KEY, "model": "qwen3.8-27b",
     "gap": "never measured: quota-locked on all attempts",
     "followup": "e1d_third_gateway.py (subset N_G only)"},
]

# ------------------------------------------------------------------ probe
PROBE_PROMPT = "Reply with the single word: pong"
SLEEP_S = 1.5


def mask(key):
    return key[:6] + "..." + key[-4:] if len(key) > 12 else key


def probe(ep, key, model, timeout=45):
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
        "temperature": 0,
        "max_tokens": 8,
    }).encode("utf-8")
    t0 = time.time()
    rec = {"model": model, "endpoint": ep, "key": mask(key),
           "latency_ms": 0}
    try:
        req = urllib.request.Request(ep, data=body, headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            d = json.loads(resp.read().decode("utf-8", "replace"))
        ch = (d.get("choices") or [{}])[0]
        msg = ch.get("message") or {}
        content = (msg.get("content") or "").strip()
        reasoning = (msg.get("reasoning_content")
                     or msg.get("reasoning") or "").strip()
        rec.update({
            "http": 200,
            "actual_model": d.get("model") or model,
            "content_chars": len(content),
            "reasoning_chars": len(reasoning),
            "has_reasoning_channel": bool(reasoning),
            "response": content[:80],
        })
        if not content and not reasoning:
            rec["status"] = "empty_response"
        else:
            rec["status"] = "available"
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode("utf-8", "replace")
        except Exception:
            err = ""
        blob = err.lower()
        rec.update({"http": e.code, "error": err[:200]})
        if e.code in (401, 403):
            rec["status"] = "credential_or_access_denied"
        elif e.code == 404:
            rec["status"] = "model_id_not_found"
        elif e.code == 429:
            rec["status"] = "rate_limited"
        elif e.code == 402:
            rec["status"] = "quota_exhausted"
        elif any(k in blob for k in ("quota", "limit", "exceed", "额度",
                                     "配额", "insufficient")):
            rec["status"] = "quota_exhausted"
        elif any(k in blob for k in ("blocked", "blocked model", "not allow",
                                     "not allowed")):
            rec["status"] = "quota_exhausted"
        else:
            rec["status"] = "http_error_%d" % e.code
    except urllib.error.URLError as e:
        rec.update({"http": None,
                    "error": "%s: %s" % (type(e.reason).__name__, e.reason),
                    "status": "network_error"})
    except Exception as e:
        rec.update({"http": None,
                    "error": "%s: %s" % (type(e).__name__, e)[:200],
                    "status": "error"})
    rec["latency_ms"] = int((time.time() - t0) * 1000)
    return rec


def load_history():
    if not os.path.exists(OUT):
        return []
    try:
        d = json.load(open(OUT, encoding="utf-8"))
        return d.get("history", [])
    except Exception:
        return []


def last_status(history, code):
    for obs in reversed(history):
        for r in obs.get("results", []):
            if r.get("code") == code:
                return obs["timestamp"], r["status"]
    return None, None


def main():
    t0 = time.time()
    history = load_history()
    results = []
    print("== window watch: %d backends across %d operators"
          % (len(BACKENDS), len({b["operator"] for b in BACKENDS})))
    print()
    for b in BACKENDS:
        r = probe(b["endpoint"], b["key"], b["model"])
        r["code"] = b["code"]
        r["operator"] = b["operator"]
        r["gap"] = b["gap"]
        r["followup"] = b["followup"]
        prev_ts, prev = last_status(history, b["code"])
        r["previous_status"] = prev
        r["previous_at"] = prev_ts
        if prev is None:
            r["delta"] = "first_observation"
        elif prev == r["status"]:
            r["delta"] = "unchanged"
        elif r["status"] == "available" and prev != "available":
            r["delta"] = "NEWLY_OPEN"
        else:
            r["delta"] = "state_changed"
        results.append(r)
        flag = "  <== NEWLY OPEN" if r["delta"] == "NEWLY_OPEN" else ""
        print("%-4s %-11s %-24s %-26s %s"
              % (b["code"], b["operator"], r["status"],
                 r.get("actual_model", r.get("model", ""))[:26], flag))
        time.sleep(SLEEP_S)

    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    new_open = [r for r in results if r["delta"] == "NEWLY_OPEN"]
    still_locked = [r for r in results if r["status"] != "available"]
    hist_entry = {
        "timestamp": now,
        "n_backends": len(results),
        "n_available": sum(1 for r in results if r["status"] == "available"),
        "n_with_reasoning_channel": sum(
            1 for r in results if r.get("has_reasoning_channel")),
        "newly_open": [r["code"] for r in new_open],
        "results": results,
    }
    history.append(hist_entry)
    doc = {
        "tool": "window_watch",
        "version": 1,
        "description": ("One-shot availability sentinel over every gateway "
                        "backend used by the study, with the concrete "
                        "follow-up command for each backend that is still "
                        "locked. Probes are minimal (8 output tokens) and "
                        "feed no experiment."),
        "gateways": sorted({b["operator"] for b in BACKENDS}),
        "n_backends": len(BACKENDS),
        "elapsed_sec": round(time.time() - t0, 1),
        "history": history,
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)

    print()
    print("available %d/%d, reasoning channel %d/%d, newly opened %s"
          % (hist_entry["n_available"], len(results),
             hist_entry["n_with_reasoning_channel"], len(results),
             hist_entry["newly_open"] or "none"))
    print("still locked: %s"
          % ", ".join("%s(%s)" % (r["code"], r["status"]) for r in still_locked)
          or "none")
    if new_open:
        print()
        print("FOLLOW-UP ACTIONS FOR BACKENDS THAT JUST REOPENED:")
        for r in new_open:
            print("  [%s] %s" % (r["code"], r["followup"]))
    else:
        print()
        print("No backend newly opened; the quota-blocked follow-ups stand:")
        seen = set()
        for r in still_locked:
            if r["followup"] in seen:
                continue
            seen.add(r["followup"])
            print("  [%s] %s: %s" % (r["code"], r["gap"][:72], r["followup"]))
    print()
    print("--> %s (history runs %d)" % (OUT, len(history)))


if __name__ == "__main__":
    main()
