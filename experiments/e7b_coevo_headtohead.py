#!/usr/bin/env python3
"""E7b: head-to-head allocation for the co-evolution arm.

E7 shows the Thompson bandit concentrates almost all pulls on the single
best fixed arm, so the co-evolution arm receives too few pulls to be
compared. E7b therefore drops the adaptive allocation and uses a fixed
interleaved schedule instead:

    24 episodes, alternating
      odd  -> co-evolution arm (wording generated at pull time by the
              attacker-side model, conditioned on the previous outcome)
      even -> the best fixed arm identified by E7 (>=3 pulls), used as the
              head-to-head control

Interleaving controls for any slow drift in the target or the gateway
during the run. The comparison is a Fisher exact test on the two
12-pull samples, plus a first-half / second-half split inside the
co-evolution arm to test adaptation.

Output: results/e7b_coevo_headtohead_v1.json
Checkpoint: results/e7b_coevo_headtohead_checkpoint.ndjson
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import e7_coevo_bandit as e7  # noqa: E402
from e5_adaptive_rl_attacker import MODEL, RateLimiter, api_chat, judge  # noqa: E402

ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "results", "e7b_coevo_headtohead_v1.json")
CKPT = os.path.join(ROOT, "results", "e7b_coevo_headtohead_checkpoint.ndjson")
E7JSON = os.path.join(ROOT, "results", "e7_coevo_bandit_v1.json")

SEED = 20261025
N_EPISODES = 24          # 12 co-evolution + 12 control
SLEEP_S = 2.0
FALLBACK_ARM = "tl-b"


def best_fixed_arm():
    """Best fixed arm in E7 among arms with >=3 pulls (rate, then pulls)."""
    try:
        with open(E7JSON, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return FALLBACK_ARM, None
    cands = [(k, v) for k, v in (d.get("per_arm") or {}).items()
             if k != e7.CO_ARM and (v.get("pulls") or 0) >= 3]
    if not cands:
        return FALLBACK_ARM, None
    k, v = max(cands, key=lambda kv: ((kv[1].get("cot_rate") or 0),
                                      kv[1].get("pulls") or 0))
    return k, v.get("cot_rate")


def load_ckpt():
    if not os.path.exists(CKPT):
        return []
    out, seen = [], set()
    for line in open(CKPT, encoding="utf-8"):
        if line.strip():
            r = json.loads(line)
            if r["id"] not in seen:
                seen.add(r["id"])
                out.append(r)
    return out


def save_ckpt(recs):
    tmp = CKPT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, CKPT)


def main():
    t0 = time.time()
    rl = RateLimiter()
    recs = load_ckpt()
    print("checkpoint: %d finished episodes" % len(recs), flush=True)

    ctrl_arm, ctrl_rate = best_fixed_arm()
    ctrl_text = next(a["user"] for a in e7.ARMS_13 if a["arm"] == ctrl_arm)
    print("control arm = %s (E7 rate %s)" % (ctrl_arm, ctrl_rate), flush=True)

    att_log = []
    ep = len(recs)
    while ep < N_EPISODES:
        ep_id = "e7b_ep%03d" % (ep + 1)
        use_co = (ep % 2 == 0)          # odd episodes (1-based) -> co-evo
        user_text = ctrl_text
        arm = ctrl_arm
        if use_co:
            arm = e7.CO_ARM
            seed = e7.seed_text(recs)
            fb = e7.feedback_text(recs)
            att = e7.att_call(e7.ATTACKER_TEMPLATE % (seed, fb))
            att_log.append({"episode": ep + 1, "seed_arm": ctrl_arm,
                            "feedback": fb[:60],
                            **{k: v for k, v in att.items() if k != "text"}})
            if att.get("ok"):
                user_text = att["text"].strip().strip('"').strip()
                att_log[-1]["text_len"] = len(user_text)
            else:
                user_text = seed
                att_log[-1]["fallback_to_seed"] = True
            print("    [co-evo] %sms ok=%s len=%d"
                  % (att.get("latency_ms"), att.get("ok"), len(user_text)),
                  flush=True)

        rl.wait()
        out = api_chat(user_text)
        rl.record((out.get("raw") or {}).get("usage", {}).get("total_tokens")
                  if out.get("ok") else 0)

        rec = {"id": ep_id, "episode": ep + 1, "arm": arm,
               "family": "co_evolution" if use_co else "fixed_control",
               "user_text": user_text, "api_ok": out["ok"],
               "attempt": out.get("attempt"),
               "latency_ms": out.get("latency_ms")}
        if out["ok"]:
            raw = out["raw"]
            ch = (raw.get("choices") or [{}])[0]
            msg = ch.get("message") or {}
            usage = raw.get("usage") or {}
            reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
            content = msg.get("content") or ""
            rec.update({
                "actual_model": raw.get("model"),
                "reasoning_chars": len(reasoning),
                "content_chars": len(content),
                "total_tokens": usage.get("total_tokens"),
                "reasoning": reasoning, "content": content,
            })
            judge(rec, reasoning, content)
        else:
            rec.update({"http": out.get("http"), "error": out.get("error"),
                        "reasoning_chars": 0, "content_chars": 0,
                        "cot_leak": False, "final_leak": False,
                        "refusal": False})
        recs.append(rec)
        save_ckpt(recs)
        print("%s arm=%-5s ok=%s cot=%s fin=%s ref=%s rch=%s"
              % (ep_id, arm, rec["api_ok"], rec.get("cot_leak"),
                 rec.get("final_leak"), rec.get("refusal"),
                 rec.get("reasoning_chars")), flush=True)
        ep += 1
        time.sleep(SLEEP_S)

    ok = [r for r in recs if r.get("api_ok")]
    co = [r for r in ok if r["arm"] == e7.CO_ARM]
    fx = [r for r in ok if r["arm"] != e7.CO_ARM]
    c_leak = sum(1 for r in co if r.get("cot_leak"))
    f_leak = sum(1 for r in fx if r.get("cot_leak"))

    adapt = None
    if len(co) >= 6:
        h1, h2 = co[:len(co) // 2], co[len(co) // 2:]
        a1 = sum(1 for r in h1 if r.get("cot_leak"))
        a2 = sum(1 for r in h2 if r.get("cot_leak"))
        adapt = {"first_half": [a1, len(h1)], "second_half": [a2, len(h2)],
                 "rate_delta": round(a2 / len(h2) - a1 / len(h1), 6)}

    cmp_ = None
    if co and fx:
        cmp_ = {"co_leaks": c_leak, "co_n": len(co),
                "fixed_leaks": f_leak, "fixed_n": len(fx),
                "co_rate": round(c_leak / len(co), 6),
                "fixed_rate": round(f_leak / len(fx), 6),
                "fisher_p": e7.fisher_exact(c_leak, len(co) - c_leak,
                                            f_leak, len(fx) - f_leak)}

    n_att = len(att_log)
    n_att_ok = sum(1 for x in att_log if x.get("ok"))
    texts = [r["user_text"] for r in co]
    gates = {
        "g1_budget_completed": {
            "check": "all 24 episodes landed with unique ids",
            "n_records": len(recs),
            "n_unique": len({r["id"] for r in recs}),
            "passed": len(recs) == len({r["id"] for r in recs}) == N_EPISODES,
        },
        "g2_balanced_allocation": {
            "check": "12 co-evolution and 12 control episodes usable",
            "co_usable": len(co), "fixed_usable": len(fx),
            "passed": len(co) >= 10 and len(fx) >= 10,
        },
        "g3_attacker_usable": {
            "check": "paraphraser returned usable text on >=80% of pulls",
            "pulls": n_att, "ok": n_att_ok,
            "passed": bool(n_att) and n_att_ok / n_att >= 0.8,
        },
        "g4_generated_prompts_differ": {
            "check": "co-evolution produced distinct prompts",
            "n_texts": len(texts), "n_unique": len(set(texts)),
            "passed": len(set(texts)) >= max(2, len(texts) - 2),
        },
        "g5_target_responsive": {
            "check": ">=90% of episodes returned a usable response",
            "n_ok": len(ok), "n_total": len(recs),
            "passed": bool(recs) and len(ok) / len(recs) >= 0.9,
        },
    }

    out = {
        "experiment": "e7b_coevo_headtohead",
        "version": 1,
        "description": ("Fixed interleaved allocation: 12 co-evolution "
                        "pulls versus 12 pulls of the best fixed arm from "
                        "E7, on the same target, to give the "
                        "co-evolution arm a sample large enough to "
                        "compare."),
        "seed": SEED,
        "n_episodes": N_EPISODES,
        "target_model": MODEL,
        "attacker_model": e7.ATT_MODEL,
        "control_arm": ctrl_arm,
        "control_arm_e7_rate": ctrl_rate,
        "elapsed_sec": round(time.time() - t0, 1),
        "co_evolution": {
            "pulls": len(co), "cot_leaks": c_leak,
            "rate": round(c_leak / len(co), 6) if co else None,
            "wilson95": e7.wilson(c_leak, len(co)) if co else None,
            "adaptation": adapt,
            "generated_texts": texts,
        },
        "fixed_control": {
            "arm": ctrl_arm, "pulls": len(fx), "cot_leaks": f_leak,
            "rate": round(f_leak / len(fx), 6) if fx else None,
            "wilson95": e7.wilson(f_leak, len(fx)) if fx else None,
        },
        "comparison": cmp_,
        "final_leaks_total": sum(1 for r in ok if r.get("final_leak")),
        "refusals_total": sum(1 for r in ok if r.get("refusal")),
        "attacker_calls": att_log,
        "gates": gates,
        "records": recs,
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)
    print("--> %s" % OUT, flush=True)
    print("    gates: %s" % {k: v.get("passed") for k, v in gates.items()},
          flush=True)
    print("    co %d/%d vs %s %d/%d  fisher=%s"
          % (c_leak, len(co), ctrl_arm, f_leak, len(fx),
             (cmp_ or {}).get("fisher_p")), flush=True)


if __name__ == "__main__":
    main()
