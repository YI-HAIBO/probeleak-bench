"""E1 候选模型普查（第二网关）

目的：在 kilo.ai 网关上筛出「免费可用 + 响应体暴露明文 reasoning 通道 +
与 dots-3-note-preview 不同模型族」的候选，作为 E1 跨模型复现的目标。

判据（全部落盘）：
  1. HTTP 200 且 finish_reason == 'stop'（非截断、非拒答）
  2. message.reasoning 非空且明文（非 reasoning_details 加密块）
  3. message.content 非空（双通道都在，才能做 final vs CoT 对比）
  4. 实际 model id 与 dots-3-note-preview 无关（真正的跨厂商）
  5. usage.completion_tokens_details.reasoning_tokens > 0

输出：results/e1_model_survey_v1.json
"""

import json
import os
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "results", "e1_model_survey_v1.json")
LOG = os.path.join(ROOT, "results", "e1_survey.ndjson")

ENDPOINT = "https://api.kilo.ai/api/gateway/chat/completions"
KEY = "anonymous"

# 候选：优先选「知名开源推理模型 + :free 或常见免费档」
CANDIDATES = [
    "deepseek/deepseek-v3.2",
    "deepseek/deepseek-v4-flash",
    "deepseek/deepseek-r1",
    "qwen/qwen3-next-80b-a3b-thinking",
    "qwen/qwen3-235b-a22b-thinking-2507",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "thinkingmachines/inkling-small:free",
    "moonshotai/kimi-k2-thinking",
    "openrouter/free",
    "reflection/beam-free",
]

# 中性探针：既需要模型产生实质推理（触发 reasoning），又不涉及安全内容
PROBE_USER = (
    "You are a careful assistant. Work through this step by step, "
    "showing your reasoning, then give a concise final answer.\n\n"
    "In a 5x5 grid of unit squares, how many squares of any size "
    "(1x1, 2x2, 3x3, 4x4, 5x5) are there in total? "
    "Explain how you count."
)

HDRS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + KEY,
}


def call(model, max_tokens=700, tries=2):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": PROBE_USER}],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }
    for attempt in range(1, tries + 1):
        t0 = time.time()
        try:
            req = urllib.request.Request(
                ENDPOINT, data=json.dumps(body).encode(), headers=HDRS
            )
            with urllib.request.urlopen(req, timeout=180) as r:
                raw = r.read().decode("utf-8", "replace")
                d = json.loads(raw)
            return {
                "http": 200,
                "raw": d,
                "latency": round(time.time() - t0, 2),
                "attempt": attempt,
            }
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", "replace")[:400]
            rec = {
                "http": e.code,
                "error": err,
                "latency": round(time.time() - t0, 2),
                "attempt": attempt,
            }
            # 4xx（除 429）不重试
            if 400 <= e.code < 500 and e.code != 429:
                return rec
            time.sleep(5)
        except Exception as e:
            rec = {
                "http": None,
                "error": type(e).__name__ + ": " + str(e)[:300],
                "latency": round(time.time() - t0, 2),
                "attempt": attempt,
            }
            time.sleep(5)
    return rec


def summarize(model, rec):
    """按判据打分。"""
    out = {
        "model_id_requested": model,
        "http": rec.get("http"),
        "latency": rec.get("latency"),
        "attempt": rec.get("attempt"),
    }
    if rec.get("error"):
        out["error"] = rec["error"]
        out["usable"] = False
        out["reason"] = "api_error"
        return out

    raw = rec["raw"]
    ch = (raw.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    usage = raw.get("usage") or {}
    ctd = usage.get("completion_tokens_details") or {}
    reasoning = msg.get("reasoning")
    content = msg.get("content")
    refusal = msg.get("refusal")

    out["actual_model"] = raw.get("model")
    out["provider"] = raw.get("provider")
    out["finish_reason"] = ch.get("finish_reason")
    out["native_finish_reason"] = ch.get("native_finish_reason")
    out["completion_tokens"] = usage.get("completion_tokens")
    out["reasoning_tokens"] = ctd.get("reasoning_tokens")
    out["cached_tokens"] = (usage.get("prompt_tokens_details") or {}).get(
        "cached_tokens"
    )
    out["reasoning_chars"] = len(reasoning or "")
    out["content_chars"] = len(content or "")
    out["has_refusal"] = bool(refusal)
    out["reasoning_sample"] = (reasoning or "")[:220]
    out["content_sample"] = (content or "")[:220]

    checks = {
        "ok_200": rec.get("http") == 200,
        "finish_stop": ch.get("finish_reason") == "stop",
        "reasoning_nonempty": out["reasoning_chars"] > 80,
        "reasoning_token_field": (ctd.get("reasoning_tokens") or 0) > 0,
        "content_nonempty": out["content_chars"] > 30,
        "no_refusal": not bool(refusal),
        "not_truncated": ch.get("finish_reason") != "length",
    }
    out["checks"] = checks
    out["all_pass"] = all(checks.values())

    same_family = any(
        k in (out["actual_model"] or "").lower()
        for k in ("dots-3-note", "dots_studio", "dots3")
    )
    out["same_family_as_primary"] = same_family
    out["usable"] = out["all_pass"] and not same_family
    out["reason"] = (
        "pass"
        if out["usable"]
        else "same_family_as_primary"
        if same_family
        else "failed_checks:"
        + ",".join(k for k, v in checks.items() if not v)
    )
    return out


def main():
    logf = open(LOG, "a", encoding="utf-8")
    results = []
    for model in CANDIDATES:
        rec = call(model)
        s = summarize(model, rec)
        results.append(s)
        logf.write(
            json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), **s},
                       ensure_ascii=False)
            + "\n"
        )
        logf.flush()
        print(
            "%-52s usable=%-5s actual=%-38s reason=%s"
            % (
                model[:52],
                s["usable"],
                str(s.get("actual_model"))[:38],
                s.get("reason"),
            ),
            flush=True,
        )
    logf.close()

    usable = [r for r in results if r["usable"]]
    same = [r for r in results if r.get("same_family_as_primary")]
    out = {
        "phase": "E1-model-survey",
        "endpoint": ENDPOINT,
        "probed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "n_candidates": len(CANDIDATES),
        "n_usable": len(usable),
        "usable_models": [r["actual_model"] for r in usable],
        "same_family_models": [r["actual_model"] for r in same],
        "results": results,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("---")
    print("usable:", out["usable_models"])
    print("same-family (excluded):", out["same_family_models"])
    print("WROTE", OUT)


if __name__ == "__main__":
    main()
