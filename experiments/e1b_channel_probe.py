"""E1b census probe: which free reasoning-candidate models on the
cross-vendor gateway actually expose a non-empty plaintext reasoning
channel on a benign request?

Persists results/e1b_channel_probe_v1.json so the census paragraph in
the enhancement report is backed by an artifact rather than ad-hoc
stdout.
"""
import json
import os
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "e1b_channel_probe_v1.json")
CAT = os.path.join(ROOT, "results", "e1_catalog_v1.json")
URL = "https://api.kilo.ai/api/gateway/chat/completions"
KEY = "anonymous"
PROMPT = "What is 2+3? Answer with the number only."
MAX_TOKENS = 64


def call(model):
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": PROMPT}],
        "max_tokens": MAX_TOKENS,
        "temperature": 0.1,
    }).encode()
    req = urllib.request.Request(
        URL, data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + KEY})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            d = json.loads(r.read().decode("utf-8"))
        ch = (d.get("choices") or [{}])[0].get("message", {})
        rc = ch.get("reasoning_content") or ch.get("reasoning") or ""
        cc = ch.get("content") or ""
        return {"http": 200, "ok": True,
                "reasoning_chars": len(rc), "content_chars": len(cc),
                "actual_model": d.get("model"),
                "elapsed": round(time.time() - t0, 1)}
    except urllib.error.HTTPError as e:
        return {"http": e.code, "ok": False,
                "error": e.read().decode("utf-8", "replace")[:200],
                "elapsed": round(time.time() - t0, 1)}
    except Exception as e:
        return {"http": None, "ok": False, "error": str(e)[:200],
                "elapsed": round(time.time() - t0, 1)}


def main():
    cat = json.load(open(CAT, encoding="utf-8"))
    cands = [c for c in cat["reasoning_candidates"] if c.get("free")]
    print("probing %d free reasoning candidates" % len(cands))
    rows = []
    for c in cands:
        mid = c["id"]
        r = call(mid)
        rows.append({"model": mid, **r})
        flag = "REASONING" if (r["ok"] and r["reasoning_chars"] > 0) else \
               ("ok-no-reasoning" if r["ok"] else "blocked")
        print("  %-52s %-16s r=%s" % (mid, flag, r.get("reasoning_chars")))
        time.sleep(1.5)
    n_reasoning = sum(1 for r in rows if r["ok"] and r["reasoning_chars"] > 0)
    n_ok = sum(1 for r in rows if r["ok"])
    n_blocked = len(rows) - n_ok
    out = {
        "experiment": "e1b_channel_probe",
        "version": 1,
        "source": CAT,
        "prompt": PROMPT,
        "max_tokens": MAX_TOKENS,
        "n_candidates": len(rows),
        "n_responsive": n_ok,
        "n_blocked": n_blocked,
        "n_plaintext_reasoning": n_reasoning,
        "rows": rows,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print("responsive=%d blocked=%d plaintext-reasoning=%d -> %s"
          % (n_ok, n_blocked, n_reasoning, OUT))


if __name__ == "__main__":
    main()
