"""Probe each cross-vendor model used by E1 (anonymous quota status)."""
import json, time, urllib.request, urllib.error

URL = "https://api.kilo.ai/api/gateway/chat/completions"
KEY = "anonymous"
MODELS = [
    "nvidia/nemotron-3-super-120b-a12b:free",
    "reflection/beam-free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "openrouter/free",
]
for model in MODELS:
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": "What is 2+3? Answer with the number only."}],
        "max_tokens": 256,
        "temperature": 0.1,
    }).encode()
    req = urllib.request.Request(URL, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + KEY,
    })
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            d = json.loads(r.read().decode())
        ch = (d.get("choices") or [{}])[0].get("message", {})
        rc = len(ch.get("reasoning_content") or "")
        print("%-52s OK  %.1fs r=%d c=%d tok=%s" % (model, time.time() - t0, rc,
              len(ch.get("content") or ""), d.get("usage", {}).get("total_tokens")))
    except urllib.error.HTTPError as e:
        print("%-52s http=%s %.1fs %s" % (model, e.code, time.time() - t0,
              e.read().decode("utf-8", "replace")[:130]))
    except Exception as e:
        print("%-52s ERR %.1fs %r" % (model, time.time() - t0, e))
    time.sleep(1.5)
