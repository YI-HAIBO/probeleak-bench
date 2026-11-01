import os
"""Connectivity probe for the two real gateways (cheap: 1 request each)."""
import json, time, urllib.request, urllib.error

PRIMARY = ("https://note3-prev-api.askdiandian.com/v1/chat/completions",
           os.environ.get("PROBELEAK_PRIMARY_KEY", ""), "dots3-note-prev")
CROSS = ("https://api.kilo.ai/api/gateway/chat/completions",
         "anonymous", "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free")

USER = "What is 2+3? Answer with the number only."

for name, (url, key, model) in (("PRIMARY", PRIMARY), ("CROSS-VENDOR", CROSS)):
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": USER}],
        "max_tokens": 256,
        "temperature": 0.1,
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + key,
    })
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            d = json.loads(r.read().decode())
        ch = (d.get("choices") or [{}])[0].get("message", {})
        rc = len(ch.get("reasoning_content") or "")
        cc = len(ch.get("content") or "")
        print("%-13s OK  http=200  %.1fs  reasoning=%d chars  content=%d chars  model=%s  tokens=%s"
              % (name, time.time() - t0, rc, cc, d.get("model"), d.get("usage", {}).get("total_tokens")))
    except urllib.error.HTTPError as e:
        print("%-13s FAIL http=%s  %.1fs  body=%s"
              % (name, e.code, time.time() - t0, e.read().decode("utf-8", "replace")[:200]))
    except Exception as e:
        print("%-13s FAIL %.1fs  %r" % (name, time.time() - t0, e))
    time.sleep(1.0)
