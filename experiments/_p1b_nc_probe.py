#!/usr/bin/env python3
"""P1b quota probe: single control call to Atria-Dawn-Preview (N_C) before
launching the control expansion. Prints HTTP status, latency, and whether a
reasoning channel is present. No state is written."""
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from e4_consumer_channel import SYSTEM_PROMPT  # noqa: E402
from p1_real_scale_validation import build_attack_probes  # noqa: E402

ENDPOINT = "https://discovery-api.intern-ai.org.cn/v1/chat/completions"
KEY = os.environ.get("N_C_KEY", "")

lib = {p["id"]: p for p in build_attack_probes()}
# use the first control probe text
from e1b_extension import CTRL  # noqa: E402
user = lib[CTRL[0]]["user"]

body = {
    "model": "Atria-Dawn-Preview",
    "messages": [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ],
    "max_tokens": 4000,
    "temperature": 0.1,
}
t0 = time.time()
try:
    req = urllib.request.Request(
        ENDPOINT, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + KEY})
    with urllib.request.urlopen(req, timeout=300) as r:
        raw = json.loads(r.read().decode("utf-8", "replace"))
    ch = (raw.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
    content = msg.get("content") or ""
    print("HTTP 200 ok")
    print("model:", raw.get("model"))
    print("latency_ms:", int((time.time() - t0) * 1000))
    print("reasoning_chars:", len(reasoning))
    print("content_chars:", len(content))
    print("finish_reason:", ch.get("finish_reason"))
    print("usage:", raw.get("usage"))
    print("reasoning head:", reasoning[:200].replace("\n", " "))
except urllib.error.HTTPError as e:
    print("HTTP %s" % e.code)
    print("body:", e.read().decode("utf-8", "replace")[:400])
    print("latency_ms:", int((time.time() - t0) * 1000))
except Exception as e:
    print("ERROR %s: %s" % (type(e).__name__, e)[:300])
    print("latency_ms:", int((time.time() - t0) * 1000))
