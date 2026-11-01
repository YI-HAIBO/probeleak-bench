#!/usr/bin/env python3
import os
"""Test third gateway API accessibility for M8 follow-up."""
import json, os, sys, time, urllib.request

ENDPOINT = "https://discovery-api.intern-ai.org.cn/v1/chat/completions"
KEY = os.environ.get("PROBELEAK_N_C_KEY", "")

# minimal test: one control probe on N_F (intern-s2, already clean, low risk)
body = {
    "model": "intern-s2",
    "messages": [
        {"role": "user", "content": "What is 2+2? Answer briefly."},
    ],
    "max_tokens": 100,
    "temperature": 0.1,
}

try:
    req = urllib.request.Request(
        ENDPOINT,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + KEY,
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = json.loads(r.read().decode("utf-8", "replace"))
    print("OK, raw keys:", list(raw.keys()))
    print("full raw:", json.dumps(raw, ensure_ascii=False)[:500])
except urllib.error.HTTPError as e:
    print("HTTPError:", e.code, e.read().decode("utf-8", "replace")[:300])
except Exception as e:
    print("Error:", type(e).__name__, str(e)[:300])