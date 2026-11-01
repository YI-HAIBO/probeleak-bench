#!/usr/bin/env python3
"""Snapshot the anonymous cross-vendor gateway free pool (window 3).

Run once per quota window so the drift report can state, from an artifact
rather than from memory, which backends were actually reachable and which
had rotated out.
"""

import json
import os
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "kilo_window3_pool.json")
EP = "https://api.kilo.ai/api/gateway/models"


def main():
    t0 = time.time()
    with urllib.request.urlopen(EP, timeout=30) as r:
        d = json.load(r)
    rows = d.get("data", d)
    free = sorted(x.get("id", "") for x in rows if ":free" in x.get("id", ""))
    out = {
        "experiment": "kilo_free_pool_snapshot",
        "window": 3,
        "captured_utc": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "endpoint": EP,
        "n_listed": len(rows),
        "n_free": len(free),
        "free_models": free,
        "elapsed_sec": round(time.time() - t0, 1),
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)
    print("--> %s  listed=%d free=%d" % (OUT, len(rows), len(free)))


if __name__ == "__main__":
    main()
