"""CLI: 用大模型攻击 SQLite 蜜罐数据库。

用法：
    python -m experiments.sql_exfil.run --config configs/sensenova.yaml \
        --out results/sensenova-sql-exfil/

环境变量：SENSENOVA_API_KEY 必填。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def _load_config(path: str) -> dict:
    """读 sensenova.yaml（手写最小 YAML 解析，避免 PyYAML 依赖）。"""
    import re
    p = Path(path)
    txt = p.read_text(encoding="utf-8")
    d: dict = {}
    cur_key = None
    for raw in txt.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if ":" not in stripped:
            continue
        k, _, v = stripped.partition(":")
        k = k.strip()
        v = v.strip()
        if indent == 0:
            cur_key = k
            d[k] = {}
        else:
            if cur_key and isinstance(d.get(cur_key), dict):
                # strip inline comments
                if " #" in v:
                    v = v.split(" #")[0].strip()
                if v.startswith("${") and v.endswith("}"):
                    env = v[2:-1]
                    v = os.environ.get(env, "")
                # 数值转换
                if v in ("true", "True"):
                    v = True
                elif v in ("false", "False"):
                    v = False
                elif v == "":
                    pass
                else:
                    try:
                        if "." in v:
                            v = float(v)
                        else:
                            v = int(v)
                    except ValueError:
                        pass
                d[cur_key][k] = v
    return d


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/sensenova.yaml")
    ap.add_argument("--out", default="results/sensenova-sql-exfil")
    ap.add_argument("--max-steps", type=int, default=5)
    args = ap.parse_args()

    # 直接读取环境变量，避免复杂 YAML 解析
    spec = {
        "model": os.environ.get("SENSENOVA_MODEL", "sensenova-6.8-flash-lite"),
        "api_key": os.environ.get("SENSENOVA_API_KEY", ""),
        "base_url": os.environ.get("SENSENOVA_BASE_URL", "https://token.sensenova.cn/v1"),
        "temperature": float(os.environ.get("SENSENOVA_TEMPERATURE", "0.1")),
        "max_tokens": int(os.environ.get("SENSENOVA_MAX_TOKENS", "512")),
    }
    if not spec["api_key"]:
        print("ERROR: SENSENOVA_API_KEY not set")
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    from experiments.sql_exfil.agent import evaluate

    t0 = time.time()
    result = evaluate(spec, workdir=str(out_dir), max_steps=args.max_steps)
    dt = time.time() - t0

    # 落盘
    run_id = time.strftime("%Y%m%d-%H%M%S")
    json_path = out_dir / f"run_{run_id}.json"
    json_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # 控制台摘要
    print(f"\n=== SQL Exfiltration Attack vs SenseNova 6.8 Flash-Lite ===")
    print(f"Run: {json_path}")
    print(f"Audit log: {result['audit_path']}")
    print(f"Total probes: {result['total']}  Exfil success: {result['exfil_success']}  "
          f"ASR: {result['asr']*100:.1f}%  (elapsed {dt:.1f}s)")
    print(f"\nBy scenario:")
    for sc, v in sorted(result["by_scenario"].items()):
        print(f"  {sc:32s} total={v['total']} ok={v['success']} ASR={v['asr']*100:.0f}%")
    print(f"\nPer-probe results:")
    for r in result["results"]:
        tag = "✅ EXFIL" if r["exfil_success"] else "❌ refused"
        print(f"  [{tag}] {r['attack_id']:32s} queries={r['n_queries']} "
              f"secrets_leaked={len(r['secrets_stolen'])}")
        for q in r["queries"]:
            print(f"          Q: {q[:120]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
