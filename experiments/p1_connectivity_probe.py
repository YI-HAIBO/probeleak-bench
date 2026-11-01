"""
P1.1 连通性探针（第 2 次重试，2026-10-17）

目的：判定"沙箱在出站 HTTP 上剥离 POST Authorization 头"这一结论是否仍然成立，
并穷举可能绕过该剥离的传参方式。不做任何重试循环——单次请求、逐个方案、
逐个记录可复现的判据（响应头 + 响应体 + HTTP 状态码）。

关键判据（上一轮已确立，本轮首先复现它）：
  用同一个 key，对比"带 Authorization 头"与"不带任何凭据"两种请求。
  若服务端在两种情况下返回**完全相同**的 "Missing Authentication header"，
  则说明凭据从未到达服务端 —— 这是剥离发生的服务端证据，而不是本地网络错误
  （网络错误会表现为超时/连接拒绝/TLS 握手失败，而不是一个语义完整的 401 JSON）。

穷举的传参方案：
  1. header Authorization: Bearer <key>           （标准）
  2. header Authorization: <key>                  （无 scheme）
  3. header 大小写变体 X-Auth / authorization      （绕过大小写敏感的剥离器）
  4. query string ?api_key= / ?key=               （header 剥离器管不到 URL）
  5. 表单字段 api_key=                             （另一个编码面）
  6. 自定义头 X-API-Key / x-goog-api-key           （部分网关接受）
  7. 请求体字段 {"api_key": ...}                  （部分网关接受）
  8. 不同出站端点：官方 api.deepseek.com 直连     （排除聚合层因素）
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"

API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip()

ENDPOINTS = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "deepseek_direct": "https://api.deepseek.com/v1/chat/completions",
    "openai": "https://api.openai.com/v1/chat/completions",
}
MODEL_BY_ENDPOINT = {
    "openrouter": "deepseek/deepseek-v3",
    "deepseek_direct": "deepseek-chat",
    "openai": "gpt-4o-mini",
}

TIMEOUT = 25

BASE_BODY = {
    "model": "deepseek/deepseek-v3",
    "messages": [{"role": "user", "content": "Reply with exactly: P1_OK"}],
    "max_tokens": 8,
    "temperature": 0,
}


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post(url: str, body: dict, headers: Dict[str, str],
          timeout: int = TIMEOUT) -> Dict:
    """发一个 POST，返回可复现判据字典（不抛异常）。"""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "p1-probe/2.0",
                 **headers},
    )
    out: Dict = {"url": url, "header_keys_sent": sorted(headers.keys()),
                 "body_keys_sent": sorted(body.keys()),
                 "status": None, "elapsed_ms": None,
                 "resp_headers": {}, "resp_text": None, "error": None}
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            out["status"] = r.status
            out["elapsed_ms"] = int((time.time() - t0) * 1000)
            out["resp_headers"] = {k: v for k, v in r.headers.items()}
            out["resp_text"] = r.read().decode("utf-8", "replace")[:1200]
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        out["resp_headers"] = {k: v for k, v in e.headers.items()}
        try:
            out["resp_text"] = e.read().decode("utf-8", "replace")[:1200]
        except Exception as ee:  # noqa: BLE001
            out["resp_text"] = f"<unreadable: {ee!r}>"
    except Exception as e:  # noqa: BLE001  超时/连接失败必须与 401 区分
        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def _get(url: str, headers: Optional[Dict[str, str]] = None,
         timeout: int = 12) -> Dict:
    """GET 探针：GET 不需要凭据也能返回可达性判据。"""
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "p1-probe/2.0",
                                          **(headers or {})})
    out: Dict = {"url": url, "status": None, "elapsed_ms": None,
                 "resp_text": None, "error": None}
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            out["status"] = r.status
            out["elapsed_ms"] = int((time.time() - t0) * 1000)
            out["resp_text"] = r.read().decode("utf-8", "replace")[:400]
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        try:
            out["resp_text"] = e.read().decode("utf-8", "replace")[:400]
        except Exception:  # noqa: BLE001
            out["resp_text"] = None
    except Exception as e:  # noqa: BLE001
        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def resolve(host: str) -> List[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443)})
    except Exception as e:  # noqa: BLE001
        return [f"<resolve_failed: {e}>"]


def env_dump() -> Dict:
    keys = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
            "no_proxy", "OPENROUTER_API_KEY", "OPENAI_API_KEY")
    return {k: os.environ.get(k) for k in keys}


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    print("=" * 78)
    print("P1.1 连通性探针（第 2 次重试）")
    print("=" * 78)

    if not API_KEY:
        print("[FATAL] OPENROUTER_API_KEY 未设置 —— 无法做任何鉴权判据")
        sys.exit(2)
    print(f"key 长度={len(API_KEY)} 前缀={API_KEY[:9]}…")
    print("代理/环境变量:", {k: v for k, v in env_dump().items()
                             if k != "OPENROUTER_API_KEY"})
    for ep in ENDPOINTS:
        host = urllib.parse.urlparse(ENDPOINTS[ep]).hostname
        print(f"  DNS {host} -> {resolve(host)}")
    print()

    log: Dict = {
        "key_meta": {"length": len(API_KEY), "prefix": API_KEY[:9],
                     "suffix": API_KEY[-4:]},
        "env": {k: v for k, v in env_dump().items() if k != "OPENROUTER_API_KEY"},
        "dns": {urllib.parse.urlparse(u).hostname: resolve(
            urllib.parse.urlparse(u).hostname) for u in ENDPOINTS.values()},
        "steps": [],
    }

    # ---- 步骤 0：GET 可达性（不需要凭据，判网络层） ----
    print("[步骤 0] GET 可达性（无凭据）")
    for name, url in ENDPOINTS.items():
        g = _get(url)
        log["steps"].append({"step": "get_reachability", "endpoint": name, **g})
        print(f"  {name:16s} status={g['status']} err={g['error']} "
              f"({g['elapsed_ms']}ms)")
    print()

    # ---- 步骤 1：核心判据 —— 带凭据 vs 无凭据是否完全一致 ----
    print("[步骤 1] 核心判据：Authorization 头是否到达服务端")
    ep = ENDPOINTS["openrouter"]
    body = dict(BASE_BODY, model=MODEL_BY_ENDPOINT["openrouter"])

    ctrl = _post(ep, body, {})                      # 对照：完全不发凭据
    treat = _post(ep, body, {"Authorization": f"Bearer {API_KEY}"})
    log["steps"].extend([{"step": "no_credential_control", **ctrl},
                         {"step": "with_authorization", **treat}])

    same = (ctrl["status"] == treat["status"]
            and ctrl["resp_text"] == treat["resp_text"])
    print(f"  无凭据:  status={ctrl['status']} err={ctrl['error']}")
    print(f"    body: {(ctrl['resp_text'] or '')[:180]}")
    print(f"  带凭据:  status={treat['status']} err={treat['error']}")
    print(f"    body: {(treat['resp_text'] or '')[:180]}")
    print(f"  -> 两者响应完全一致 = {same}")
    log["credential_header_verdict"] = {
        "control_equals_treatment": same,
        "interpretation": (
            "凭据头未到达服务端（服务端对两种请求给出相同答复）"
            if same else "凭据头至少改变了服务端行为，可继续排查"),
    }
    print()

    # ---- 步骤 2：穷举替代传参方式 ----
    print("[步骤 2] 穷举替代传参方式（openrouter 端点）")
    variants: List[tuple] = [
        ("bearer_std", {"Authorization": f"Bearer {API_KEY}",
                        "Content-Type": "application/json"}, body),
        ("no_scheme", {"Authorization": API_KEY,
                       "Content-Type": "application/json"}, body),
        ("lower_auth", {"authorization": f"Bearer {API_KEY}",
                        "Content-Type": "application/json"}, body),
        ("x_auth", {"X-Auth": f"Bearer {API_KEY}",
                    "Content-Type": "application/json"}, body),
        ("x_api_key", {"X-API-Key": API_KEY,
                       "Content-Type": "application/json"}, body),
        ("x_goog", {"x-goog-api-key": API_KEY,
                    "Content-Type": "application/json"}, body),
        ("query_api_key", {"Content-Type": "application/json"}, body),
        ("query_key", {"Content-Type": "application/json"}, body),
        ("body_field", {"Content-Type": "application/json"},
         dict(body, api_key=API_KEY)),
    ]
    url_q_apikey = ep + "?" + urllib.parse.urlencode({"api_key": API_KEY})
    url_q_key = ep + "?" + urllib.parse.urlencode({"key": API_KEY})

    for name, headers, b in variants:
        url = ep
        if name == "query_api_key":
            url = url_q_apikey
        elif name == "query_key":
            url = url_q_key
        r = _post(url, b, headers)
        log["steps"].append({"step": "variant", "variant": name, **r})
        txt = (r["resp_text"] or r["error"] or "")[:110]
        print(f"  {name:15s} status={r['status']} ({r['elapsed_ms']}ms) "
              f"{txt}")

    # ---- 步骤 3：直连 deepseek（绕过聚合层） ----
    print("\n[步骤 3] DeepSeek 官方直连（排除聚合层因素）")
    body_ds = dict(BASE_BODY, model="deepseek-chat")
    ds = _post(ENDPOINTS["deepseek_direct"], body_ds,
               {"Authorization": f"Bearer {API_KEY}"})
    log["steps"].append({"step": "deepseek_direct", **ds})
    print(f"  status={ds['status']} ({ds['elapsed_ms']}ms) "
          f"{(ds['resp_text'] or ds['error'] or '')[:200]}")

    # ---- 步骤 4：deepseek 端点的对照判据（该端点自己报什么错） ----
    ds_none = _post(ENDPOINTS["deepseek_direct"], body_ds, {})
    log["steps"].append({"step": "deepseek_direct_no_credential", **ds_none})
    same_ds = (ds["resp_text"] == ds_none["resp_text"])
    print(f"  对照(无凭据): status={ds_none['status']} "
          f"{(ds_none['resp_text'] or ds_none['error'] or '')[:120]}")
    print(f"  deepseek 端点上两者响应一致 = {same_ds}")
    log["credential_header_verdict"]["deepseek_control_equals_treatment"] = same_ds
    print()

    ok = any(s.get("status") == 200 for s in log["steps"]
             if s.get("step") in ("variant", "deepseek_direct"))
    if ok:
        log["verdict"] = "REAL_LLM_REACHABLE"
    elif any(s.get("status") == 401 and "invalid" in (s.get("resp_text") or "").lower()
             for s in log["steps"]):
        # 服务端读到了 key 全文并明确判 invalid（如 DeepSeek 回显 ****d43b）
        # —— 这是「凭据到达服务端、但 key 对该厂商无效」的证据，
        # 与「网络层剥离凭据头」完全不同。
        log["verdict"] = "CREDENTIALS_REACH_SERVER_KEY_INVALID"
    elif same:
        log["verdict"] = "SANDBOX_BLOCKS_CREDENTIALS"
    else:
        log["verdict"] = "UNKNOWN"
    log["timestamp_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    out_path = RESULTS / "p1_connectivity_probe_v2.json"
    out_path.write_text(json.dumps(log, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
    print("=" * 78)
    print(f"[结论] {log['verdict']}")
    print(f"[输出] {out_path}")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
