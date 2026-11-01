#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 25: Serverless 绕过 —— 真实 OS 级进程冷启动/复用/残留实测

旧版用 asyncio.sleep + dict 模拟 Serverless 语义。本版在真实操作系统上实测
Serverless 的六个核心攻击面：

  [1] 进程冷启动延迟   —— 真实 spawn python.exe 到 stdout 就绪的墙钟时间分布
  [2] 请求级冷/热差异  —— 真实 TCP server 的首请求 RTT vs 稳态 RTT
  [3] 跨连接状态残留   —— 同一 server 进程服务两个"租户"连接，前一连接写入的
                          敏感值能否被后一连接读回（容器复用的真实攻击面）
  [4] 环境变量泄露     —— 父进程向子进程注入密钥，子进程读回 + 宿主敏感环境变量枚举
  [5] 临时文件残留     —— 子进程写入 %TEMP% 后退出，文件是否跨进程存活
  [6] 进程命令行泄露   —— 密钥出现在 argv 中，同主机其他进程能否枚举到

所有数字均由实测产生，结论按实测动态生成。
"""

import json
import os
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
PY = sys.executable
FAKE_KEY = "FAKE_wxm_sk-prod-abc123def456"
SENSITIVE_RE = re.compile(r"(?i)(key|token|secret|passwd|password|credential)")
SERVER_PORT = 45711

SERVER_SRC = '''
import socket, sys
HOST, PORT = "127.0.0.1", __PORT__
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, PORT))
srv.listen(16)
sys.stdout.write("LISTENING\\n")
sys.stdout.flush()
# 模块级共享状态：模拟 Serverless 容器复用时跨请求保留的进程级变量
STATE = {}
while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    try:
        data = conn.recv(65536).decode("utf-8", "replace").strip()
    except OSError:
        conn.close()
        continue
    if data.startswith("STORE "):
        STATE["key_value"] = data[6:]
        conn.sendall(b"OK")
    elif data == "READ":
        conn.sendall(STATE.get("key_value", "<empty>").encode())
    elif data == "PING":
        conn.sendall(b"PONG")
    else:
        conn.sendall(b"ERR")
    conn.close()
'''


def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    idx = max(0, min(len(sorted_vals) - 1, int(len(sorted_vals) * q) - 1))
    return round(sorted_vals[idx], 3)


# ---------------------------------------------------------------- [1] 进程冷启动
def test_process_cold_start(n=15):
    print(f"\n[1] 真实进程冷启动：spawn python.exe -> stdout READY（{n} 次）")
    lat = []
    for _ in range(n):
        t0 = time.perf_counter()
        p = subprocess.Popen(
            [PY, "-c", "print('READY')"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace",
        )
        line = p.stdout.readline()
        dt = (time.perf_counter() - t0) * 1000
        p.stdout.close()
        p.wait(timeout=30)
        if line.strip() == "READY":
            lat.append(dt)
    s = sorted(lat)
    r = {
        "test": "process_cold_start",
        "description": "真实 spawn 新进程到其 stdout 首次就绪的墙钟时间",
        "n": len(lat),
        "mean_ms": round(statistics.mean(lat), 2),
        "p50_ms": pct(s, 0.50),
        "p95_ms": pct(s, 0.95),
        "min_ms": round(min(lat), 2),
        "max_ms": round(max(lat), 2),
        "stdev_ms": round(statistics.pstdev(lat), 2),
    }
    print(f"    mean={r['mean_ms']}ms  p50={r['p50_ms']}ms  "
          f"p95={r['p95_ms']}ms  min={r['min_ms']}ms  max={r['max_ms']}ms")
    return r


# ---------------------------------------------------------- [2] 请求级冷/热差异
def test_request_cold_vs_warm(n=120):
    print(f"\n[2] 请求级冷/热差异：真实 TCP server 首请求 vs 稳态请求（{n} 次）")
    lat = []
    for i in range(n):
        t0 = time.perf_counter()
        s = socket.create_connection(("127.0.0.1", SERVER_PORT), timeout=10)
        s.sendall(b"PING")
        resp = s.recv(64)
        dt = (time.perf_counter() - t0) * 1000
        s.close()
        if resp == b"PONG":
            lat.append(dt)
    warm = lat[5:]
    warm_sorted = sorted(warm)
    r = {
        "test": "request_cold_vs_warm",
        "description": "长驻 server 进程内，每请求新建 TCP 连接的 RTT 序列",
        "n_requests": len(lat),
        "first_request_ms": round(lat[0], 3),
        "warm_mean_ms": round(statistics.mean(warm), 3),
        "warm_p50_ms": round(statistics.median(warm), 3),
        "warm_p95_ms": pct(warm_sorted, 0.95),
        "warm_min_ms": round(min(warm), 3),
        "warm_max_ms": round(max(warm), 3),
    }
    if statistics.mean(warm) > 0:
        r["cold_warm_ratio"] = round(lat[0] / statistics.mean(warm), 2)
    print(f"    首请求={r['first_request_ms']}ms  稳态 mean={r['warm_mean_ms']}ms  "
          f"p95={r['warm_p95_ms']}ms  冷/热比={r.get('cold_warm_ratio')}")
    return r


# ------------------------------------------------------- [3] 跨连接状态残留
def test_cross_connection_state():
    print("\n[3] 跨连接状态残留：连接A写入 -> 断开 -> 新连接B读取")
    a = socket.create_connection(("127.0.0.1", SERVER_PORT), timeout=10)
    a.sendall(f"STORE {FAKE_KEY}".encode())
    ra = a.recv(64)
    a.close()

    b = socket.create_connection(("127.0.0.1", SERVER_PORT), timeout=10)
    b.sendall(b"READ")
    rb = b.recv(65536)
    b.close()

    leaked = FAKE_KEY.encode() in rb
    r = {
        "test": "cross_connection_state",
        "description": "同一 server 进程模块级变量跨 TCP 连接保留（容器复用语义）",
        "store_response": ra.decode(errors="replace"),
        "new_connection_read": rb.decode(errors="replace"),
        "cross_connection_leak": leaked,
    }
    print(f"    STORE 应答={r['store_response']}  新连接 READ={r['new_connection_read']}")
    print(f"    跨连接泄露: {leaked}")
    return r


# ------------------------------------------------------------ [4] 环境变量泄露
def test_environ_leak():
    print("\n[4] 环境变量泄露：父进程注入密钥 -> 子进程读回 + 宿主敏感变量枚举")
    env = dict(os.environ)
    env["SENSENOVA_API_KEY"] = FAKE_KEY
    p = subprocess.run(
        [PY, "-c", "import os;print(os.environ.get('SENSENOVA_API_KEY','<none>'))"],
        capture_output=True, text=True, timeout=60, env=env,
        encoding="utf-8", errors="replace",
    )
    child_saw = p.stdout.strip()
    hits = sorted({k for k in os.environ if SENSITIVE_RE.search(k)})
    r = {
        "test": "environ_leak",
        "description": "Serverless 密钥经环境变量注入执行环境后的可见性",
        "child_read_env_var": child_saw,
        "env_injection_works": child_saw == FAKE_KEY,
        "sensitive_env_keys_on_host": hits,
        "sensitive_env_key_count": len(hits),
    }
    print(f"    子进程读回: {child_saw}")
    print(f"    宿主敏感环境变量键: {len(hits)} 个 -> {hits[:8]}")
    return r


# ------------------------------------------------------------ [5] 临时文件残留
def test_tmpfile_residue():
    print("\n[5] 临时文件残留：子进程写入 %TEMP% 后退出，文件跨进程存活")
    tmpdir = Path(tempfile.gettempdir())
    target = tmpdir / f"phase25_residue_{os.getpid()}.txt"
    code = (
        "from pathlib import Path;"
        f"Path(r'{target}').write_text({FAKE_KEY!r}, encoding='utf-8')"
    )
    subprocess.run([PY, "-c", code], capture_output=True, text=True, timeout=60)
    exists = target.exists()
    content = target.read_text(encoding="utf-8") if exists else None
    leaked = (content == FAKE_KEY)
    if exists:
        target.unlink()
    r = {
        "test": "tmpfile_residue",
        "description": "子进程正常退出后 %TEMP% 文件是否可被后续进程读回",
        "tmp_path": str(target),
        "file_survived_process_exit": exists,
        "content_read_back": leaked,
        "residue_leak": leaked,
    }
    print(f"    文件跨退出存活: {exists}  内容读回一致: {leaked}")
    return r


# ---------------------------------------------------------- [6] 进程命令行泄露
def test_cmdline_leak():
    print("\n[6] 进程命令行泄露：密钥在 argv 中，枚举同主机进程命令行")
    p = subprocess.Popen(
        [PY, "-c", "import time;time.sleep(6)", "--token", FAKE_KEY],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    wmic = Path("C:/Windows/System32/wbem/WMIC.exe")
    if wmic.exists():
        cmd = [str(wmic), "process", "get", "ProcessId,CommandLine", "/format:csv"]
        source = "WMIC"
    else:
        cmd = ["powershell", "-NoProfile", "-Command",
               "Get-CimInstance Win32_Process | "
               "ForEach-Object { \"$($_.ProcessId),$($_.CommandLine)\" }"]
        source = "PowerShell-CIM"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90,
                           encoding="utf-8", errors="replace")
        out = r.stdout or ""
        rc = r.returncode
    except Exception as e:
        out, rc = f"ERR:{e}", -1
    p.wait(timeout=30)
    # 判定：密钥出现，且所在行同时包含我们的 PID
    lines = [l for l in out.splitlines() if FAKE_KEY in l]
    matched = [l for l in lines if str(p.pid) in l]
    r6 = {
        "test": "cmdline_leak",
        "description": "同主机进程枚举能否读到其他进程 argv 中的密钥",
        "enumeration_source": source,
        "enumeration_rc": rc,
        "pid": p.pid,
        "lines_with_key": len(lines),
        "line_with_our_pid": len(matched),
        "cmdline_leak": len(matched) > 0,
    }
    print(f"    枚举源: {source} (rc={rc})  含密钥行: {len(lines)}  "
          f"其中含本 PID 的行: {len(matched)}")
    print(f"    命令行泄露: {r6['cmdline_leak']}")
    return r6


def main():
    print("=" * 70)
    print("Phase 25: Serverless 绕过 —— 真实 OS 级进程实测")
    print("=" * 70)

    results = []
    results.append(test_process_cold_start(15))
    results.append(test_environ_leak())
    results.append(test_tmpfile_residue())

    # 启动真实 TCP server（同时服务测试 2 和 3）
    srv_file = RESULTS / "_phase25_server.py"
    srv_file.write_text(SERVER_SRC.replace("__PORT__", str(SERVER_PORT)), encoding="utf-8")
    proc = subprocess.Popen(
        [PY, str(srv_file)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    try:
        ready = proc.stdout.readline().strip()
        print(f"\n[server] 真实 TCP server 启动: port={SERVER_PORT} ready={ready!r}")
        results.append(test_request_cold_vs_warm(120))
        results.append(test_cross_connection_state())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        srv_file.unlink(missing_ok=True)
        print("[server] 已关闭")

    results.append(test_cmdline_leak())

    # ---------------- 汇总 ----------------
    by = {r["test"]: r for r in results}
    spawn = by["process_cold_start"]
    crw = by["request_cold_vs_warm"]
    xconn = by["cross_connection_state"]
    env = by["environ_leak"]
    tmp = by["tmpfile_residue"]
    cmd = by["cmdline_leak"]

    n_attack_surface = sum([
        xconn["cross_connection_leak"],
        env["env_injection_works"],
        tmp["residue_leak"],
        cmd["cmdline_leak"],
    ])

    print("\n" + "=" * 70)
    print("Phase 25 结果汇总（真实 OS 级）")
    print("=" * 70)
    print(f"  进程冷启动均值        : {spawn['mean_ms']} ms（p95 {spawn['p95_ms']} ms）")
    print(f"  首请求/稳态 RTT       : {crw['first_request_ms']} / {crw['warm_mean_ms']} ms"
          f"（冷/热比 {crw.get('cold_warm_ratio')}）")
    print(f"  跨连接状态残留        : {xconn['cross_connection_leak']}")
    print(f"  环境变量注入可读      : {env['env_injection_works']}"
          f"（宿主敏感变量 {env['sensitive_env_key_count']} 个）")
    print(f"  临时文件跨退出残留    : {tmp['residue_leak']}")
    print(f"  进程命令行可枚举      : {cmd['cmdline_leak']}")
    print(f"  复现的攻击面          : {n_attack_surface}/4")
    print("=" * 70)

    conclusion_parts = []
    conclusion_parts.append(
        f"Phase 25（真实 OS 级实测）复现了 Serverless 架构的 {n_attack_surface}/4 个核心攻击面："
    )
    if xconn["cross_connection_leak"]:
        conclusion_parts.append(
            "① 容器/进程复用导致跨租户状态残留——同一 server 进程中，前一个连接"
            f"STORE 的 {FAKE_KEY} 被随后一个全新连接原样读回，"
            "证明实例复用期间的进程级状态对后续请求完全可见；"
        )
    else:
        conclusion_parts.append("① 跨连接状态残留在本环境未复现；")
    if env["env_injection_works"]:
        conclusion_parts.append(
            f"② 执行环境元数据泄露——经环境变量注入的密钥被真实子进程完整读回，"
            f"且宿主枚举到 {env['sensitive_env_key_count']} 个敏感环境变量键，"
            "环境变量是 Serverless 密钥分发的默认通道也是最脆弱的通道；"
        )
    if tmp["residue_leak"]:
        conclusion_parts.append(
            "③ 临时目录残留——子进程写入 %TEMP% 后正常退出，文件跨进程存活且"
            "内容可被后续进程完整读回，对应 Serverless /tmp 的同容器复用窗口；"
        )
    if cmd["cmdline_leak"]:
        conclusion_parts.append(
            "④ 进程命令行泄露——出现在 argv 中的密钥被同主机进程枚举直接读到，"
            "冷启动注入路径（参数而非环境）同样不提供隔离；"
        )
    conclusion_parts.append(
        f"⑤ 冷启动时序侧信道——真实进程冷启动均值 {spawn['mean_ms']} ms"
        f"（p95 {spawn['p95_ms']} ms），首请求 RTT {crw['first_request_ms']} ms "
        f"相对稳态 {crw['warm_mean_ms']} ms 的冷/热比为 {crw.get('cold_warm_ratio')}，"
        "调用方可通过请求延迟分布区分冷热实例，进而推断复用策略。"
    )
    conclusion = "".join(conclusion_parts) + (
        "Serverless 执行单元不是可信隔离边界：复用窗口内的状态、环境与元数据"
        "都必须按已污染假设进行审计。"
    )

    out = {
        "phase": "phase25_serverless_bypass",
        "direction": "Serverless 架构绕过",
        "instance": "REAL",
        "environment": {
            "os": os.name,
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "measurement": "OS 级进程/网络实测，无模拟器",
        },
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "results": results,
        "summary": {
            "total_tests": len(results),
            "attack_surface_reproduced": n_attack_surface,
            "attack_surface_total": 4,
            "process_cold_start_mean_ms": spawn["mean_ms"],
            "cold_warm_ratio": crw.get("cold_warm_ratio"),
            "conclusion": conclusion,
        },
    }
    outpath = RESULTS / "phase25_serverless_bypass.json"
    outpath.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[saved] {outpath}")


if __name__ == "__main__":
    main()
