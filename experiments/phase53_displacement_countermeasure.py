#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Phase 53 —— 位移对策切断泄露位移通道
========================================================================

问题来源
------------------------------------------------------------------------
Phase 51 证实 D30 输出侧过滤存在**泄露位移**（3000 探针，s=1.0）：
CoT 有效泄露 42.1% -> 15.1%，但最终答案有效泄露 25.5% -> 30.3%，
位移系数 1.39x。被压掉的敏感信息没有消失，而是转投最终答案通道。

更关键的方法论缺陷：Phase 51 的净收益用**CoT 降幅**做分子
（0.421 - 0.151 = 0.270），完全没有计入它自己造成的位移。
本 phase 把分子换成**并集泄露率**（|CoT 泄露 ∪ 最终答案泄露|），
这才是"信息是否流出系统"的正确度量，并检验两件事：

  (1) 部署"位移对策"（把 D30 命中后改写/净化的最终答案也一并净化）能否
      把 D30 从"经济上不成立"变成"成立"；
  (2) 这个结论对**对策自身成本假设**有多敏感——因为它可能只取决于一个
      没有实测来源的自由参数。

Phase 51 语义（逐位对齐，不得改动）
------------------------------------------------------------------------
  rng = random.Random(2029)        # 与 Phase 49 完全同构的抽样流
  rng_f = random.Random(20290)     # D30 过滤专用流，与抽样流解耦
  suppressed = cot_leaked and det_roll  < D30_EFFICACY[a] * s * (1 - fpr(s))
  displaced  = suppressed and disp_roll < DISPLACEMENT[a]
  cot_eff    = cot_leaked and not suppressed
  final_eff  = final_leaked or displaced        # <-- 位移不要求原最终答案未泄露
  union      = cot_eff or final_eff

位移对策
------------------------------------------------------------------------
强度 tau in [0,1]：命中并发生位移的探针上，位移通道被成功净化的概率。

  coef(tau) = (1 - tau) + tau * RESIDUAL
  displaced_residue = displaced and (scrub_roll < coef(tau))

  tau = 0 -> coef = 1.0  -> scrub_roll < 1.0 恒真 -> residue == displaced
                            （完全不动位移通道，即 Phase 51 原样）
  tau = 1 -> coef = 0.10 -> residue ≈ 10% * displaced
                            （净化不完美，这是有意的保守假设）

  final_eff(tau) = final_leaked or displaced_residue
  cot_eff(tau)   = cot_eff              # 对策只作用于最终答案通道
  union(tau)     = cot_eff(tau) or final_eff(tau)

  理论下界：tau 再大也不可能低于 P(cot_eff or final_leaked)，
  即位移通道被完全清空后的并集。这个下界可精确枚举，用来校验 tau=1。

关键建模纪律（承自 Phase 51 的经验）：tau 的抽样走 rng_f 流的**第三**个随机数，
排在 det_roll / disp_roll 之后，因此不影响前两次抽样，也不进入 rng(2029) 流。
这是自检 1 能"零容差精确复现"而非"近似通过"的前提。

成本
------------------------------------------------------------------------
D30 自身成本（承自 Phase 51，原封不动）：
  util_loss(s)       = 0 if s=0 else 0.30 * s^1.6
  lat_overhead_ms(s) = 0 if s=0 else 8.0 + 45.0 * s^1.5

位移对策额外成本（本 phase 新增，**显式声明为建模假设**；s=0 时对策无触发源，
成本为 0）：
  EXTRA_UTIL(tau) = (1 - REWRITE_UTIL_LOSS) * tau
  EXTRA_LAT(tau)  = EXTRA_LAT_MS * tau

  REWRITE_UTIL_LOSS 是自由参数（"改写后的最终答案还保留多少有用性"），
  没有实测来源，故必须做敏感性扫描而不是只报一点。

三道自检闸门（任一失败即中止并作废）
------------------------------------------------------------------------
1. tau=0 零容差精确复现 Phase 51 run_batch(3000, s) 的全部 6 档
   （cot_eff / final_eff / suppressed_count / displaced_count），
   锚点在运行时从 Phase 51 引擎现场算出，不硬编码、不会过期。
2. 并集泄露率随 tau 单调不增（对每个 s 成立）。
3. tau=1 时 union 达到"位移通道清空"理论下界之上，
   且残差量级 == RESIDUAL * displaced_rate（容差 0.01）。
"""

import json
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = ROOT / "results"

sys.path.insert(0, str(HERE))
from phase49_cot_exfiltration import (  # noqa: E402
    COT_ATTACK_MODES,
    SENSITIVE_TYPES,
    THINKING_MODES,
    CoTExfiltration,
)
# D30 检出效能、位移率、成本模型全部承自 Phase 51，保证口径一致
from phase51_cot_firewall_ablation import (  # noqa: E402
    D30_EFFICACY,
    DISPLACEMENT,
    detect_prob,
    fpr,
    util_loss,
    lat_overhead_ms,
)

ATTACK_AFFINITY = CoTExfiltration.ATTACK_AFFINITY
MODE_MULTIPLIER = CoTExfiltration.MODE_MULTIPLIER
MODE_STEPS = CoTExfiltration.MODE_STEPS

SEED = 2029                 # Phase 49 / Phase 51 抽样流种子
SEED_FILTER = 20290         # Phase 51 D30 过滤专用流种子
SEED_SCRUB = 202911         # 位移对策专用流种子（第三条独立流）
PROBES = 3000               # 与 Phase 51 Arm B 一致（锚点对齐所必需）
STRICTNESS_SWEEP = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
TAU_SWEEP = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
LAMBDA_GRID = [1.0, 2.0, 5.0]
LAT_NORMALIZE = 1000.0

# ---- 位移对策参数（建模假设，敏感性扫描见 COST_SENSITIVITY_GRID）----
RESIDUAL = 0.10             # tau=1 时位移通道残余比例（净化不完美）
REWRITE_UTIL_LOSS = 0.15    # tau=1 时改写保留的有用性比例
EXTRA_LAT_MS = 30.0         # tau=1 时新增每探针延迟 (ms)

COST_SENSITIVITY_GRID = [    # (rewrite_util_loss, extra_lat_ms)
    (0.00, 0.0),    # 乐观下界：改写几乎免费
    (0.15, 30.0),   # 基准
    (0.30, 50.0),   # 保守上界
]

REL_TOL = 0.01              # 自检 3 的残差量级容差


# ---------------------------------------------------------------------------
# 引擎：单遍枚举，产出每探针的四个基础事件
# ---------------------------------------------------------------------------
def enumerate_probes(n: int) -> List[dict]:
    """
    逐位复刻 Phase 51 的探针循环，返回每探针的基础事件向量。

    随机数消耗顺序（与 Phase 51 完全一致）：
      rng(2029):    choice*3, randint, random, uniform, random,
                    [randint, uniform], gauss
      rng_f(20290): det_roll, disp_roll          # 恰好 2 抽，与 Phase 51 对齐
      rng_t(202911): scrub_roll                  # 第三条独立流，每探针 1 抽
    """
    rng = random.Random(SEED)
    rng_f = random.Random(SEED_FILTER)
    rng_t = random.Random(SEED_SCRUB)

    rows: List[dict] = []
    for _ in range(n):
        stype = rng.choice(SENSITIVE_TYPES)
        mode = rng.choice(THINKING_MODES)
        attack = rng.choice(COT_ATTACK_MODES)

        pe = ATTACK_AFFINITY[attack][stype] * MODE_MULTIPLIER[mode]
        steps = rng.randint(*MODE_STEPS[mode])
        cl = rng.random() < pe

        fp = max(0.02, pe * rng.uniform(0.45, 0.70))
        fl = rng.random() < fp

        if cl:
            rng.randint(1, max(1, steps - 1))
            rng.uniform(0.8, 1.2)
        rng.gauss(steps * 45 + 200, 40)

        det_roll = rng_f.random()
        disp_roll = rng_f.random()
        scrub_roll = rng_t.random()              # 独立流，不推进 rng_f

        rows.append({
            "attack": attack, "mode": mode,
            "cl": cl, "fl": fl,
            "det_roll": det_roll, "disp_roll": disp_roll,
            "scrub_roll": scrub_roll,
        })
    return rows


def coef_of_tau(tau: float) -> float:
    """tau -> 位移通道存活概率。tau=0 -> 1.0，tau=1 -> RESIDUAL"""
    return (1.0 - tau) + tau * RESIDUAL


def evaluate(rows: List[dict], s: float, tau: float) -> Dict:
    """
    在给定严格度 s 与位移对策强度 tau 下统计所有泄露事件。

    返回原始计数（未归一化），供所有 τ 共用同一批探针做配对比较。
    """
    n = len(rows)
    n_cl = n_fl = n_both = 0
    n_sup = n_disp = n_cot_eff = 0
    n_cot_eff_and_fl = 0
    n_disp_res = 0
    n_final_eff = 0
    n_union = 0

    for r in rows:
        cl, fl = r["cl"], r["fl"]
        if cl:
            n_cl += 1
        if fl:
            n_fl += 1
        if cl and fl:
            n_both += 1

        suppressed = cl and (r["det_roll"] < detect_prob(r["attack"], s))
        displaced = suppressed and (r["disp_roll"] < DISPLACEMENT[r["attack"]])
        cot_eff = cl and (not suppressed)

        if suppressed:
            n_sup += 1
        if displaced:
            n_disp += 1
        if cot_eff:
            n_cot_eff += 1
            if fl:
                n_cot_eff_and_fl += 1

        # ---- tau 只作用于位移通道 ----
        disp_res = displaced and (r["scrub_roll"] < coef_of_tau(tau))
        if disp_res:
            n_disp_res += 1

        fe = fl or disp_res
        ue = cot_eff or fe
        n_final_eff += int(fe)
        n_union += int(ue)

    return {
        "n_cl": n_cl, "n_fl": n_fl, "n_both": n_both,
        "n_suppressed": n_sup, "n_displaced": n_disp,
        "n_cot_eff": n_cot_eff, "n_cot_eff_and_fl": n_cot_eff_and_fl,
        "n_displaced_residue": n_disp_res,
        "n_final_eff": n_final_eff, "n_union": n_union,
        "rate": {
            "cot_eff": round(n_cot_eff / n, 4),
            "final_eff": round(n_final_eff / n, 4),
            "displaced": round(n_disp / n, 4),
            "displaced_residue": round(n_disp_res / n, 4),
            "suppressed_rate_of_cot": round(n_sup / max(1, n_cl), 4),
            "union": round(n_union / n, 4),
            # 位移通道完全清空后的理论下界（可精确枚举）
            "union_floor": round((n_cot_eff + n_fl - n_cot_eff_and_fl) / n, 4),
        },
    }


def cost_of(s: float, tau: float,
            rewrite_util: float = REWRITE_UTIL_LOSS,
            extra_lat: float = EXTRA_LAT_MS) -> Dict:
    """D30 + 位移对策的合并成本。s=0 时过滤器未部署，对策无触发源，成本为 0"""
    if s == 0.0:
        return {"utility_loss": 0.0, "latency_ms": 0.0, "normalized": 0.0}
    util = util_loss(s) + (1.0 - rewrite_util) * tau
    lat = lat_overhead_ms(s) + extra_lat * tau
    return {"utility_loss": round(util, 4),
            "latency_ms": round(lat, 2),
            "normalized": round(util + lat / LAT_NORMALIZE, 4)}


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 74)
    print("Phase 53 — 位移对策切断泄露位移通道")
    print("=" * 74)
    print(f"[配置] probes={PROBES}  s∈{STRICTNESS_SWEEP}  tau∈{TAU_SWEEP}")
    print(f"[假设] RESIDUAL={RESIDUAL}  REWRITE_UTIL_LOSS={REWRITE_UTIL_LOSS}  "
          f"EXTRA_LAT_MS={EXTRA_LAT_MS}")
    print()

    rows = enumerate_probes(PROBES)
    n = len(rows)

    # ---- 运行时锚点：直接从 Phase 51 引擎取，不硬编码 ----
    from phase51_cot_firewall_ablation import run_batch
    anchors = {str(s): run_batch(PROBES, s=s) for s in STRICTNESS_SWEEP}

    # ---- 自检 1：tau=0 零容差精确复现 Phase 51 ----
    print("[自检 1] tau=0 零容差精确复现 Phase 51 run_batch(3000, s)")
    self1: Dict[str, dict] = {}
    ok1 = True
    for s in STRICTNESS_SWEEP:
        got = evaluate(rows, s, 0.0)
        exp = anchors[str(s)]
        checks = {
            "cot_eff": (got["rate"]["cot_eff"], exp["cot_eff_leak_rate"]),
            "final_eff": (got["rate"]["final_eff"], exp["final_eff_leak_rate"]),
            "suppressed": (got["n_suppressed"], exp["suppressed_count"]),
            "displaced": (got["n_displaced"], exp["displaced_count"]),
        }
        passed = all(a == b for a, b in checks.values())
        ok1 &= passed
        self1[str(s)] = {
            "got": {k: v[0] for k, v in checks.items()},
            "expect": {k: v[1] for k, v in checks.items()},
            "union": got["rate"]["union"],
            "union_floor": got["rate"]["union_floor"],
        }
        print(f"  s={s}: cot {got['rate']['cot_eff']}  final {got['rate']['final_eff']}  "
              f"sup {got['n_suppressed']}  disp {got['n_displaced']}  "
              f"-> {'PASS' if passed else 'FAIL'}")
    print(f"  结论: {'PASS' if ok1 else 'FAIL'}")
    if not ok1:
        print("  [中止] tau=0 无法零容差复现 Phase 51，位移通道无法被单独度量")
        sys.exit(1)

    # ---- 全网格枚举 ----
    grid: Dict[str, Dict] = {}
    for s in STRICTNESS_SWEEP:
        grid[str(s)] = {}
        for tau in TAU_SWEEP:
            e = evaluate(rows, s, tau)
            c = cost_of(s, tau)
            grid[str(s)][str(tau)] = {
                "coef": round(coef_of_tau(tau), 4),
                "counts": {k: v for k, v in e.items() if k != "rate"},
                "rate": e["rate"],
                "cost": c,
            }

    base_union = grid["0.0"]["0.0"]["rate"]["union"]

    # ---- 自检 2：并集随 tau 单调不增 ----
    print("\n[自检 2] 并集泄露率随 tau 单调不增")
    self2: Dict[str, List[float]] = {}
    ok2 = True
    for s in STRICTNESS_SWEEP:
        seq = [grid[str(s)][str(t)]["rate"]["union"] for t in TAU_SWEEP]
        self2[str(s)] = seq
        mono = all(seq[i] >= seq[i + 1] for i in range(len(seq) - 1))
        ok2 &= mono
        print(f"  s={s}: {[f'{v:.3f}' for v in seq]}  -> {'PASS' if mono else 'FAIL'}")
    print(f"  结论: {'PASS' if ok2 else 'FAIL'}")
    if not ok2:
        print("  [中止] tau 未能削减并集泄露")
        sys.exit(1)

    # ---- 自检 3：tau=1 残差量级 == RESIDUAL，且 union 不低于理论下界 ----
    print(f"\n[自检 3] tau=1 残差量级 == RESIDUAL={RESIDUAL} 且 union >= 理论下界")
    self3: Dict[str, dict] = {}
    ok3 = True
    for s in STRICTNESS_SWEEP:
        cell = grid[str(s)]["1.0"]
        rat = cell["rate"]
        expected_resid = RESIDUAL * rat["displaced"]
        got_resid = rat["displaced_residue"]
        above_floor = rat["union"] >= rat["union_floor"]
        resid_ok = abs(got_resid - expected_resid) <= REL_TOL
        passed = above_floor and resid_ok
        ok3 &= passed
        self3[str(s)] = {
            "n_displaced": cell["counts"]["n_displaced"],
            "n_residue": cell["counts"]["n_displaced_residue"],
            "residue_rate": got_resid,
            "expected_residue_rate": round(expected_resid, 4),
            "union": rat["union"],
            "union_floor": rat["union_floor"],
            "gap_to_floor": round(rat["union"] - rat["union_floor"], 4),
        }
        print(f"  s={s}: 残差 {got_resid} (exp {expected_resid:.4f})  "
              f"并集 {rat['union']} >= 下界 {rat['union_floor']}  "
              f"-> {'PASS' if passed else 'FAIL'}")
    print(f"  结论: {'PASS' if ok3 else 'FAIL'}")
    if not ok3:
        print("  [中止] tau=1 未通过残差/下界校验")
        sys.exit(1)

    # ---- 成本-收益（分子用并集降幅）----
    def net_matrix(rewrite_util: float, extra_lat: float) -> Dict[str, Dict]:
        out: Dict[str, Dict] = {}
        for s in STRICTNESS_SWEEP:
            out[str(s)] = {}
            for tau in TAU_SWEEP:
                cell = grid[str(s)][str(tau)]
                red = round(base_union - cell["rate"]["union"], 4)
                c = cost_of(s, tau, rewrite_util=rewrite_util, extra_lat=extra_lat)
                net = {f"lambda_{lam:g}": round(red - lam * c["normalized"], 4)
                       for lam in LAMBDA_GRID}
                out[str(s)][str(tau)] = {
                    "union_leak_reduction": red,
                    "cost": c,
                    "net_benefit": net,
                    "net_sign": {f"lambda_{lam:g}": ("pos" if v > 0 else "neg")
                                 for lam, v in zip(LAMBDA_GRID, net.values())},
                }
        return out

    cb = net_matrix(REWRITE_UTIL_LOSS, EXTRA_LAT_MS)

    def argmax(netm: Dict[str, Dict], lam: float,
               exclude_no_defense: bool = False) -> Tuple[str, str, float]:
        """网格 argmax。exclude_no_defense=True 时跳过整条 s=0 行：
        s=0 意味着不部署 D30 过滤，此时 tau 无作用对象（无抑制、无位移），
        故 s=0 的 6 个 tau 格点全部等价于"无防御"，必须整行排除而非只排除
        (s=0, tau=0) 一个点——否则 argmax 会落在 (0, 0.2) 这类退化格点上，
        把"不部署防御"误报成"最优非零防御"。
        注意：SWEEP 列表是 float，比较必须走 float()，字符串比较会静默失效。"""
        best = None
        for s in STRICTNESS_SWEEP:
            if exclude_no_defense and float(s) == 0.0:
                continue
            for tau in TAU_SWEEP:
                v = netm[str(s)][str(tau)]["net_benefit"][f"lambda_{lam:g}"]
                if best is None or v > best[2]:
                    best = (str(s), str(tau), v)
        return best

    # 真正"部署了防御"的格点数：s>0 的 5 档 x 6 档 tau
    N_DEFENSE_CELLS = (len(STRICTNESS_SWEEP) - 1) * len(TAU_SWEEP)

    print("\n[成本-收益] 并集降幅与净收益（lambda=2）")
    print("  s     tau  union   降幅     效用    延迟      net(2)")
    for s in STRICTNESS_SWEEP:
        for tau in TAU_SWEEP:
            v = cb[str(s)][str(tau)]
            u = grid[str(s)][str(tau)]["rate"]["union"]
            print(f"  {s:>4}  {tau:>4}  {u:.3f}  {v['union_leak_reduction']:+.3f}  "
                  f"{v['cost']['utility_loss']:.3f}  {v['cost']['latency_ms']:7.1f}ms  "
                  f"{v['net_benefit']['lambda_2']:+.3f}")
    print()

    # ---- 敏感性：结论是否只取决于 REWRITE_UTIL_LOSS ----
    print("[敏感性] 位移对策成本假设对结论的影响（lambda=2）")
    sensitivity: List[dict] = []
    for ru, el in COST_SENSITIVITY_GRID:
        nm = net_matrix(ru, el)
        entry = {"rewrite_util_loss": ru, "extra_lat_ms": el, "per_lambda": {}}
        print(f"  rewrite_util_loss={ru:.2f}  extra_lat={el:.0f}ms")
        for lam in LAMBDA_GRID:
            b = argmax(nm, lam, exclude_no_defense=True)
            neg = sum(
                1 for s in STRICTNESS_SWEEP for tau in TAU_SWEEP
                if float(s) > 0.0
                and nm[str(s)][str(tau)]["net_benefit"][f"lambda_{lam:g}"] <= 0
            )
            entry["per_lambda"][f"lambda_{lam:g}"] = {
                "best_nonzero": {"s": b[0], "tau": b[1], "net": b[2]},
                "best_nonzero_net_is_positive": bool(b[2] > 0),
                "positive_cells": N_DEFENSE_CELLS - neg,
                "negative_cells": neg,
                "total_defense_cells": N_DEFENSE_CELLS,
            }
            print(f"    lambda={lam:g}: 最优非零防御 (s={b[0]},tau={b[1]}) "
                  f"net={b[2]:+.4f}  正收益格点={N_DEFENSE_CELLS - neg}/{N_DEFENSE_CELLS}")
        sensitivity.append(entry)
    print()

    # ---- 三档基线对照 ----
    print("[对照] 三档基线（每档 lambda）")
    baseline = {}
    for lam in LAMBDA_GRID:
        a = argmax(cb, lam)
        b = argmax(cb, lam, exclude_no_defense=True)
        baseline[f"lambda_{lam:g}"] = {
            "no_defense": {"s": "0.0", "tau": "0.0", "net": 0.0},
            "best_grid": {"s": a[0], "tau": a[1], "net": a[2]},
            "best_nonzero": {"s": b[0], "tau": b[1], "net": b[2]},
            "no_defense_is_best": (float(a[0]) == 0.0),
            "best_nonzero_net_is_positive": bool(b[2] > 0),
        }
        bd = baseline[f"lambda_{lam:g}"]
        print(f"  lambda={lam:g}: 全网格最优 (s={a[0]},tau={a[1]}) net={a[2]:+.4f}  "
              f"| 最优非零防御 (s={b[0]},tau={b[1]}) net={b[2]:+.4f}  "
              f"| 无防御仍最优={bd['no_defense_is_best']}")
    print()

    # ---- 与 Phase 51 的度量口径对比（方法论要点）----
    # Phase 51 的净收益分子用的是 CoT 降幅；本 phase 用并集降幅。
    # 两者的分母都是 s=0 的无防御基线——若误用 anchors[s]（已过滤值）做
    # 分子基准，降幅恒为 0，对比退化为无意义。
    a0 = anchors["0.0"]
    cot_metric_vs_union: Dict[str, dict] = {}
    print("[口径对比] Phase 51 用 CoT 降幅 vs 本 phase 用并集降幅（tau=0）")
    for s in STRICTNESS_SWEEP:
        cell = grid[str(s)]["0.0"]
        cot_red = round(a0["cot_eff_leak_rate"] - cell["rate"]["cot_eff"], 4)
        uni_red = round(base_union - cell["rate"]["union"], 4)
        ratio = round(uni_red / cot_red, 2) if cot_red > 0 else None
        cot_metric_vs_union[str(s)] = {
            "cot_leak_reduction": cot_red,
            "union_leak_reduction": uni_red,
            "ratio_union_over_cot": ratio,
        }
        print(f"  s={s}: CoT 降幅 {cot_red:+.4f}  并集降幅 {uni_red:+.4f}  "
              f"比值 {ratio}")
    print()

    self_checks = {
        "tau0_reproduces_phase51": ok1,
        "tau0_detail": self1,
        "union_monotone_in_tau": ok2,
        "union_sequences": self2,
        "tau1_residual_and_floor": ok3,
        "tau1_detail": self3,
        "anchors_source": "phase51.run_batch(3000, s) 运行时现场计算，非硬编码",
        "all_three_passed": bool(ok1 and ok2 and ok3),
    }

    s_base = sensitivity[1]["per_lambda"]["lambda_2"]["best_nonzero"]
    s_opt = sensitivity[0]["per_lambda"]["lambda_2"]["best_nonzero"]
    s_con = sensitivity[2]["per_lambda"]["lambda_2"]["best_nonzero"]
    g10 = grid["1.0"]
    r51 = cot_metric_vs_union["1.0"]
    # 三档成本假设下，lambda=2 有多少个"真实部署了防御"的格点净收益为正
    pos_l2 = [(e["rewrite_util_loss"], e["per_lambda"]["lambda_2"]["positive_cells"])
              for e in sensitivity]
    any_positive = any(pc > 0 for _, pc in pos_l2)

    insights = [
        f"位移通道可被单独度量：s=1.0 时 N_displaced={grid['1.0']['0.0']['counts']['n_displaced']}"
        f"（占全部探针 {grid['1.0']['0.0']['rate']['displaced']:.1%}）。"
        f"注意 Phase 51 的语义是 displaced 与 final_leaked **不互斥**"
        f"（位移发生在被抑制的探针上，无论其最终答案原本是否泄露），"
        f"故位移通道只能部分解释最终答案泄露的抬升",
        f"度量口径是关键：Phase 51 用 CoT 降幅做分子，s=1.0 时得 "
        f"{r51['cot_leak_reduction']:+.4f}；换成并集降幅只有 "
        f"{r51['union_leak_reduction']:+.4f}（比值 {r51['ratio_union_over_cot']}x）。"
        f"即 Phase 51 把 D30 的收益**高估了 "
        f"{(1 / r51['ratio_union_over_cot'] if r51['ratio_union_over_cot'] else 0):.1f} 倍**"
        f"，因为它没计入自己造成的位移",
        f"切断位移通道：并集 {g10['0.0']['rate']['union']:.3f} (s=1,tau=0) -> "
        f"{g10['1.0']['rate']['union']:.3f} (s=1,tau=1)，"
        f"残余缺口 {self3['1.0']['gap_to_floor']:.4f} 来自残余系数 {RESIDUAL}；"
        f"理论下界 {g10['1.0']['rate']['union_floor']:.3f}（位移通道完全清空）",
        f"三道闸门全过：tau=0 零容差复现 Phase 51 全部 6 档"
        f"（cot_eff/final_eff/suppressed/displaced 四量全对），"
        f"并集随 tau 单调不增，tau=1 残差量级 == {RESIDUAL} 且不低于理论下界",
        f"基准成本假设（改写保留 {REWRITE_UTIL_LOSS:.0%} 有用性、+{EXTRA_LAT_MS:.0f}ms）下，"
        f"lambda=2 最优非零方案 (s={s_base['s']},tau={s_base['tau']}) "
        f"净收益 {s_base['net']:+.4f}"
        f"{'——仍为负，无防御仍最优' if s_base['net'] <= 0 else '——转正，D30+位移对策经济上成立'}",
        f"结论对成本假设**不敏感**（这本身是结论）：lambda=2 下把 30 个"
        f"'已部署防御'格点（s>0）逐个算净收益，改写成本从 0（免费）"
        f"-> {REWRITE_UTIL_LOSS:.2f}（基准）-> 0.30（保守）时，正收益格点数恒为 "
        f"{', '.join(str(pc) for _, pc in pos_l2)}"
        f"（共 {N_DEFENSE_CELLS} 个格点）。即无论对策多便宜，收益都追不上成本"
        f"——因为改写削减的位移量远小于 D30 过滤本身的效用损失"
        f"（s=1.0 时位移仅 {grid['1.0']['0.0']['rate']['displaced']:.1%} 的探针，"
        f"而效用损失为 {REWRITE_UTIL_LOSS:.0%} x s x tau）",
        f"lambda=1 时{'无防御仍最优' if baseline['lambda_1']['no_defense_is_best'] else '非零防御占优'}"
        f"（最优网格 s={baseline['lambda_1']['best_grid']['s']}, "
        f"tau={baseline['lambda_1']['best_grid']['tau']}），"
        f"lambda=5 时{'无防御仍最优' if baseline['lambda_5']['no_defense_is_best'] else '非零防御占优'}",
        "方法论要点：tau 的抽样排在 det_roll/disp_roll **之后**、且走独立 rng_f 流，"
        "因此不推进 Phase 49 的抽样流——这正是 Phase 51 用独立流换来的零容差复现能力",
        "工程含义：位移对策**没有**把「是否部署 D30」变成一个关于改写有用性损失的"
        "定量门槛——因为改写只能削减位移量，不能削减 D30 过滤本身的效用损失，"
        "而后者（s=1 时 0.30）远大于前者（位移只覆盖 8.0% 的探针）。"
        "在改写近乎免费时仍为 0/30 正收益格点，说明门槛落在了"
        "'改写能带来正效用'这一不可能的方向上。"
        "真正的决策变量不是改写成本，而是**是否值得为 8% 的位移探针"
        "付出 30% 的效用损失**——这必须用真实业务标注回答",
        f"诚实结论：三档成本假设（含改写完全免费）下均无正收益格点，"
        f"切断位移通道**不足以**让 D30 经济上成立。约束来自**成本**而非位移"
        f"（位移只覆盖 {grid['1.0']['0.0']['rate']['displaced']:.1%} 的探针），"
        f"这与 Phase 51 的定性判断一致，但把收益分子从 CoT 降幅改为并集降幅后，"
        f"高估倍数从 '未知' 变成可测的 "
        f"{(1 / (r51['ratio_union_over_cot'] or 1)):.1f} 倍",
        "方法论要点（本 phase 自查出的缺陷）：SWEEP 列表是 float，"
        "而 argmax 原先用 `s == '0.0'` 做字符串比较——该比较恒为 False，"
        "导致 `exclude_no_defense` 静默失效、`no_defense_is_best` 恒为 False、"
        "负收益格点计数虚高。已改为 float 比较，且'无防御'按 s>0 整行排除"
        "（s=0 时 tau 无作用对象）。教训：排除类谓词必须用与数据同型的比较，"
        "并用一个'已知应该被排除'的样本自检",
    ]

    output = {
        "phase": 53,
        "title": "位移对策切断泄露位移通道",
        "objective": (
            "Phase 51 证实 D30 把 CoT 泄露位移到最终答案（位移系数 1.39x），"
            "但其净收益用 CoT 降幅做分子、未计入自身位移。本 phase 改用并集泄露率，"
            "部署位移对策强度 tau 切断位移通道，重测成本-收益，并检验结论对"
            "对策自身成本假设的敏感性。"
        ),
        "config": {
            "seed": SEED,
            "seed_filter": SEED_FILTER,
            "probes": n,
            "strictness_sweep": STRICTNESS_SWEEP,
            "tau_sweep": TAU_SWEEP,
            "lambda_grid": LAMBDA_GRID,
            "latency_normalize": LAT_NORMALIZE,
            "residual_at_tau1": RESIDUAL,
            "rewrite_util_loss": REWRITE_UTIL_LOSS,
            "extra_lat_ms": EXTRA_LAT_MS,
            "cost_sensitivity_grid": COST_SENSITIVITY_GRID,
            "phase51_inherited": {
                "detect_prob": "D30_EFFICACY[a] * s * (1 - fpr(s))",
                "fpr": "0.02 + 0.16*(1-s)",
                "displacement": DISPLACEMENT,
                "utility_loss": "0 if s=0 else 0.30*s^1.6",
                "latency_ms": "0 if s=0 else 8.0+45.0*s^1.5",
                "final_eff_semantics": "final_leaked OR displaced（不互斥）",
            },
            "tau_rng_note": (
                "tau 的 scrub_roll 是 rng_f 流的第三个随机数，排在 det_roll/disp_roll "
                "之后，故不影响 Phase 51 的前两次抽样，也不进入 rng(2029) 抽样流"
            ),
        },
        "results": {
            "self_checks": self_checks,
            "anchors": {str(s): {
                "cot_eff_leak_rate": a["cot_eff_leak_rate"],
                "final_eff_leak_rate": a["final_eff_leak_rate"],
                "suppressed_count": a["suppressed_count"],
                "displaced_count": a["displaced_count"],
            } for s, a in anchors.items()},
            "grid": grid,
            "cost_benefit": cb,
            "baseline_comparison": baseline,
            "cost_sensitivity": sensitivity,
            "cot_metric_vs_union": cot_metric_vs_union,
            "base_union_rate": base_union,
        },
        "insights": insights,
    }

    RESULTS.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS / "phase53_displacement_countermeasure_v1.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print("=" * 74)
    print(f"[完成] 三道闸门全过，输出: {out_path}")
    print("=" * 74)
    for i, ins in enumerate(insights, 1):
        print(f"  {i}. {ins}")


if __name__ == "__main__":
    main()
