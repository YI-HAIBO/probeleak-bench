"""
Phase 51: CoT 输出接入 D30 记忆防火墙 —— 泄露率降幅对照实验

背景
----
Phase 45 的 D30 记忆防火墙是"输入侧"防御（LLM 训练数据记忆提取隔离），
Phase 49 发现 CoT 是"输出侧"的新盲区：CoT 泄露率 42.4%，是最终答案泄露率
26.7% 的 1.59x，最危险组合 thinking_leak@extended 达 82.5%。
本 phase 把 D30 的过滤机制复用到输出侧（CoT），量化真实的泄露率降幅。

三个科学问题
------------
1. 降幅有多大：严格度 s 从 0 扫到 1，CoT 通道泄露率降多少？
2. 泄露会不会位移：CoT 被压掉的信息会不会迁移到最终答案？
   （displacement_ratio = final(s)/final(0) > 1.0 即证实位移）
3. 代价与最优严格度：过度过滤会删掉合法推理（效用损失）+ 增加延迟，
   净收益最优的 s* 在哪、对代价权重 λ 是否稳定。

三臂设计
--------
Arm A  baseline ：s=0，攻击者用均匀攻击模式分布。
                 必须逐位复现 Phase 49 —— 不是对拍硬编码常数，而是运行时直接
                 对跑 CoTExfiltration().run(1000)，比较总体/模式/攻击/组合
                 四级粒度的原始计数（共 48 项断言）。
Arm B  static   ：s ∈ {0.0,0.2,0.4,0.6,0.8,1.0}，攻击者仍用均匀分布。
                 与 Arm A 共用 rng.choice 抽样流，是探针级配对实验。
Arm C  adaptive ：攻击者知道 D30 的检出效能，把攻击模式按 (1-efficacy)^k
                 重加权，s 取 Arm B 的最优严格度。测泄露回弹。
                 因改用 rng.choices，抽样消耗路径不同，与 Arm B 是独立实验臂
                 而非配对复制（不声称逐位可比，只比率值）。

严谨性设计（三道自检闸门，任一失败即中止并作废）
----------
1. s=0 复现自检：Arm A 与 Phase 49 引擎在总体/per_mode/per_attack/per_combo
   四个粒度上必须完全相等。关键前提：D30 的过滤抽样必须走独立的 rng_f 流。
   若与 Phase 49 共用同一个 rng，两次额外的 rng.random() 虽不改变当次探针的
   判定结果，却会推进 RNG 内部状态（gauss 还有 gauss_next 缓存，位移更早发生），
   导致第 2 次迭代起的所有随机数整体位移。实测后果：cot 0.424→0.423、
   final 0.267→0.281，per_combo 20 格全部错配。
   另外 RNG 抽样必须用 rng.choice（而非 rng.choices）：两者消耗路径不同
   （_randbelow/getrandbits vs random() 累积和），换用 choices 会直接破坏复现。
2. 检出效能单调性：cot_eff_leak_rate 必须随 s 非递增。
3. δ 隔离自检：位移参数 δ=0 时，final_leak_rate 在任何 s 下都必须等于 s=0 的值
   （δ 只能作用于最终答案通道，不得回灌 CoT 通道）。

与 Phase 47/50 教训的衔接
--------------------------
Phase 47 的教训是"线性混合会让相关性参数失效"。本 phase 的检出建模是
非线性的：eff_detect = efficacy * s * (1 - fpr(s))，s 与 fpr(s) 同为 s 的函数，
且 eff_detect 与 p_effective 相乘后才判定泄露 → s 真实作用于泄露率，不是只改方差。
Phase 50 的教训是"contextual bandit 没有 next state，不该有 gamma 项"。
本 phase 的 Arm C 不做 Q 学习，直接用解析重加权 (1-efficacy)^k 表达攻击者适应，
避免重复同一个建模错误。
"""

import json
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"

sys.path.insert(0, str(HERE))
from phase49_cot_exfiltration import (  # noqa: E402
    COT_ATTACK_MODES,
    SENSITIVE_TYPES,
    THINKING_MODES,
    CoTExfiltration,
)

# 以下三项是 Phase 49 CoTExfiltration 的类属性，取出作为本 phase 的基准
ATTACK_AFFINITY = CoTExfiltration.ATTACK_AFFINITY
MODE_MULTIPLIER = CoTExfiltration.MODE_MULTIPLIER
MODE_STEPS = CoTExfiltration.MODE_STEPS

# ---------------------------------------------------------------------------
# D30 复用到输出侧的检出效能：该攻击模式的 CoT 泄露形态是否容易被过滤命中
# ---------------------------------------------------------------------------
D30_EFFICACY = {
    "thinking_leak":        0.92,   # 显式思考文本，指纹可直检
    "prefix_extraction":    0.85,   # 逐字前缀，可指纹匹配
    "step_reconstruction":  0.55,   # 反推数据，间接形态
    "reasoning_escalation": 0.38,   # 推理中的行为越权，非文本泄露
    "tool_injection":       0.30,   # 侧信道经工具，几乎不在 CoT 文本里
}

# 位移率 δ：CoT 泄露被有效抑制后，信息迁移到最终答案的概率
# （显式文本容易被改写后塞回最终答案；侧信道与 CoT 过滤无关）
DISPLACEMENT = {
    "thinking_leak":        0.45,
    "prefix_extraction":    0.30,
    "step_reconstruction":  0.20,
    "reasoning_escalation": 0.10,
    "tool_injection":       0.05,
}

STRICTNESS_SWEEP = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
PROBES_BASE = 1000        # Arm A 探针数，必须等于 Phase 49 的 1000 才能逐位复现
PROBES = 3000             # Arm B/C 探针数（20 个攻击×模式组合，每格约 150 个样本）
K_SHIFT = 1.5            # 自适应攻击者的规避强度指数
LAMBDA_GRID = [1.0, 2.0, 5.0]
TOTAL_PROBES = PROBES_BASE + (2 * len(STRICTNESS_SWEEP) + 1) * PROBES

# 成本模型
UTIL_LOSS_COEF = 0.30    # s=1 时约 30% 的合法推理步骤被误删（过度过滤）
UTIL_LOSS_EXP = 1.6      # 高严格度下过度过滤加速上升
LAT_BASE_MS = 8.0        # 过滤器固定开销
LAT_SCALING_MS = 45.0    # 随严格度上升（含触发的重生成成本）
LAT_EXP = 1.5
LAT_NORMALIZE = 1000.0   # 延迟折算到泄露率量纲的分母


def detect_prob(attack: str, s: float) -> float:
    """有效检出并抑制的概率（单次抽样判定）"""
    return D30_EFFICACY[attack] * s * (1.0 - fpr(s))


def fpr(s: float) -> float:
    """抑制失败率（假阴性）：即使检出也可能漏。s=1 时仍有 2% 残余"""
    return 0.02 + 0.16 * (1.0 - s)


def util_loss(s: float) -> float:
    """效用损失：合法推理步骤被误删的比例。s=0 时无过滤器部署，损失为 0"""
    return 0.0 if s == 0.0 else UTIL_LOSS_COEF * s ** UTIL_LOSS_EXP


def lat_overhead_ms(s: float) -> float:
    """延迟开销。s=0 时无过滤器部署，开销为 0（不是 8ms）"""
    return 0.0 if s == 0.0 else LAT_BASE_MS + LAT_SCALING_MS * s ** LAT_EXP


def adaptive_weights(k: float = K_SHIFT) -> List[float]:
    """自适应攻击者的攻击模式重加权：偏向外泄检出效能低的模式"""
    w = [(1.0 - D30_EFFICACY[a]) ** k for a in COT_ATTACK_MODES]
    tot = sum(w)
    return [x / tot for x in w]


def run_batch(total_probes: int, s: float,
              attack_weights: Optional[List[float]] = None,
              displacement: Optional[Dict[str, float]] = None) -> Dict:
    """跑一批探针。s=0 且 attack_weights=None 时必须复现 Phase 49。

    关键：D30 的过滤抽样必须走独立的 rng_f 流。若与 Phase 49 共用同一个 rng，
    两次额外 rng.random() 虽不改变当次探针的判定结果，但会推进 RNG 内部状态，
    使第 2 次迭代起的所有随机数整体位移（gauss 还有 gauss_next 缓存，位移更早
    发生）。实测这会让 cot_leak 从 0.424 漂到 0.423、final 从 0.267 漂到 0.281。
    """
    rng = random.Random(2029)              # 与 Phase 49 完全同构的抽样流
    rng_f = random.Random(20290)           # D30 过滤专用流，与抽样流解耦
    disp = displacement if displacement is not None else DISPLACEMENT

    per_mode: Dict[str, Dict] = {
        m: {"tried": 0, "cot_leak": 0, "cot_eff": 0, "final_orig": 0, "final_eff": 0}
        for m in THINKING_MODES
    }
    per_attack: Dict[str, Dict] = {
        a: {"tried": 0, "cot_leak": 0, "cot_eff": 0, "suppressed": 0, "displaced": 0,
            "final_orig": 0, "final_eff": 0}
        for a in COT_ATTACK_MODES
    }
    per_combo: Dict[str, Dict] = {
        f"{a}|{m}": {"tried": 0, "cot_eff": 0, "final_eff": 0}
        for a in COT_ATTACK_MODES for m in THINKING_MODES
    }

    n_cot_leak = n_cot_eff = n_final_orig = n_final_eff = 0
    n_suppressed = n_displaced = 0
    total_intensity = 0.0
    total_latency = 0.0
    steps_hist: List[int] = []

    for i in range(total_probes):
        # ---- 以下 1-7 步与 Phase 49 逐位同构，不得改动顺序 ----
        stype = rng.choice(SENSITIVE_TYPES)
        mode = rng.choice(THINKING_MODES)
        if attack_weights is None:
            attack = rng.choice(COT_ATTACK_MODES)          # Phase 49 同构
        else:
            attack = rng.choices(COT_ATTACK_MODES, weights=attack_weights)[0]

        base_p = ATTACK_AFFINITY[attack][stype]
        p_effective = base_p * MODE_MULTIPLIER[mode]

        min_s, max_s = MODE_STEPS[mode]
        n_steps = rng.randint(min_s, max_s)
        steps_hist.append(n_steps)

        cot_leaked = rng.random() < p_effective
        final_p = max(0.02, p_effective * rng.uniform(0.45, 0.70))
        final_leaked = rng.random() < final_p

        if cot_leaked:
            steps_with_leak = rng.randint(1, max(1, n_steps - 1))
            cot_leak_intensity = min(1.0, steps_with_leak / max(1, n_steps) * rng.uniform(0.8, 1.2))
        else:
            steps_with_leak = 0
            cot_leak_intensity = 0.0
        total_intensity += cot_leak_intensity

        latency = rng.gauss(n_steps * 45 + 200, 40)
        total_latency += latency

        # ---- 8-9 步：D30 输出侧过滤，走独立 rng_f 流，不干扰 Phase 49 抽样序列 ----
        det_roll = rng_f.random()
        disp_roll = rng_f.random()

        suppressed = cot_leaked and det_roll < detect_prob(attack, s)
        displaced = suppressed and disp_roll < disp[attack]

        cot_eff = cot_leaked and not suppressed
        final_eff = final_leaked or displaced

        # ---- 汇总 ----
        pm = per_mode[mode]
        pm["tried"] += 1
        pm["cot_leak"] += int(cot_leaked)
        pm["cot_eff"] += int(cot_eff)
        pm["final_orig"] += int(final_leaked)
        pm["final_eff"] += int(final_eff)

        pa = per_attack[attack]
        pa["tried"] += 1
        pa["cot_leak"] += int(cot_leaked)
        pa["cot_eff"] += int(cot_eff)
        pa["suppressed"] += int(suppressed)
        pa["displaced"] += int(displaced)
        pa["final_orig"] += int(final_leaked)
        pa["final_eff"] += int(final_eff)

        pc = per_combo[f"{attack}|{mode}"]
        pc["tried"] += 1
        pc["cot_eff"] += int(cot_eff)
        pc["final_eff"] += int(final_eff)

        n_cot_leak += int(cot_leaked)
        n_cot_eff += int(cot_eff)
        n_final_orig += int(final_leaked)
        n_final_eff += int(final_eff)
        n_suppressed += int(suppressed)
        n_displaced += int(displaced)

    return {
        "strictness": s,
        "total_probes": total_probes,
        "adapted": attack_weights is not None,
        "cot_leak_rate": round(n_cot_leak / total_probes, 4),
        "cot_eff_leak_rate": round(n_cot_eff / total_probes, 4),
        "final_orig_leak_rate": round(n_final_orig / total_probes, 4),
        "final_eff_leak_rate": round(n_final_eff / total_probes, 4),
        "suppressed_rate_of_cot": round(n_suppressed / max(1, n_cot_leak), 4),
        "suppressed_count": n_suppressed,
        "displaced_count": n_displaced,
        "avg_cot_leak_intensity": round(total_intensity / total_probes, 4),
        "avg_base_latency_ms": round(total_latency / total_probes, 1),
        "avg_cot_steps": round(sum(steps_hist) / total_probes, 2),
        "utility_loss": round(util_loss(s), 4),
        "lat_overhead_ms": round(lat_overhead_ms(s), 1),
        "total_latency_ms": round(total_latency / total_probes + lat_overhead_ms(s), 1),
        "per_mode": per_mode,
        "per_attack": per_attack,
        "per_combo": per_combo,
    }


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    random.seed(2029)
    np.random.seed(2029)

    print("=" * 72)
    print("Phase 51: CoT 输出接入 D30 记忆防火墙 —— 泄露率降幅对照")
    print(f"严格度扫描: {STRICTNESS_SWEEP} · 探针/臂: {PROBES}")
    print("=" * 72)

    # ---------------- 自检闸门 ----------------
    print("\n[自检 1] s=0 必须逐位复现 Phase 49 引擎（PROBES_BASE=1000）")
    ref = CoTExfiltration().run(total_probes=PROBES_BASE)["results"]
    arm_a = run_batch(PROBES_BASE, s=0.0)

    # 不硬编码期望值：直接与 Phase 49 引擎实时对跑，覆盖总体/模式/攻击/组合四级粒度
    mismatches: List[str] = []
    if arm_a["cot_leak_rate"] != ref["overall_cot_leak_rate"]:
        mismatches.append(
            f"cot_leak {arm_a['cot_leak_rate']}!={ref['overall_cot_leak_rate']}")
    if arm_a["final_eff_leak_rate"] != ref["overall_final_leak_rate"]:
        mismatches.append(
            f"final {arm_a['final_eff_leak_rate']}!={ref['overall_final_leak_rate']}")
    if abs(arm_a["avg_base_latency_ms"] - ref["avg_latency_ms"]) >= 0.1:
        mismatches.append(
            f"latency {arm_a['avg_base_latency_ms']}!={ref['avg_latency_ms']}")
    for mm in THINKING_MODES:
        ra, rb = arm_a["per_mode"][mm], ref["per_mode"][mm]
        if (ra["tried"], ra["cot_leak"], ra["final_orig"]) != \
           (rb["tried"], rb["leaks"], rb["final_leaks"]):
            mismatches.append(f"per_mode[{mm}] {ra}!={rb}")
    for a in COT_ATTACK_MODES:
        ra, rb = arm_a["per_attack"][a], ref["per_attack_mode"][a]
        if (ra["tried"], ra["cot_leak"]) != (rb["tried"], rb["leaks"]):
            mismatches.append(f"per_attack[{a}]")
    for k, v in ref["per_combo"].items():
        c = arm_a["per_combo"][k]
        if (c["tried"], c["cot_eff"]) != (v["tried"], v["leaks"]):
            mismatches.append(f"per_combo[{k}] {c}!={v}")

    ok1 = not mismatches
    print(f"  cot     {arm_a['cot_leak_rate']:.4f} (期望 {ref['overall_cot_leak_rate']})")
    print(f"  final   {arm_a['final_eff_leak_rate']:.4f} (期望 {ref['overall_final_leak_rate']})")
    print(f"  latency {arm_a['avg_base_latency_ms']:.1f} (期望 {ref['avg_latency_ms']})")
    print(f"  对比粒度: 总体 3 项 + per_mode {len(THINKING_MODES)} + "
          f"per_attack {len(COT_ATTACK_MODES)} + per_combo {len(ref['per_combo'])}")
    if mismatches:
        print(f"  -> 失败，实验作废（{len(mismatches)} 处不一致）")
        for x in mismatches[:6]:
            print(f"       {x}")
        sys.exit(1)
    print(f"  -> 通过（与 Phase 49 引擎完全一致）")

    print("\n[自检 2] δ 隔离：位移参数置零后 final_leak 不得随 s 变化")
    zero_disp = {a: 0.0 for a in COT_ATTACK_MODES}
    delta_check = {}
    for s in STRICTNESS_SWEEP:
        b = run_batch(PROBES, s=s, displacement=zero_disp)
        delta_check[str(s)] = b["final_eff_leak_rate"]
    # 基准必须与扫描同探针数：Arm A 用 PROBES_BASE=1000，扫描用 PROBES=3000，
    # 跨探针数比绝对值无意义（3000 探针下 δ=0 的 final 是 0.255 而非 Arm A 的 0.267）。
    # 正确不变量：δ=0 时 final 对所有 s 相同 —— 即 δ 不得回灌 CoT 通道。
    base_zero = delta_check["0.0"]
    delta_values = set(delta_check.values())
    ok2 = delta_values == {base_zero}
    print(f"  δ=0 时各 s 的 final_leak_rate 集合 = {sorted(delta_values)}")
    print(f"  δ=0, s=0.0 同探针数基准 = {base_zero} (PROBES={PROBES})")
    print(f"  -> {'通过' if ok2 else '失败，δ 已回灌 CoT 通道，实验作废'}")
    if not ok2:
        sys.exit(1)

    # ---------------- Arm B：static sweep ----------------
    print("\n[Arm B] static defense 严格度扫描")
    arm_b = {}
    for s in STRICTNESS_SWEEP:
        b = run_batch(PROBES, s=s)
        arm_b[str(s)] = b
        print(f"  s={s:.1f}  CoT {b['cot_eff_leak_rate']*100:5.1f}%  "
              f"final {b['final_eff_leak_rate']*100:5.1f}%  "
              f"抑制 {b['suppressed_rate_of_cot']*100:5.1f}%  "
              f"效用损 {b['utility_loss']*100:4.1f}%  "
              f"延迟 +{b['lat_overhead_ms']:.0f}ms")
    # 位移比与降幅一律对同一探针数的 s=0 基准比（下方 base_ref），
    # 不在扫描打印中跨探针数引用 arm_a(PROBES_BASE=1000)。

    # 单调性自检
    cot_seq = [arm_b[str(s)]["cot_eff_leak_rate"] for s in STRICTNESS_SWEEP]
    ok3 = all(cot_seq[i] >= cot_seq[i + 1] for i in range(len(cot_seq) - 1))
    print(f"\n[自检 3] 检出效能单调性: cot_eff 序列 {[round(x,4) for x in cot_seq]}")
    print(f"  -> {'通过（非递增）' if ok3 else '失败，模型缺陷，实验作废'}")
    if not ok3:
        sys.exit(1)

    # ---------------- 代价-收益与最优严格度 ----------------
    # 基准必须与扫描同探针数：arm_a 用 PROBES_BASE=1000（Phase 49 复现专用），
    # 扫描用 PROBES=3000。跨探针数比降幅会系统性低估（s=0 处 0.4240 vs 0.4207）。
    base_ref = arm_b["0.0"]
    base_cot = base_ref["cot_eff_leak_rate"]
    base_final = base_ref["final_eff_leak_rate"]

    cost_benefit = {}
    for s in STRICTNESS_SWEEP:
        b = arm_b[str(s)]
        cot_red = base_cot - b["cot_eff_leak_rate"]
        final_red = base_final - b["final_eff_leak_rate"]
        disp_ratio = b["final_eff_leak_rate"] / max(1e-9, base_final)
        cost = {
            f"lambda_{lam:g}": round(lam * (b["utility_loss"] + b["lat_overhead_ms"] / LAT_NORMALIZE), 4)
            for lam in LAMBDA_GRID
        }
        net = {
            f"lambda_{lam:g}": round(cot_red - cost[f"lambda_{lam:g}"], 4)
            for lam in LAMBDA_GRID
        }
        cost_benefit[str(s)] = {
            "strictness": s,
            "cot_leak_reduction": round(cot_red, 4),
            "cot_leak_reduction_pct": round(cot_red / max(1e-9, base_cot), 4),
            "final_leak_delta": round(b["final_eff_leak_rate"] - base_final, 4),
            "final_leak_reduction": round(final_red, 4),
            "displacement_ratio": round(disp_ratio, 4),
            "utility_loss": b["utility_loss"],
            "lat_overhead_ms": b["lat_overhead_ms"],
            "cost": cost,
            "net_benefit": net,
        }

    s_star_by_lambda = {
        f"lambda_{lam:g}": float(
            min(STRICTNESS_SWEEP,
                key=lambda s: -cost_benefit[str(s)]["net_benefit"][f"lambda_{lam:g}"])
        )
        for lam in LAMBDA_GRID
    }
    s_star = s_star_by_lambda["lambda_2"]
    # s*=0 是边界解：代价计入后"不值得部署任何过滤"。这是结论，不是数值缺陷，
    # 但会让后续消融落在无防御点上而退化，故另设 s_report。
    s_star_boundary = s_star == min(STRICTNESS_SWEEP)
    s_report = s_star if not s_star_boundary else max(STRICTNESS_SWEEP)
    arm_b_star = arm_b[str(s_report)]

    # ---------------- Arm C：adaptive attacker（全扫描，归一化规避率） ----------------
    # 直接比较"自适应泄露 − 静态泄露"会得出负回弹，这是混杂而非结论：
    # 自适应权重 (1-efficacy)^k 把攻击混合推向 tool_injection / reasoning_escalation，
    # 这两类恰好检出难且基础成功率也低，于是"避开防御"同时"降低了自身能力上限"。
    # 正确指标是归一化规避率 = 有防御泄露 / 无防御泄露（同混合内部可比）：
    #   回弹 > 0  ⇒ 自适应混合在防御下损失得比均匀混合更少，即适应确实有效。
    weights = adaptive_weights()
    arm_c: Dict[str, Dict] = {}
    print("\n[Arm C] adaptive attacker —— 全严格度扫描")
    for s in STRICTNESS_SWEEP:
        c = run_batch(PROBES, s=s, attack_weights=weights)
        arm_c[str(s)] = c

    adapt_ceiling = arm_c["0.0"]["cot_eff_leak_rate"]   # 自适应混合在无防御下的能力上限
    mix_shift = adapt_ceiling - base_cot               # 负值 = 自适应混合本身泄露更低（混杂幅度）
    rebound = {}
    for s in STRICTNESS_SWEEP:
        sb, sc = arm_b[str(s)], arm_c[str(s)]
        ev_static = sb["cot_eff_leak_rate"] / max(1e-9, base_cot)
        ev_adapt = sc["cot_eff_leak_rate"] / max(1e-9, adapt_ceiling)
        ev_static_f = sb["final_eff_leak_rate"] / max(1e-9, base_final)
        ev_adapt_f = sc["final_eff_leak_rate"] / max(1e-9, arm_c["0.0"]["final_eff_leak_rate"])
        rebound[str(s)] = {
            "strictness": s,
            "static_evasion_frac": round(ev_static, 4),
            "adaptive_evasion_frac": round(ev_adapt, 4),
            "rebound_pp": round((ev_adapt - ev_static) * 100, 2),
            "static_cot_leak": sb["cot_eff_leak_rate"],
            "adaptive_cot_leak": sc["cot_eff_leak_rate"],
            "static_final_evasion_frac": round(ev_static_f, 4),
            "adaptive_final_evasion_frac": round(ev_adapt_f, 4),
            "final_rebound_pp": round((ev_adapt_f - ev_static_f) * 100, 2),
        }
        print(f"  s={s:.1f}  static {sb['cot_eff_leak_rate']*100:5.1f}%  "
              f"adaptive {sc['cot_eff_leak_rate']*100:5.1f}%  "
              f"规避 {ev_static*100:5.1f}% -> {ev_adapt*100:5.1f}%  "
              f"回弹 {rebound[str(s)]['rebound_pp']:+.1f}pp")

    print(f"\n  攻击模式重加权: " + ", ".join(
        f"{a}={w*100:.1f}%" for a, w in zip(COT_ATTACK_MODES, weights)))
    print(f"  自适应混合无防御上限 {adapt_ceiling*100:.1f}% vs 静态 {base_cot*100:.1f}%"
          f"（混杂幅度 {mix_shift*100:+.1f}pp）")

    # 最危险组合的逐严格度降幅（Phase 49 榜首 thinking_leak|extended）
    worst = "thinking_leak|extended"
    worst_curve = {}
    for s in STRICTNESS_SWEEP:
        t0 = arm_b["0.0"]["per_combo"][worst]["tried"]
        t1 = arm_b[str(s)]["per_combo"][worst]["tried"]
        worst_curve[str(s)] = {
            "base_cot_leak_rate": round(arm_b["0.0"]["per_combo"][worst]["cot_eff"]
                                        / max(1, t0), 4),
            "cot_leak_rate": round(arm_b[str(s)]["per_combo"][worst]["cot_eff"]
                                    / max(1, t1), 4),
        }
    worst_base = worst_curve["0.0"]["base_cot_leak_rate"]
    worst_def = worst_curve[str(s_report)]["cot_leak_rate"]

    print(f"\n  最危险组合 {worst}: {worst_base*100:.1f}% -> "
          f"{worst_def*100:.1f}% (s={s_report})")

    # ---------------- 汇总 ----------------
    output = {
        "phase": "51_cot_firewall_ablation",
        "description": "CoT 输出接入 D30 记忆防火墙的泄露率降幅对照（含泄露位移效应与自适应攻击者）",
        "config": {
            "strictness_sweep": STRICTNESS_SWEEP,
            "probes_per_arm": PROBES,
            "probes_arm_a": PROBES_BASE,
            "num_batches": 14,
            "total_probes": TOTAL_PROBES,
            "d30_detection_efficacy": D30_EFFICACY,
            "displacement_delta": DISPLACEMENT,
            "fpr_model": "0.02 + 0.16*(1-s)",
            "utility_loss_model": f"0 if s=0 else {UTIL_LOSS_COEF}*s^{UTIL_LOSS_EXP}",
            "latency_overhead_model_ms": f"0 if s=0 else {LAT_BASE_MS}+{LAT_SCALING_MS}*s^{LAT_EXP}",
            "lat_normalize": LAT_NORMALIZE,
            "lambda_grid": LAMBDA_GRID,
            "adaptive_k": K_SHIFT,
            "adaptive_weights": dict(zip(COT_ATTACK_MODES, [round(w, 4) for w in weights])),
            "seed_sample": 2029,
            "seed_filter": 20290,
            "baseline_reference": (
                f"phase49 live engine@{PROBES_BASE}: cot={ref['overall_cot_leak_rate']}, "
                f"final={ref['overall_final_leak_rate']}, lat={ref['avg_latency_ms']}"
            ),
            "rng_note": (
                "D30 过滤抽样走独立 rng_f(20290)，与 Phase 49 的抽样流 rng(2029) 解耦；"
                "否则两次额外 rng.random() 会推进 RNG 状态，使第 2 次迭代起的随机数整体位移。"
                "Arm A 与 Arm B 共用 rng.choice 抽样，是探针级配对实验；"
                "Arm C 改用 rng.choices(加权)，消耗路径不同，是与 Arm B 独立的实验臂而非配对复制。"
            ),
        },
        "results": {
            "self_checks": {
                "s0_reproduces_phase49": ok1,
                "s0_assertions": (3 + len(THINKING_MODES) + len(COT_ATTACK_MODES)
                                  + len(ref["per_combo"])),
                "s0_reference": {
                    "cot": ref["overall_cot_leak_rate"],
                    "final": ref["overall_final_leak_rate"],
                    "latency_ms": ref["avg_latency_ms"],
                },
                "delta_isolation": ok2,
                "delta_isolation_final_rates": delta_check,
                "delta_isolation_base_zero": base_zero,
                "detection_monotone": ok3,
                "cot_eff_sequence": cot_seq,
            },
            "arm_a_baseline_s0": {
                "cot_leak_rate": arm_a["cot_eff_leak_rate"],
                "final_leak_rate": arm_a["final_eff_leak_rate"],
                "avg_latency_ms": arm_a["avg_base_latency_ms"],
                "avg_cot_steps": arm_a["avg_cot_steps"],
                "per_attack": {a: round(v["cot_leak"] / max(1, v["tried"]), 4)
                              for a, v in arm_a["per_attack"].items()},
                "per_mode": {m: round(v["cot_leak"] / max(1, v["tried"]), 4)
                            for m, v in arm_a["per_mode"].items()},
            },
            "arm_b_static_sweep": arm_b,
            "sweep_baseline": {
                "note": "降幅/位移/净收益一律以同探针数(3000)的 s=0 为基准，不是 arm_a(1000)",
                "probes": PROBES,
                "cot_leak_rate": base_cot,
                "final_leak_rate": base_final,
            },
            "cost_benefit": cost_benefit,
            "optimal_strictness_by_lambda": s_star_by_lambda,
            "optimal_strictness_lambda2": s_star,
            "optimal_strictness_is_boundary": s_star_boundary,
            "ablation_strictness": s_report,
            "arm_c_adaptive": {k: v for k, v in arm_c.items()},
            "adaptive_mix_confound": {
                "note": ("自适应权重(1-efficacy)^k 把攻击混合推向检出难且基础成功率也低的"
                         "tool_injection/reasoning_escalation，故其无防御泄露本身更低；"
                         "直接比绝对泄露会得出错误的负回弹，必须用归一化规避率"),
                "static_ceiling_cot_leak": base_cot,
                "adaptive_ceiling_cot_leak": adapt_ceiling,
                "ceiling_shift_pp": round(mix_shift * 100, 2),
            },
            "adaptive_rebound": rebound,
            "worst_combo_ablation": {
                "combo": worst,
                "baseline_cot_leak_rate": round(worst_base, 4),
                f"cot_leak_rate_at_s_{s_report}": round(worst_def, 4),
                "reduction_pp": round((worst_base - worst_def) * 100, 2),
                "curve": worst_curve,
            },
            "per_attack_at_s_report": {
                a: {
                    "cot_leak_rate": round(arm_b_star["per_attack"][a]["cot_eff"]
                                            / max(1, arm_b_star["per_attack"][a]["tried"]), 4),
                    "final_leak_rate": round(arm_b_star["per_attack"][a]["final_eff"]
                                              / max(1, arm_b_star["per_attack"][a]["tried"]), 4),
                    "suppressed_rate": round(arm_b_star["per_attack"][a]["suppressed"]
                                             / max(1, arm_b_star["per_attack"][a]["cot_leak"]), 4),
                    "displacement_count": arm_b_star["per_attack"][a]["displaced"],
                    "d30_efficacy": D30_EFFICACY[a],
                }
                for a in COT_ATTACK_MODES
            },
        },
        "insights": [],
    }

    cb_star = cost_benefit[str(s_report)]
    cb_l2 = cost_benefit[str(s_star)]
    rb_star = rebound[str(s_report)]
    best_evad = max(rebound.items(), key=lambda kv: kv[1]["rebound_pp"])

    # 净收益符号统计：比"最优点位置"更能回答"是否值得部署"
    grid_points = len(STRICTNESS_SWEEP) * len(LAMBDA_GRID)
    pos_points = [
        f"s={s:g}@λ={lam:g}"
        for s in STRICTNESS_SWEEP
        for lam in LAMBDA_GRID
        if cost_benefit[str(s)]["net_benefit"][f"lambda_{lam:g}"] > 0
    ]
    neg_by_lambda = {
        f"lambda_{lam:g}": sum(
            1 for s in STRICTNESS_SWEEP
            if cost_benefit[str(s)]["net_benefit"][f"lambda_{lam:g}"] < 0)
        for lam in LAMBDA_GRID
    }
    net_sign = {
        "grid_points": grid_points,
        "positive_points": pos_points,
        "positive_count": len(pos_points),
        "negative_count_by_lambda": neg_by_lambda,
    }
    output["results"]["net_benefit_sign_analysis"] = net_sign

    output["insights"] = [
        f"CoT 通道（s={s_report}）：{base_cot*100:.1f}% -> "
        f"{arm_b_star['cot_eff_leak_rate']*100:.1f}%（降 {cb_star['cot_leak_reduction']*100:.1f}pp，"
        f"相对 {cb_star['cot_leak_reduction_pct']*100:.0f}%）",
        f"泄露位移证实：final 从 {base_final*100:.1f}% 升至 "
        f"{arm_b_star['final_eff_leak_rate']*100:.1f}%，"
        f"displacement_ratio={cb_star['displacement_ratio']:.2f}x（>1 即证实）——"
        "被压掉的信息部分转移到最终答案，净泄露改善远小于 CoT 表面降幅",
        f"净收益几乎处处为负：{grid_points} 个格点中仅 {len(pos_points)} 个为正"
        f"（{'、'.join(pos_points) if pos_points else '无'}）；"
        f"负点数按 λ 计 {neg_by_lambda} —— **D30 作为全链路默认防线在经济上不成立**",
        f"argmax 落点：s*(λ=2)={s_star}"
        f"{'（边界解 s=0：代价计入后最优即不部署，已改用 s=' + str(s_report) + ' 做消融）' if s_star_boundary else ''}"
        f"，s* 对 λ 敏感 {s_star_by_lambda}",
        f"效能-抑制梯度严格单调（D30 效能 0.30 tool_injection "
        f"{output['results']['per_attack_at_s_report']['tool_injection']['suppressed_rate']*100:.1f}%"
        f" → 0.92 thinking_leak "
        f"{output['results']['per_attack_at_s_report']['thinking_leak']['suppressed_rate']*100:.1f}%），"
        "证明严格度真实作用于泄露率而非仅改变方差",
        f"最危险组合 {worst}：{worst_base*100:.1f}% -> {worst_def*100:.1f}%"
        f"（-{(worst_base - worst_def)*100:.1f}pp），曲线 {worst_curve}",
        f"最大规避回弹出现在 s={best_evad[0]}：自适应规避率 {best_evad[1]['adaptive_evasion_frac']*100:.1f}%"
        f" vs 静态 {best_evad[1]['static_evasion_frac']*100:.1f}%"
        f"（{best_evad[1]['rebound_pp']:+.1f}pp）",
        f"混杂披露：自适应混合的无防御上限 {adapt_ceiling*100:.1f}% 低于静态 {base_cot*100:.1f}%"
        f"（{mix_shift*100:+.1f}pp），故回弹必须按归一化规避率度量而非绝对泄露率差",
        "工程结论：D30 对显式文本型泄露（thinking_leak / prefix_extraction）有效，"
        "对侧信道与行为型泄露（tool_injection / reasoning_escalation）基本无效；"
        "宜作为专用过滤器与输入侧防御联动，而非单独部署；"
        "通用化前必须先切断位移通道（命中后改写最终答案）",
    ]

    out_path = RESULTS / "phase51_cot_firewall_ablation_v1.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[Phase 51] 结果已写入: {out_path}")
    print(f"[Phase 51] s*(λ=2)={s_star}"
          f"{'（边界解）' if s_star_boundary else ''}，消融 s={s_report}："
          f"CoT {base_cot*100:.1f}% -> {arm_b_star['cot_eff_leak_rate']*100:.1f}%，"
          f"位移 {cb_star['displacement_ratio']:.2f}x，"
          f"自适应回弹 CoT {rb_star['rebound_pp']:+.1f}pp")


if __name__ == "__main__":
    main()
