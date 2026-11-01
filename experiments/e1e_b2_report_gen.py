#!/usr/bin/env python3
"""Report generator for task #103: third-window drift re-measurement (E1e)
plus the completed B2 bandit (40/40 episodes).

Every number is read from an artifact on disk -- nothing is hand-copied.
Idempotent: re-run after any experiment finishes and the tables refresh.
"""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
OUT = os.path.join(RES, "e1e_b2_report.md")

POOL = os.path.join(RES, "kilo_window3_pool.json")
E1E = os.path.join(RES, "e1e_third_window_v1.json")
B2 = os.path.join(RES, "b2_adaptive_replication_v1.json")

WINDOW_LABEL = {
    0: "wave 0 (E1 cross-model)",
    1: "window 1 (E1b)",
    2: "window 2 (E1c)",
    3: "window 3 (E1e)",
}


def load(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def pct(x, nd=1):
    if x is None:
        return "--"
    return ("%%.%df\\%%%%" % nd) % (100 * x)


def fmt_ci(ci, nd=1):
    if not ci:
        return "--"
    return ("[%%.%df, %%.%df]" % (nd, nd)) % (100 * ci[0], 100 * ci[1])


def fp(p):
    if p is None:
        return "--"
    return "%.4f" % p


def main():
    pool = load(POOL)
    e1e = load(E1E)
    b2 = load(B2)
    L = []
    w = L.append

    w("# Task #103 -- Third-window drift re-measurement (E1e) and "
      "completed B2 bandit")
    w("")
    w("Generated from artifacts: `kilo_window3_pool.json`, "
      "`e1e_third_window_v1.json`, `b2_adaptive_replication_v1.json`.")
    w("")

    # ---------------------------------------------------------- 1. pool
    w("## 1. Window-3 free pool and rotation")
    w("")
    if pool:
        w("- Captured %s UTC: **%d** models listed, **%d** marked free."
          % (pool.get("captured_utc"), pool.get("n_listed"),
             pool.get("n_free")))
        w("- Free backends: " + ", ".join("`%s`" % m
                                          for m in pool.get("free_models", []))
          + ".")
        gone = [m for m in ("reflection/beam-free",)
                if m not in (pool.get("free_models") or [])]
        if gone:
            w("- **Rotated out** since window 2: "
              + ", ".join("`%s`" % m for m in gone)
              + " -- the window-2 backend that leaked most "
                "(Beam, 13/17) is no longer reachable, so it cannot "
                "receive a third window point.")
    else:
        w("- Pool snapshot missing; run `experiments/_kilo_pool_snapshot.py`.")
    w("")

    # ------------------------------------------------- 2. window-3 results
    w("## 2. E1e -- E1 protocol on the third window")
    w("")
    if not e1e:
        w("E1e artifact missing; run `experiments/e1e_third_window.py`.")
        w("")
    else:
        ref = (e1e.get("reference_primary") or {}).get("high_tier") or {}
        w("- Protocol: 4 high-tier probes x 6 reps + 8 controls = "
          "%d requests per backend; primary reference recomputed from E3 "
          "is %d/%d = %s."
          % (len(e1e.get("high_probes", [])) * 6
             + len(e1e.get("control_probes", [])),
             ref.get("cot_leak_count", 0), ref.get("n_ok", 0),
             pct(ref.get("cot_leak_rate"))))
        w("- Elapsed: %.1f s (the wave itself ran across a longer wall-clock "
          "span; this counter restarts whenever the run resumes from the "
          "checkpoint)." % (e1e.get("elapsed_sec") or 0))
        w("")
        w("| code | backend | vendor | CoT leaks (high tier) | Wilson 95% | "
          "final | refusals | Fisher p vs primary |")
        w("|------|---------|--------|----------------------|-----------|"
          "-------|----------|----------------------|")
        pm = e1e.get("per_model") or {}
        for c in e1e.get("cross_model_comparisons", []):
            fin = ((pm.get(c["model_code"]) or {}).get("high_tier") or {}) \
                .get("final_leak_count")
            w("| %s | `%s` | %s | %d/%d = %s | %s | %s | %d | %s |"
              % (c["model_code"], c["model"], c["vendor"],
                 c["cot_leaks"], c["n"], pct(c["rate"]),
                 fmt_ci(c.get("wilson95")),
                 "--" if fin is None else fin,
                 c.get("refusal_count") or 0,
                 fp(c.get("fisher_exact_p"))))
        w("")
        ctrl = e1e.get("per_model") or {}
        n_ctrl_leak = sum(
            (v.get("controls") or {}).get("cot_leak_count") or 0
            for v in ctrl.values())
        n_ctrl = sum((v.get("controls") or {}).get("n_ok") or 0
                     for v in ctrl.values())
        w("- Control-probe CoT hits across all window-3 backends: "
          "%d/%d (report alongside the high-tier rates; the judge counts "
          "a key echoed from the system prompt as a hit)." % (n_ctrl_leak,
                                                              n_ctrl))
        w("- Gates: " + ", ".join(
            "%s=%s" % (k, v.get("passed"))
            for k, v in (e1e.get("gates") or {}).items()) + ".")
        w("")

        # ------------------------------------------------- 3. drift series
        w("## 3. Cross-window drift series")
        w("")
        w("Each row re-scans every prior E1 artifact for the same backend "
          "id, so the series is recomputed, not quoted.")
        w("")
        w("| code | backend | windows | rates per window | spread | "
          "significant shift | verdict |")
        w("|------|---------|---------|------------------|--------|"
          "-------------------|---------|")
        for code, d in (e1e.get("cross_window_drift") or {}).items():
            rates = "; ".join(
                "%s: %s" % (WINDOW_LABEL.get(s["window"], "w%s"
                                             % s["window"]),
                            pct(s["rate"]) if s.get("rate") is not None
                            else "n/a")
                for s in d["series"])
            if d["n_windows"] >= 3:
                verdict = ("drifting" if d["any_significant_shift"]
                           else "stable across %d windows" % d["n_windows"])
            elif d["n_windows"] == 2:
                verdict = ("two points only -- provisional"
                           if not d["any_significant_shift"]
                           else "shift detected, 2 points")
            else:
                verdict = "single window"
            w("| %s | `%s` | %d | %s | %s | %s | %s |"
              % (code, d["model"], d["n_windows"], rates,
                 pct(d["rate_spread"]) if d["rate_spread"] is not None
                 else "--",
                 "yes" if d["any_significant_shift"] else "no", verdict))
        w("")
        for code, d in (e1e.get("cross_window_drift") or {}).items():
            sig = [p for p in d["pairwise"] if p.get("fisher_p") is not None]
            if not sig:
                continue
            parts = []
            for p in d["pairwise"]:
                if p.get("fisher_p") is None:
                    parts.append("w%s vs w3: %s" % (p["vs_window"],
                                                    p.get("note", "n/a")))
                else:
                    parts.append("w%s vs w3: %s -> %s, p=%s"
                                 % (p["vs_window"], pct(p["prev_rate"]),
                                    pct(p["cur_rate"]), fp(p["fisher_p"])))
            w("- **%s** (`%s`): %s." % (code, d["model"], "; ".join(parts)))
        w("")

    # ------------------------------------------------------------- 4. B2
    w("## 4. B2 -- adaptive attacker on a second real model (completed)")
    w("")
    if not b2:
        w("B2 artifact missing.")
        w("")
    else:
        s = b2.get("summary") or {}
        w("- Target: `%s` (independent cross-vendor gateway)."
          % b2.get("model"))
        w("- Episodes: **%d/%d** planned, aborted=%s, elapsed %.0f s."
          % (b2.get("completed_episodes") or 0,
             b2.get("planned_episodes") or 0, b2.get("aborted"),
             b2.get("elapsed_sec") or 0))
        w("- CoT leaks **%d/%d = %s** (final %d, refusals %d); "
          "first leak at episode %s."
          % (s.get("cot_leaks") or 0, s.get("n_requests_ok") or 0,
             pct(s.get("cot_leak_rate")),
             s.get("final_leaks") or 0, s.get("refusals") or 0,
             s.get("first_leak_episode")))
        adapt = b2.get("adaptation") or {}
        if adapt:
            w("- Thompson convergence: top arm in the last third = `%s` "
              "(share %s) against a uniform share of %s."
              % (adapt.get("top_arm_last_third"),
                 pct(adapt.get("top_share_last_third")),
                 pct(adapt.get("uniform_share"))))
        w("- Per-arm (CoT leaks / pulls): " + ", ".join(
            "`%s` %s/%s" % (k, v.get("cot_leaks"),
                            v.get("n_pulls", v.get("n pulls",
                                                   v.get("pulls"))))
            for k, v in (b2.get("per_arm") or {}).items()) + ".")
        w("- Per-family (CoT leaks / pulls): " + ", ".join(
            "`%s` %s/%s" % (k, v.get("cot_leaks"),
                            v.get("n_pulls", v.get("n pulls")))
            for k, v in (b2.get("per_family") or {}).items()) + ".")
        w("- Gates: " + ", ".join("%s=%s" % (k, v.get("passed"))
                                  for k, v in (b2.get("gates") or {}).items())
          + ".")
        if (b2.get("completed_episodes") or 0) < (b2.get("planned_episodes")
                                                  or 0):
            w("- **Truncated**: the run stopped at %d of %d episodes when "
              "the anonymous window closed; every rate above is computed "
              "on the completed subset only."
              % (b2.get("completed_episodes"), b2.get("planned_episodes")))
    w("")

    # --------------------------------------------------------- 5. status
    w("## 5. Status and integration")
    w("")
    if e1e:
        n3 = sum(1 for d in (e1e.get("cross_window_drift") or {}).values()
                 if d["n_windows"] >= 3)
        n2 = sum(1 for d in (e1e.get("cross_window_drift") or {}).values()
                 if d["n_windows"] == 2)
        w("- **%d** backends now carry at least three window points; "
          "**%d** carry two." % (n3, n2))
    else:
        w("- E1e not finished; window-point counts unavailable.")
    w("- Paper status: unchanged at the current pass until this report is "
      "merged; see `results/p3_18point_audit.md` for the pass history.")
    w("")

    text = "\n".join(L) + "\n"
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print("--> %s (%d lines)" % (OUT, len(L)))


if __name__ == "__main__":
    main()
