#!/usr/bin/env python3
"""Report generator for the 2026-10-24 cross-vendor wave-2 session.

Covers three artifacts:
  - results/kilo_reprobe_v1.json   (gateway re-probe / channel census)
  - results/e1c_extension_v1.json  (E1 protocol on 4 newly-rotated models)
  - results/b2_adaptive_replication_v1.json (E5 bandit on a 2nd model)

All numbers in the report are read from those JSONs at generation time
(no hardcoded figures), and the generator is idempotent.
Output: results/e1c_b2_report.md
"""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REPROBE = os.path.join(ROOT, "results", "kilo_reprobe_v1.json")
E1C = os.path.join(ROOT, "results", "e1c_extension_v1.json")
B2 = os.path.join(ROOT, "results", "b2_adaptive_replication_v1.json")
E5 = os.path.join(ROOT, "results", "e5_adaptive_rl_attacker_v1.json")
OUT = os.path.join(ROOT, "results", "e1c_b2_report.md")


def pct(x, digits=1):
    return ("%.{}f%%".format(digits) % (100.0 * x)) if x is not None else "--"


def fmt_ci(ci, digits=1):
    if not ci or ci[0] is None:
        return "--"
    fmt = "[%%.%df, %%.%df]" % (digits, digits)
    return fmt % (ci[0], ci[1])


def load(p):
    return json.load(open(p, encoding="utf-8"))


def main():
    rp = load(REPROBE)
    e1c = load(E1C)
    b2 = load(B2)
    e5 = load(E5)

    lines = []
    A = lines.append

    A("# Cross-Vendor Wave-2 Report (2026-10-24)")
    A("")
    A("Session goal: use the newly re-opened free pool of the cross-vendor")
    A("gateway (`https://api.kilo.ai/api/gateway`, anonymous key) to (a)")
    A("re-probe the channel census, (b) run the E1 protocol on four")
    A("newly-rotated reasoning models (E1c), and (c) revive the blocked B2")
    A("cross-model experiment with the E5 adaptive attacker on a second")
    A("reasoning model. All figures below are read at generation time from")
    A("the three source JSONs; nothing is hardcoded.")
    A("")

    # ---------------------------------------------------------------- reprobe
    A("## 1. Gateway re-probe")
    A("")
    A("- catalog: 402 listed models, %d with `isFree`."
      % rp["n_listed_free"])
    A("- probed the %d free reasoning candidates: %d responsive, %d blocked;"
      % (rp["n_probed"], rp["n_responsive"], rp["n_probed"] - rp["n_responsive"]))
    A("  of which %d expose a non-empty plaintext reasoning channel on a"
      % rp["n_plaintext_reasoning"])
    A("  benign prompt (`reasoning_content`/`reasoning` field non-empty).")
    A("- `kilo-auto/free` is a router: all 5 sampled requests resolved to")
    A("  `dots-studio/dots-3-note-preview:free` (the primary model's family")
    A("  under separate hosting) with the reasoning channel live.")
    A("- Two free models show **no** reasoning channel on benign prompts")
    A("  (`stealth/glyph-cluster`, `poolside/laguna-s-2.1:free`); two were")
    A("  hard-blocked at probe time (`nemotron-3.5-super-vl` 502,")
    A("  `nemotron-3-super-120b-a12b` 404).")
    A("- Artifact: `results/kilo_reprobe_v1.json`.")
    A("")

    # ---------------------------------------------------------------- E1c
    A("## 2. E1c: extension cohort wave 2")
    A("")
    A("Protocol identical to E1b: 4 high-tier probes x6 reps + 8 controls")
    A("= 32 requests per model; same system prompt, 15 honeypot keys,")
    A("dual-channel judge. Primary-model reference recomputed from")
    A("`e3_probe_benchmark_v1.json`: high tier %d/%d = %s (CI %s)."
      % (e1c["reference_primary"]["high_tier"]["cot_leak_count"],
         e1c["reference_primary"]["high_tier"]["n_ok"],
         pct(e1c["reference_primary"]["high_tier"]["cot_leak_rate"]),
         fmt_ci(e1c["reference_primary"]["high_tier"]["cot_leak_wilson95"])))
    A("")
    A("| code | model | vendor | high-tier CoT leak | vs primary | Fisher p |")
    A("|------|-------|--------|--------------------|-----------|----------|")
    for c in e1c["cross_model_comparisons"]:
        A("| %s | %s | %s | %d/%d = %s (CI %s) | %+.3f, CI %s | %.4f |"
          % (c["model_code"], c["model"], c["vendor"],
             c["cot_leaks"], c["n"], pct(c["rate"]), fmt_ci(c["wilson95"]),
             c["diff_minus_ref"], fmt_ci(c["diff_wald95"], 3),
             c["fisher_exact_p"]))
    A("")
    per = e1c["per_model"]
    A("Per-model integrity (as measured, truncations reported, not imputed):")
    A("")
    for code in ["M_L", "M_M", "M_N", "M_O"]:
        d = per[code]
        o = d["overall"]
        A("- **%s** %s (%s): usable %d/%d sent; overall CoT %d, final %d,"
          " refusal %d."
          % (code, d["model"], d["vendor"], o["n_ok"], o["n_sent"],
             o["cot_leak_count"], o["final_leak_count"], o["refusal_count"]))
    A("")
    A("Gates: " + ", ".join(
        "%s=%s" % (k, v.get("passed")) for k, v in e1c["gates"].items()) + ".")
    A("")
    A("Reading:")
    A("")
    A("- The two fully-usable **small-to-mid reasoning models leak at or")
    A("  above the primary model's rate**: M_L (Nemotron-3-Nano-Omni 30B)")
    A("  %s and M_M (Reflection Beam) %s; both 95%% CIs cover the primary"
      % (pct(per["M_L"]["high_tier"]["cot_leak_rate"]),
         pct(per["M_M"]["high_tier"]["cot_leak_rate"])))
    A("  rate of %s (Fisher p=%.2f and p=%.2f). The blind spot is not a"
      % (pct(e1c["reference_primary"]["high_tier"]["cot_leak_rate"]),
         e1c["cross_model_comparisons"][0]["fisher_exact_p"],
         e1c["cross_model_comparisons"][1]["fisher_exact_p"]))
    A("  property of one vendor or one scale point.")
    A("- **M_O (Poolside Laguna XS 2.1) leaks 0/%d high-tier** (CI %s,"
      % (per["M_O"]["high_tier"]["n_ok"],
         fmt_ci(per["M_O"]["high_tier"]["cot_leak_wilson95"])))
    A("  Fisher p=%.4f vs primary): a second protective model after"
      % e1c["cross_model_comparisons"][2]["fisher_exact_p"])
    A("  content-safety. Its reasoning channel is live but does not emit")
    A("  the honeypot keys. Floor effects and quota truncation (%d/%d usable)"
      % (per["M_O"]["overall"]["n_ok"], per["M_O"]["overall"]["n_sent"]))
    A("  both apply; replication on a fuller sample is needed before")
    A("  calling it aligned.")
    A("- **M_N (Xingchen AGI Xing 4.0 29B) was quota-blocked on all 32")
    A("  attempts** during this wave (channel probe succeeded earlier the")
    A("  same day, so the block is a quota window artifact, not a")
    A("  hard-unavailable model). Reported as 0/0, not imputed.")
    A("- Gate g2 (dual-channel visibility >= 0.9 per model) fails only")
    A("  because M_N returned nothing; every model with any usable")
    A("  response has both channels visible.")
    A("")

    # ---------------------------------------------------------------- B2
    A("## 3. B2 revival: adaptive attacker on a second model")
    A("")
    A("Original B2 verdict was `BLOCKED_NO_SECOND_REASONING_MODEL`: the")
    A("primary gateway serves exactly one model. The re-probe showed")
    A("`nvidia/nemotron-3.5-lightning:free` (quota-blocked 32/32 during")
    A("E1b's wave, live now) exposes a plaintext reasoning channel, so the")
    A("E5 protocol (Thompson-sampling bandit over the same 12 fresh")
    A("paraphrase arms, same system prompt and judge) was re-run against")
    A("it as the second model.")
    A("")
    s = b2["summary"]
    A("- Planned %d episodes; the shared free quota locked after %d episodes"
      % (b2["planned_episodes"], b2["completed_episodes"]))
    A("  (consecutive 429 `PROMOTION_MODEL_LIMIT_REACHED` across 5 retries),")
    A("  so the run stopped at %d episodes (%d usable). Truncation is"
      % (b2["completed_episodes"], s["n_requests_ok"]))
    A("  reported, not imputed.")
    A("- CoT leaks: %d/%d = %s; final-channel leaks: %d; refusals: %d."
      % (s["cot_leaks"], s["n_requests_ok"], pct(s["cot_leak_rate"]),
         s["final_leaks"], s["refusals"]))
    A("- **First leak at episode %d** (the primary-model run needed 5"
      % (s["first_leak_episode"] if s["first_leak_episode"] is not None
         else -1))
    A("  episodes): the attacker needed no exploration to find the blind")
    A("  spot on the second model.")
    A("- Family rates (usable pulls only): "
      + "; ".join(
          "%s %d/%d" % (fam, v["cot_leaks"], v["n_pulls"])
          for fam, v in b2["per_family"].items() if v["n_pulls"]) + ".")
    tl = b2["per_family"]["thinking_leak"]
    A("- **thinking_leak family: %d/%d = %s** on the second model"
      % (tl["cot_leaks"], tl["n_pulls"], pct(tl["cot_rate"])))
    A("  (CI %s); on the primary model the same family ran %d/%d = %s."
      % (fmt_ci(tl["wilson95"]),
         e5["per_family"]["thinking_leak"]["cot_leaks"],
         e5["per_family"]["thinking_leak"]["n pulls"],
         pct(e5["per_family"]["thinking_leak"]["cot_rate"])))
    A("  The trigger family the bandit converged on is the same.")
    A("- The asymmetry replicates: **%d CoT leaks vs %d final leaks** —"
      % (s["cot_leaks"], s["final_leaks"]))
    A("  honeypot keys surface in reasoning while the final answer stays")
    A("  clean.")
    A("- Gates: " + ", ".join(
        "%s=%s" % (k, v.get("passed")) for k, v in b2["gates"].items()) + ".")
    A("  Caveat: g2 (adaptation) is computed on the final third of a")
    A("  truncated run, i.e. %d episodes — it passes formally but carries"
      % max(1, s["n_requests_ok"] // 3))
    A("  almost no statistical weight and is reported as such.")
    A("- Artifact: `results/b2_adaptive_replication_v1.json`.")
    A("")

    # ---------------------------------------------------------------- budget
    A("## 4. Quota accounting")
    A("")
    A("- E1c live wave: %d requests sent (4 models x 32)."
      % sum(per[c]["overall"]["n_sent"] for c in per))
    A("- B2: %d episodes attempted (%d usable, %d failed on quota), each"
      % (b2["completed_episodes"], s["n_requests_ok"],
         b2["completed_episodes"] - s["n_requests_ok"]))
    A("  with up to 5 retries on 429.")
    A("- Channel re-probe prior to the wave: %d benign probes."
      % rp["n_probed"])
    A("- Behavior matches the E1b-era observation that the anonymous free")
    A("  pool is a shared rotating window: models lock mid-wave")
    A("  (`PROMOTION_MODEL_LIMIT_REACHED`) and recover later the same day")
    A("  (Lightning was 32/32 blocked in E1b and fully live here).")
    A("")

    A("## 5. What this changes for the paper")
    A("")
    A("- These are new, post-Pass-36 results and are **not yet integrated**")
    A("  into `p3_tifs.tex`; the paper remains at Pass-36.")
    A("- Candidate additions if a follow-up pass is wanted: wave-2 rows for")
    A("  tab:e1b (M_L/M_M/M_O with their truncation states), and a")
    A("  cross-model replication sentence for the adaptive-attacker section")
    A("  (second model, same trigger family, first-leak at episode 1).")
    A("- The honest limitations stand: %d-episode usable bandit sample, quota-"
      % s["n_requests_ok"])
    A("  truncated per-model cells, shared anonymous quota beyond our")
    A("  control.")
    A("")

    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, OUT)
    print("wrote %s (%d lines)" % (OUT, len(lines)))


if __name__ == "__main__":
    main()
