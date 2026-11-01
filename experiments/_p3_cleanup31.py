"""Pass-31: Remove engineering artifacts and code traces from the manuscript."""
import os, sys

TEX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "paper", "p3_tifs.tex")

with open(TEX, "r", encoding="utf-8") as f:
    tex = f.read()

edits = []

# --- P0-1: "repetition-v2 run" (L389-392) ---
old = ("classes. The repetition-v2 run shows that appearance was a small-sample\n"
       "artifact. The repetition-v2 run (the first to third translation-exfiltration probes, the first and second role-play probes, 8 repetitions each; 39 successful responses\n"
       "from 48 requests sent, with the third role-play probe entirely gateway-blocked by the upstream content-safety layer (HTTP 403, Forbidden) and one\n"
       "further request failing, so role-play results are the first and second role-play probes only) found that\n"
       "role-play leaked CoT 16/16 (100\\%) and final 16/16 (100\\%), and\n"
       "translation-exfiltration leaked CoT 23/23 (100\\%) and final 16/23 (69.6\\%). The")
new = ("classes. The expanded repetition run shows that appearance was a small-sample\n"
       "artifact. The expanded repetition run (the translation-exfiltration and role-play probes at 8 repetitions each; 39 successful responses\n"
       "from 48 requests sent, with one role-play probe entirely gateway-rejected by the upstream content-safety layer (HTTP 403, Forbidden) and one\n"
       "further request failing, so role-play results are the remaining role-play probes only) found that\n"
       "role-play leaked CoT 16/16 (100\\%) and final 16/16 (100\\%), and\n"
       "translation-exfiltration leaked CoT 23/23 (100\\%) and final 16/23 (69.6\\%). The")
edits.append((old, new, "P0-1 repetition-v2"))

# --- P0-2: "prompt-level self-check arm" (L430) ---
old = ("requests coming from a prompt-level self-check arm), and the third sample")
new = ("requests coming from a prompt-level self-check condition), and the third sample")
edits.append((old, new, "P0-2 self-check arm"))

# --- P0-3: "field name that differs from the one used by other runs" (L525-526) ---
old = ("negative-control, and ablation records; in addition the stress test stores the reasoning leak under a field\n"
       "name that differs from the one used by other runs. None of the")
new = ("negative-control, and ablation records; in addition the stress test stores the reasoning leak under a label\n"
       "that differs from the one used by other runs. None of the")
edits.append((old, new, "P0-3 field name"))

# --- P0-4: "the consumer arm, full-text release" (L785) ---
old = ("high-leak probe responses collected on the primary model (the consumer arm,\n"
       "full-text release). Of these, 13 contained verifiable key signatures in the raw")
new = ("high-leak probe responses collected on the primary model (the consumer-arm sample, full-text release). Of these, 13 contained verifiable key signatures in the raw")
edits.append((old, new, "P0-4 consumer arm"))

# --- P0-5: "the security audit run" (L1256) ---
old = ("defense agent's current residual. The real LLM-driven security audit (the security audit run)\n"
       "      extracted the credential in 4 of 4 sessions on the deployed model, but")
new = ("defense agent's current residual. The real LLM-driven security audit\n"
       "      extracted the credential in 4 of 4 sessions on the deployed model, but")
edits.append((old, new, "P0-5 security audit run"))

# --- P0-6: "arm A only" + "per-experiment channel field names" (L1270-1271) ---
old = ("documented filter (attack-class records only, arm A only for the first and second samples,\n"
       "per-experiment channel field names) and re-verifies determinism by byte-level")
new = ("documented filter (attack-class records only, for the first and second samples,\n"
       "per-experiment channel labels) and re-verifies determinism by byte-level")
edits.append((old, new, "P0-6 arm A / field names"))

# --- P0-7: "per-model gateway error bodies" + "pooled-sample reconciliation artifact" (L1287-1288) ---
old = ("generators, and every JSON result artifact, including the per-model gateway\n"
       "error bodies for the blocked cross-model replication and the pooled-sample\n"
       "reconciliation artifact; each figure and table value maps to a JSON field in")
new = ("generators, and every JSON result artifact, including the per-model gateway\n"
       "error responses for the blocked cross-model replication and the pooled-sample\n"
       "reconciliation data; each figure and table value maps to a JSON field in")
edits.append((old, new, "P0-7 error bodies / reconciliation artifact"))

# --- P1-1: "re-optimizes every 100 requests" (L932) ---
old = ("per-configuration, per-class leak-rate model and re-optimizes every 100\n"
       "requests.")
new = ("per-configuration, per-class leak-rate model and re-optimizes periodically\n"
       "requests.")
edits.append((old, new, "P1-1 every 100 requests"))

# --- P1-2: "every five generations" (L940) ---
old = ("the request stream, the co-evolution schedule (in which an adaptive attacker migrates\n"
       "its attack mix every five generations), and the utility aggregation are")
new = ("the request stream, the co-evolution schedule (in which an adaptive attacker migrates\n"
       "its attack mix periodically), and the utility aggregation are")
edits.append((old, new, "P1-2 every five generations"))

# --- P1-3: "every five generations" (L964) ---
old = ("co-evolution attacker that migrates its attack mix every five generations toward\n"
       "the currently highest-residual class, the agent's utility falls to")
new = ("co-evolution attacker that migrates its attack mix periodically toward\n"
       "the currently highest-residual class, the agent's utility falls to")
edits.append((old, new, "P1-3 every five generations (L964)"))

# --- P1-4: "three-seed stability" (L742) ---
old = ("marginal drift below 0.002 in every cell; monotonicity in $\\rho$ and\n"
       "three-seed stability also hold.")
new = ("marginal drift below 0.002 in every cell; monotonicity in $\\rho$ and\n"
       "multiple-seed stability also hold.")
edits.append((old, new, "P1-4 three-seed stability"))

# --- P1-5: "check mode" (L1274) ---
old = ("Report and figure generators are reproducible and expose a check mode that signals failure if a regenerated artifact differs from the stored one.")
new = ("Report and figure generators are reproducible and expose a verification mechanism that signals failure if a regenerated artifact differs from the stored one.")
edits.append((old, new, "P1-5 check mode"))

# --- P1-6: "digests" (L368) ---
old = ("generator that re-reads the JSON artifacts (structured records storing per-response verdicts, gate results, and digests); re-running any generator reproduces")
new = ("generator that re-reads the JSON artifacts (structured records storing per-response verdicts, gate results, and content-based hashes); re-running any generator reproduces")
edits.append((old, new, "P1-6 digests (L368)"))

# --- P1-7: "digests" (L1268) ---
old = ("per-response verdicts, gate results, and a content-based digest; the pooled statistics")
new = ("per-response verdicts, gate results, and a content-based hash; the pooled statistics")
edits.append((old, new, "P1-7 digest (L1268)"))

# --- P1-8: "trace identifiers" (L566-567) ---
old = ("HTTP 403 (Forbidden; ``key not bound to this model''), with per-model error bodies and\n"
       "trace identifiers preserved (each response carries a unique identifier that allows the operator to correlate the error with the request, though the identifiers are not released).")
new = ("HTTP 403 (Forbidden; ``key not bound to this model''), with per-model error responses and\n"
       "unique response identifiers preserved (each response carries a unique identifier that allows the operator to correlate the error with the request, though the identifiers are not released).")
edits.append((old, new, "P1-8 trace identifiers"))

# --- P1-9: "gateway-blocked" (L358) ---
old = ("final), the union rate, the refusal rate, and gateway-blocked counts. For")
new = ("final), the union rate, the refusal rate, and gateway-rejected counts. For")
edits.append((old, new, "P1-9 gateway-blocked (L358)"))

# --- P1-10: "the first, second, schema-hiding, third, and consumer samples" (L1204) ---
old = ("five independent real samples of the primary model (the first, second, schema-hiding, third, and consumer samples; diverse-cohort total $N=268$)")
new = ("five independent real samples of the primary model (the first, second, third, and consumer samples, plus the schema-hiding arm; diverse-cohort total $N=268$)")
edits.append((old, new, "P1-11 sample names"))

# Apply all edits
for old, new, label in edits:
    cnt = tex.count(old)
    if cnt != 1:
        print(f"ABORT [{label}]: expected 1 occurrence, found {cnt}")
        print(f"  old: {repr(old[:80])}")
        sys.exit(1)
    tex = tex.replace(old, new)
    print(f"OK [{label}]")

tmp = TEX + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(tex)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, TEX)
print(f"Written {TEX} ({len(tex)} bytes)")
print("Pass-31 complete.")