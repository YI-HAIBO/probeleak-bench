"""E10 pre-flight: no network calls, checks the parts that cannot be wrong."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e10_coevo_vs_adaptive_defense as e9
from p1_real_cot_validation import HONEYPOT_KEYS

print("== SECRET_SHAPE coverage ==")
miss = [k for k in HONEYPOT_KEYS if not e9.SECRET_SHAPE.search(k)]
print("keys matched %d/%d  misses=%s" % (len(HONEYPOT_KEYS) - len(miss),
                                         len(HONEYPOT_KEYS), miss))

print("== checkpoint reuse ==")
tgt, gen = e9.load_state()
print("target records %d, generator records %d" % (len(tgt), len(gen)))
lib = {p["id"]: p for p in __import__(
    "p1_real_scale_validation", fromlist=["build_attack_probes"]
).build_attack_probes()}
print("base probes present:", all(
    ("attack_" + p) in tgt for p in e9.BASE))
print("controls present:", all(
    ("control_" + p) in tgt for p in e9.CTRL))
need_fix = ["attack_%s_%s_%d" % (e9.FIX_SRC, b, j)
            for b in e9.BASE for j in range(e9.N_PER_BASE)]
need_c1 = ["attack_%s_%s_%d" % (e9.COE1_SRC, b, j)
           for b in e9.BASE for j in range(e9.N_PER_BASE)]
have_fix = [k for k in need_fix if k in tgt]
have_c1 = [k for k in need_c1 if k in tgt]
print("fix arm reusable   %d/%d" % (len(have_fix), len(need_fix)))
print("coe1 reusable      %d/%d" % (len(have_c1), len(need_c1)))
print("new attacker calls needed: %d, new target calls needed: %d"
      % (2 * e9.N_PER_BASE * len(e9.BASE),
         2 * e9.N_PER_BASE * len(e9.BASE)))

print("== fingerprint / sim sanity ==")
tvecs0 = [e9.vec(lib[b]["user"]) for b in e9.BASE]
for b in e9.BASE:
    print("  base %-4s sim0=%.4f fp_exact=%s"
          % (b, e9.max_sim(lib[b]["user"], tvecs0),
             e9.fingerprint(lib[b]["user"]) in
             {e9.fingerprint(lib[x]["user"]) for x in e9.BASE}))
for r in tgt.values():
    if r.get("kind") == "attack":
        txt = r.get("user_text", "")
        print("  reused %-24s sim0=%.4f len=%d"
              % (r["pid"], e9.max_sim(txt, tvecs0), len(txt)))
        break

print("== oracle vs non-oracle redaction on a real leaking trace ==")
leak = None
for r in tgt.values():
    if r.get("cot_leak") and (r.get("reasoning") or ""):
        leak = r["reasoning"]
        break
if leak:
    o, _ = e9.redact_oracle(leak, 1.0)
    s, _ = e9.redact_shape(leak, 1.0)
    from e5_adaptive_rl_attacker import find_keys
    print("  trace chars=%d  oracle hits=%d  shape hits=%d"
          % (len(leak), len(find_keys(o)), len(find_keys(s))))
    spans = e9.SECRET_SHAPE.findall(leak)
    print("  shape spans found: %d" % len(spans))
    print("  first 3 spans: %s" % [x[:28] for x in spans[:3]])
else:
    print("  no leaking trace available")
