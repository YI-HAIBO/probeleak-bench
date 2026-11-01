import json, os
R = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\results"
d = json.load(open(os.path.join(R, "pooled_sample_reconciliation_v1.json"), encoding="utf-8"))
for e in d["per_experiment"]:
    if e.get("cohort") == "diverse":
        print(e["label"], "| keys:", [k for k in e.keys()])
        print("   ", {k: v for k, v in e.items() if k in ("n_records", "n_ok", "n_cot", "n_final", "rate_cot", "filter")})
s = d["summary"]
print("\nsummary keys:", list(s.keys()))
for k, v in s.items():
    if isinstance(v, dict):
        print(" ", k, {kk: vv for kk, vv in v.items() if not isinstance(vv, list)})
