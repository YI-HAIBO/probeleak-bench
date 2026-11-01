import json, os, collections
R = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\results"
for fn, path in [("p1_real_cot_validation_v1.json", "records"),
                 ("e2_real_schema_hiding_v1.json", "records"),
                 ("e4_consumer_channel_v1.json", "producer.records")]:
    d = json.load(open(os.path.join(R, fn), encoding="utf-8"))
    obj = d
    for part in path.split("."):
        obj = obj[part]
    leaks = [r for r in obj if isinstance(r, dict) and r.get("cot_leak")]
    print(fn)
    print("  leak ids:", sorted(str(r.get("id")) for r in leaks))
    print("  leak modes:", dict(collections.Counter(r.get("attack_mode") for r in leaks)))
