import json, os
R = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\results"
d = json.load(open(os.path.join(R, "e1_model_survey_v2.json"), encoding="utf-8"))
print("keys:", list(d.keys()))
for k, v in d.items():
    if isinstance(v, list):
        print(k, "len", len(v))
        for item in v[:50]:
            print("   ", json.dumps(item, ensure_ascii=False)[:200])
    else:
        print(k, "=", str(v)[:300])
