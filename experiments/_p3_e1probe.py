import json
J = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\results\e1_cross_model_v1.json"
d = json.load(open(J, encoding="utf-8"))
for c in d["cross_model_comparisons"]:
    print(json.dumps(c, ensure_ascii=False))
