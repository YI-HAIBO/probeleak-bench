"""Fetch and analyze the cross-vendor gateway model catalog (E1 enhancement).

The original 39-model census was built from a hand-picked candidate list.
The gateway exposes a 402-model catalog at /api/gateway/models. This script
downloads the catalog, filters to *reasoning-capable candidates* (models
whose id/architecture suggests a plaintext reasoning channel), and writes
results/e1_catalog_v1.json so the census can be re-run over a much larger
systematic candidate pool once the chat quota recovers.
"""
import json
import urllib.request

URL = "https://api.kateway"  # replaced below
URL = "https://api.kilo.ai/api/gateway/models"
OUT = r"C:\Users\Yi\WorkBuddy\2026-10-10-18-49-43\llm-attack-eval\results\e1_catalog_v1.json"

req = urllib.request.Request(URL, headers={"Authorization": "Bearer anonymous"})
with urllib.request.urlopen(req, timeout=60) as r:
    d = json.loads(r.read().decode("utf-8"))
models = d.get("data", d)
print("n models:", len(models))
# inspect one record structure
print("sample record:", json.dumps(models[0], ensure_ascii=False)[:400])

# Reasoning-channel keywords in id or architecture/reasoning fields
KEYS = ("reason", "thinking", "r1", "o1", "o3", "qwq", "deepseek-r", " beam",
        "nemotron", "reflect", "magistral", "gpt-oss", "llama", "qwen3",
        "rubik", "skywork", "absolute", "gemma", "phi-4", "marco")


def fields(m):
    if isinstance(m, str):
        return m, "", ""
    mid = m.get("id") or m.get("model") or ""
    arch = m.get("architecture", {}) or {}
    if not isinstance(arch, str):
        arch = json.dumps(arch, ensure_ascii=False)
    extra = json.dumps(
        {k: v for k, v in m.items()
         if k not in ("id", "model", "architecture")},
        ensure_ascii=False)
    return mid, arch, extra


def is_free(m):
    if isinstance(m, str):
        return False
    pricing = m.get("pricing", {})
    if isinstance(pricing, dict):
        return (pricing.get("prompt") in ("0", 0, "0.0")
                and pricing.get("completion") in ("0", 0, "0.0"))
    return "free" in (m.get("id") or "").lower()


all_ids = []
reasoning_candidates = []
for m in models:
    mid, arch, extra = fields(m)
    all_ids.append(mid)
    blob = (mid + " " + arch + " " + extra).lower()
    if any(k in blob for k in KEYS):
        reasoning_candidates.append({
            "id": mid,
            "free": is_free(m),
            "architecture": arch[:200],
        })

print("n reasoning-keyword candidates:", len(reasoning_candidates))
free_ids = [c for c in reasoning_candidates if c["free"]]
print("n free among them:", len(free_ids))

out = {
    "source": URL,
    "n_models": len(models),
    "n_reasoning_candidates": len(reasoning_candidates),
    "reasoning_candidates": reasoning_candidates,
    "all_model_ids": all_ids,
}
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)
print("WROTE", OUT)
