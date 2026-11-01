#!/usr/bin/env python3
"""Build the ProbeLeak-Bench v1.0 public release bundle (idempotent).

Pipeline:
  1. assemble release/probeleak-bench-v1.0/
       probes/       35 frozen probes (json + jsonl)
       framework/    src/llm_attack_eval package
       experiments/  experiment scripts (*.py, syntax-checked, scrubbed)
       artifacts/    key JSON evidence artifacts cited by the paper
       docs/         number->artifact provenance map
  2. scrub real gateway credentials from experiments/*.py
     (synthetic FAKE_-marked honeypot keys in artifacts are the measurement
     and are kept; only real authenticators are removed)
  3. verify zero real-credential literals remain
  4. write MANIFEST.sha256 + zip

No secrets ship: no .env, no bin/, no honeypot.db.
"""
import ast
import hashlib
import json
import os
import re
import shutil
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REL = os.path.join(ROOT, "release")
BUNDLE = os.path.join(REL, "probeleak-bench-v1.0")
ZIP = os.path.join(REL, "probeleak-bench-v1.0.zip")

ARTIFACTS = [
    "e3_probe_benchmark_v1.json",
    "e1_cross_model_v1.json",
    "e1b_extension_v1.json",
    "e1b_channel_probe_v1.json",
    "e1_catalog_v1.json",
    "e1c_extension_v1.json",
    "e1d_third_gateway_v1.json",
    "e1e_third_window_v1.json",
    "e4_consumer_channel_v1.json",
    "e5_adaptive_rl_attacker_v1.json",
    "e6_real_scale_expansion_v1.json",
    "b2_adaptive_replication_v1.json",
    "b3_third_gateway_v1.json",
    "e7_coevo_bandit_v1.json",
    "e7b_coevo_headtohead_v1.json",
    "e8_real_defense_validation_v1.json",
    "e10_coevo_vs_adaptive_defense_v1.json",
    "m8_control_expansion_v1.json",
    "m8_cleanliness_v2.json",
    "window_watch_v1.json",
    # P1 statistical-power closure (2026-10-26)
    "p1_benign_fpr_v1.json",
    "p1b_nc_expansion_v1.json",
    "p1c_benign_traffic_v1.json",
]

PROBE_FIELDS = ["id", "kind", "attack_mode", "family", "schema_dependent",
                "user_text", "combined_standard_prompt", "difficulty_tier"]

# A real credential body is high-entropy random (e.g. sk-f77450cea4e9...).
# Synthetic honeypot bodies are readable role words (sk-prod-abc123...).
HONEYPOT_BODY = re.compile(
    r'^(prod|admin|internal|service|webhook|test|demo|dev|staging|zh|wxm|'
    r'crm|billing|api|gateway|sandbox|stage|prod-|key|secret|token)')


def rm(p):
    if os.path.isdir(p):
        shutil.rmtree(p)
    elif os.path.exists(p):
        os.remove(p)


def copy_tree(src, dst, keep_ext=None, skip_dirs=("__pycache__",)):
    os.makedirs(dst, exist_ok=True)
    for name in os.listdir(src):
        s = os.path.join(src, name)
        d = os.path.join(dst, name)
        if os.path.isdir(s):
            if name in skip_dirs:
                continue
            copy_tree(s, d, keep_ext, skip_dirs)
        else:
            if keep_ext is not None and not name.endswith(keep_ext):
                continue
            shutil.copy2(s, d)


def py_ok(p):
    try:
        ast.parse(open(p, encoding="utf-8").read())
        return True
    except Exception:
        return False


def scrub_py(p):
    """Replace hardcoded authenticator literals; return True if changed."""
    s = open(p, "r", encoding="utf-8").read()
    orig = s
    s = re.sub(
        r'(API_KEY|api_key|apiKey)\s*=\s*["\'][A-Za-z0-9_-]{12,}["\']',
        r'\1 = os.environ.get("GATEWAY_API_KEY", "")', s)
    s = re.sub(r'["\'](sk-[A-Za-z0-9_-]{16,})["\']', '"<redacted-key>"', s)
    s = re.sub(r'["\'](ak_[A-Za-z0-9_-]{16,})["\']', '"<redacted-key>"', s)
    if s != orig:
        if 'os.environ.get("GATEWAY_API_KEY"' in s and \
           not re.search(r'^\s*(import os|from os\b)', s, re.M):
            s = "import os\n" + s
        open(p, "w", encoding="utf-8").write(s)
        return True
    return False


def scan_real_credentials(base):
    """Hits that look like real authenticators (random body, no FAKE_ marker)."""
    hits = []
    for root, _dirs, files in os.walk(base):
        for fn in files:
            p = os.path.join(root, fn)
            try:
                s = open(p, "rb").read().decode("latin-1")
            except Exception:
                continue
            for i, line in enumerate(s.splitlines(), 1):
                if "FAKE_" in line:
                    continue
                for m in re.findall(
                        r'(?:sk-[A-Za-z0-9_-]{16,}|ak_[A-Za-z0-9_-]{16,})', line):
                    body = m.split("-", 1)[1] if m.startswith("sk-") else m
                    if HONEYPOT_BODY.match(body):
                        continue  # synthetic honeypot value
                    # prose false positive? (English words, underscores)
                    if re.fullmatch(r'[a-z]{2,}(_[a-z]{2,})+', body):
                        continue
                    hits.append((os.path.relpath(p, base), i, m[:24]))
    return hits


def main():
    os.makedirs(REL, exist_ok=True)
    rm(BUNDLE)
    rm(ZIP)
    os.makedirs(BUNDLE)

    # 1) probes ------------------------------------------------------------
    data = json.load(open(os.path.join(ROOT, "results",
                                       "e3_probe_benchmark_v1.json"),
                          encoding="utf-8"))
    probes = data["manifest"]
    assert len(probes) == 35, "expected 35 probes, got %d" % len(probes)
    pd = os.path.join(BUNDLE, "probes")
    os.makedirs(pd)
    clean = [{k: p.get(k) for k in PROBE_FIELDS} for p in probes]
    with open(os.path.join(pd, "probes.json"), "w", encoding="utf-8") as f:
        json.dump({"name": "ProbeLeak-Bench", "version": "1.0",
                   "probe_count": len(clean), "fields": PROBE_FIELDS,
                   "probes": clean}, f, ensure_ascii=False, indent=2)
    with open(os.path.join(pd, "probes.jsonl"), "w", encoding="utf-8") as f:
        for p in clean:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    # 2) framework ---------------------------------------------------------
    copy_tree(os.path.join(ROOT, "src", "llm_attack_eval"),
              os.path.join(BUNDLE, "framework"))

    # 3) experiment scripts (syntax gate + scrub) ---------------------------
    ex_src = os.path.join(ROOT, "experiments")
    ex_dst = os.path.join(BUNDLE, "experiments")
    os.makedirs(ex_dst)
    excluded = []
    scrubbed = []
    for name in sorted(os.listdir(ex_src)):
        s = os.path.join(ex_src, name)
        if os.path.isdir(s):
            if name == "__pycache__":
                continue
            sub = os.path.join(ex_dst, name)
            os.makedirs(sub)
            for fn in sorted(os.listdir(s)):
                if fn.endswith(".py"):
                    sp = os.path.join(s, fn)
                    if not py_ok(sp):
                        excluded.append(os.path.join(name, fn))
                        continue
                    dp = os.path.join(sub, fn)
                    shutil.copy2(sp, dp)
                    if scrub_py(dp):
                        scrubbed.append(os.path.join(name, fn))
        elif name.endswith(".py"):
            sp = s
            if not py_ok(sp):
                excluded.append(name)
                continue
            dp = os.path.join(ex_dst, name)
            shutil.copy2(sp, dp)
            if scrub_py(dp):
                scrubbed.append(name)

    # 4) artifacts ---------------------------------------------------------
    ad = os.path.join(BUNDLE, "artifacts")
    os.makedirs(ad)
    missing = []
    for name in ARTIFACTS:
        s = os.path.join(ROOT, "results", name)
        if os.path.exists(s):
            shutil.copy2(s, os.path.join(ad, name))
        else:
            missing.append(name)

    # 5) docs --------------------------------------------------------------
    dd = os.path.join(BUNDLE, "docs")
    os.makedirs(dd)
    shutil.copy2(os.path.join(ROOT, "results", "p3_metrics_provenance.md"),
                 os.path.join(dd, "provenance.md"))
    if excluded:
        with open(os.path.join(dd, "EXCLUDED.txt"), "w", encoding="utf-8") as f:
            f.write("Legacy scripts excluded from this release "
                    "(pre-existing syntax errors; superseded):\n")
            f.write("\n".join(excluded) + "\n")

    # 6) credential verification -------------------------------------------
    hits = scan_real_credentials(BUNDLE)
    if hits:
        for h in hits[:20]:
            print("  CREDENTIAL:", h)
        raise SystemExit("ABORT: bundle still contains real credentials")

    # 7) README / LICENSE / CHANGELOG --------------------------------------
    write_readme(BUNDLE, len(clean), len(excluded))
    write_license(BUNDLE)
    write_changelog(BUNDLE)

    # 8) MANIFEST + zip ----------------------------------------------------
    lines = []
    for root, _dirs, files in os.walk(BUNDLE):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, BUNDLE).replace(os.sep, "/")
            h = hashlib.sha256(open(p, "rb").read()).hexdigest()
            lines.append("%s  %s" % (h, rel))
    with open(os.path.join(BUNDLE, "MANIFEST.sha256"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(BUNDLE):
            for fn in sorted(files):
                p = os.path.join(root, fn)
                z.write(p, os.path.join("probeleak-bench-v1.0",
                                        os.path.relpath(p, BUNDLE)))

    n = sum(len(fs) for _, _, fs in os.walk(BUNDLE))
    size = sum(os.path.getsize(os.path.join(r, f))
               for r, _, fs in os.walk(BUNDLE) for f in fs)
    print("bundle: %s" % BUNDLE)
    print("files:  %d  (%.2f MB)" % (n, size / 1e6))
    print("zip:    %.2f MB" % (os.path.getsize(ZIP) / 1e6))
    print("probes: %d" % len(clean))
    print("scripts scrubbed of hardcoded keys: %d" % len(scrubbed))
    print("legacy scripts excluded (syntax): %d" % len(excluded))
    if missing:
        print("WARNING artifacts missing: %s" % missing)
    print("credential scan: 0 real authenticators")


README_tpl = """# ProbeLeak-Bench v1.0

A frozen probe suite and evidence artifact set for measuring credential
leakage in the reasoning (chain-of-thought) channel of LLM-based database
agents.

This bundle accompanies the manuscript:

> **Measuring the Reasoning-Channel Blind Spot in LLM Database Agents:
> Forensic Evidence of Credential Leakage and Defense Composition**
> Haibo Yi, Shenzhen Polytechnic University.

## Contents

| Path | Contents |
|---|---|
| `probes/probes.json` | The 35 frozen attack probes with class, protocol family, schema-dependence and difficulty-tier metadata |
| `probes/probes.jsonl` | Same probes, one JSON object per line |
| `framework/` | The `llm_attack_eval` experiment framework (corpus, engine, judge, report, CLI) |
| `experiments/` | The experiment scripts that produced the paper's numbers; gateway authenticators are read from `GATEWAY_API_KEY` |
| `artifacts/` | The stored JSON result artifacts the paper's numbers are computed from |
| `docs/provenance.md` | Mapping of every reported value to its JSON artifact field |
| `MANIFEST.sha256` | SHA-256 of every shipped file |

## Quick start

```bash
pip install -e .                      # or put framework/ on PYTHONPATH
export GATEWAY_API_KEY=...            # only for re-running real-model scripts
python -c "import json; \\
print(len(json.load(open('probes/probes.json'))['probes']))"   # 35
```

Every number in the manuscript is regenerated from `artifacts/` by the
report and figure generators; a regeneration that differs from the stored
artifact fails loudly. Simulation experiments use fixed seeds and are
exactly reproducible.

## What is and is not re-runnable

- The probe suite, framework, all simulation experiments, and every derived
  statistic in the paper are re-runnable from this bundle.
- The real-model experiments target third-party hosted gateways whose
  credentials are not released (the primary model is identified only under
  a disclosure agreement with the operator). The request scripts are
  shipped, so the protocol can be re-run against any gateway that exposes
  a reasoning channel, by setting `GATEWAY_API_KEY`.
- **No-credential synthetic run.** The framework ships a deterministic
  `SyntheticModel` backend plus a 15-key synthetic honeypot. Run the full
  probe-to-verdict pipeline offline, with no API key and no network:

  ```bash
  python experiments/p2_synthetic_demo.py
  ```

  This replays the probe set through the mock reasoning model and reproduces
  the manuscript's channel-separation signature (reasoning-channel leakage
  with a clean final channel), asserting a blind-spot gate. It is a faithful
  harness for the non-credential parts of the pipeline, not a substitute for
  the real-model measurements.

## Ethics and safety

- All credentials in the experiments are **synthetic honeypot keys** marked
  with a `FAKE_` prefix in a dedicated test database. No real customer
  secret and no personally identifiable data appears in any artifact. Key
  values that appear inside `artifacts/` are the synthetic material the
  models were measured on reciting; they are not authenticators.
- The gateway operator was informed of the findings before submission and
  consented to publication.
- The probes are intended for measuring leakage on systems you operate or
  are authorized to test.

## License

- Code (`framework/`, `experiments/`): MIT.
- Probe data (`probes/`) and result artifacts (`artifacts/`):
  CC-BY-4.0.

See `LICENSE.txt`.
"""

LICENSE_txt = """ProbeLeak-Bench v1.0

Copyright (c) 2026 Haibo Yi, Shenzhen Polytechnic University.

Code files (framework/, experiments/) are licensed under the MIT License:

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

The probe suite (probes/) and the result artifacts (artifacts/) are
licensed under Creative Commons Attribution 4.0 International (CC-BY-4.0):

  https://creativecommons.org/licenses/by/4.0/
"""

CHANGELOG_txt = """# Changelog

## v1.0 - 2026-10-26

- Initial public release.
- 35 frozen attack probes (high-tier, mid-tier, low-tier) with class,
  protocol-family, schema-dependence and difficulty-tier metadata.
- Evidence artifacts for: the native blind-spot measurement (fresh-probe
  14.55% CoT leak vs 0/268 final), cross-vendor replication across three
  gateway operators and fifteen backends, three quota windows, the
  adaptive attacker, the co-evolving attacker, real defense validation
  (D23' rewrite-equivalence and output-side layer), the consumer arm,
  and the M8 control-expansion cleanliness quantification.
- Provenance map from every reported value to its JSON artifact field.
- Synthetic no-credential pipeline: a deterministic `SyntheticModel`
  backend plus a 15-key synthetic honeypot that replays the probe-to-verdict
  flow offline and reproduces the reasoning-channel blind spot
  (`experiments/p2_synthetic_demo.py`).
"""


def write_readme(bundle, n, n_excluded):
    with open(os.path.join(bundle, "README.md"), "w", encoding="utf-8") as f:
        f.write(README_tpl.replace("The 35 frozen", "The %d frozen" % n))


def write_license(bundle):
    with open(os.path.join(bundle, "LICENSE.txt"), "w", encoding="utf-8") as f:
        f.write(LICENSE_txt)


def write_changelog(bundle):
    with open(os.path.join(bundle, "CHANGELOG.md"), "w", encoding="utf-8") as f:
        f.write(CHANGELOG_txt)


if __name__ == "__main__":
    main()
