# ProbeLeak-Bench v1.0

A frozen probe suite and evidence artifact set for measuring credential
leakage in the reasoning (chain-of-thought) channel of LLM-based database
agents.

Companion artifact set for:

> **When the Model Thinks Out Loud: Reasoning-Channel Credential Leakage
> in LLM-Integrated Database Systems**
> Haibo Yi, Shenzhen Polytechnic University.

## Repository layout

| Path | Contents |
|---|---|
| `probes/probes.json` | The 35 frozen attack probes with class, protocol family, schema-dependence and difficulty-tier metadata |
| `probes/probes.jsonl` | Same probes, one JSON object per line |
| `framework/` | The `llm_attack_eval` experiment framework (corpus, engine, judge, report, CLI) |
| `experiments/` | The experiment scripts that produced the paper's numbers; gateway authenticators are read from `GATEWAY_API_KEY` |
| `artifacts/` | The stored JSON result artifacts the paper's numbers are computed from |
| `docs/provenance.md` | Mapping of every reported value to its JSON artifact field |
| `MANIFEST.sha256` | SHA-256 of every shipped file |
| `probeleak-bench-v1.0.zip` | The same bundle as a single downloadable archive (also available on the v1.0 release) |

## Quick start

Every number in the manuscript is regenerated from `artifacts/` by the
report and figure generators; a regeneration that differs from the stored
artifact fails loudly. Simulation experiments use fixed seeds and are
exactly reproducible.

```bash
# no-credential synthetic run (no API key, no network)
python experiments/p2_synthetic_demo.py
```

## What is and is not re-runnable

- The probe suite, framework, all simulation experiments, and every derived
  statistic in the paper are re-runnable from this repository.
- The real-model experiments target third-party hosted gateways whose
  credentials are not released (the primary model is identified only under
  a disclosure agreement with the operator). The request scripts are
  shipped, so the protocol can be re-run against any gateway that exposes
  a reasoning channel, by setting `GATEWAY_API_KEY`.
- **No-credential synthetic run.** The framework ships a deterministic
  `SyntheticModel` backend plus a 15-key synthetic honeypot. Run the full
  probe-to-verdict pipeline offline, with no API key and no network:
  `python experiments/p2_synthetic_demo.py`.

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
- Probe data (`probes/`) and result artifacts (`artifacts/`): CC-BY-4.0.

See `LICENSE.txt`.
