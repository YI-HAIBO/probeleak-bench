# ProbeLeak-Bench v1.0

Frozen probe suite and evidence artifact set for measuring credential leakage in the reasoning (chain-of-thought) channel of LLM-based database agents.

Companion artifact set for: *Measuring the Reasoning-Channel Blind Spot in LLM Database Agents: Forensic Evidence of Credential Leakage and Defense Composition* (Haibo Yi, Shenzhen Polytechnic University).

## Contents

- `probeleak-bench-v1.0.zip` \- the full bundle (350 files: 35 frozen probes, framework, experiment scripts, stored artifacts, provenance map, MANIFEST.sha256)
- `README.md` \- this file
- `RELEASE_NOTES.md` \- what's in this release

## Quick start

Download the zip and run the no-credential synthetic pipeline:

```bash
unzip probeleak-bench-v1.0.zip
cd probeleak-bench-v1.0
python experiments/p2_synthetic_demo.py
```

This replays the full probe-to-verdict pipeline offline with a deterministic `SyntheticModel` backend and a 15-key synthetic honeypot \- no API key, no network. Real-model re-runs require the operator's own `GATEWAY_API_KEY` (not released).

## License

Released for reproducibility review of the above manuscript. The gateway credential is not released.
