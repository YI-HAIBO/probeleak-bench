# Release v1.0

Initial public release of the ProbeLeak-Bench evidence artifact set.

## Contents

- 35 frozen attack probes with class, protocol-family, schema-dependence and difficulty-tier metadata
- Experiment framework (`framework/`)
- Experiment scripts (`experiments/`), including the no-credential synthetic pipeline (`experiments/p2_synthetic_demo.py`)
- Stored JSON result artifacts (`artifacts/`)
- Provenance map from every reported value to its artifact field (`docs/provenance.md`)
- `MANIFEST.sha256`

The full bundle is browsable directly in this repository and is also
packaged as `probeleak-bench-v1.0.zip` (downloadable from the v1.0
release).

## Reproducibility

Every number in the manuscript is regenerated from `artifacts/` by the
report and figure generators; a regeneration that differs from the stored
artifact fails loudly. Simulation experiments use fixed seeds and are
exactly reproducible. The no-credential synthetic run replays the full
pipeline without a gateway credential.

## Security note (v1.0)

All shipped keys are synthetic `FAKE_`-prefixed honeypot values. No real
gateway credential is present in any file. The secret-audit script
(`experiments/release_secret_scan.py`) ships with its known-credential
list redacted, so the audit tool remains usable while no real secret is
committed.
