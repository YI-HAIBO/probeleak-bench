# Changelog

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
