"""Evaluation engine: run corpus × models, compute metrics (stdlib-only)."""
from __future__ import annotations

import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

from .models import AttackPayload, EvalSummary, ModelSpec, TargetResult
from .runner import OpenAICompat, run_probe


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def percentile(vals: list[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(round((len(s) - 1) * p))))
    return s[k]


def evaluate(
    payloads: Iterable[AttackPayload],
    specs: list[ModelSpec],
    *,
    concurrency: int = 4,
    system_prompt: Optional[str] = None,
    use_judge: bool = False,
    judge_spec: Optional[ModelSpec] = None,
    on_result: Optional[Callable[[TargetResult], None]] = None,
    corpora_names: Optional[list[str]] = None,
    client_factory=None,
) -> tuple[list[TargetResult], EvalSummary]:
    payloads = list(payloads)
    specs = list(specs)
    judge_client = OpenAICompat(judge_spec) if (use_judge and judge_spec) else None

    results: list[TargetResult] = []
    run_id = uuid.uuid4().hex[:10]
    started = _now()

    jobs = [(spec, p) for spec in specs for p in payloads]
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futures = [
            ex.submit(run_probe, spec, p, system_prompt, judge_client, client_factory)
            for spec, p in jobs
        ]
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            if on_result:
                on_result(r)

    total = len(results)
    success = sum(1 for r in results if r.success)
    lat = [r.latency_ms for r in results]

    def rate_by(key):
        bucket: dict[str, list[bool]] = defaultdict(list)
        for r in results:
            bucket[key(r)].append(r.success)
        return {k: sum(v) / len(v) for k, v in bucket.items()}

    asr_by_tech = rate_by(lambda r: r.attack_technique)
    asr_by_del = rate_by(lambda r: r.attack_delivery)

    sev_map = {p.id: p.severity for p in payloads}
    bucket_sev: dict[str, list[bool]] = defaultdict(list)
    for r in results:
        bucket_sev[sev_map.get(r.payload_id, "unknown")].append(r.success)
    asr_by_sev = {k: sum(v) / len(v) for k, v in bucket_sev.items()}

    summary = EvalSummary(
        run_id=run_id,
        started_at=started,
        finished_at=_now(),
        corpora=corpora_names or ["inline"],
        models=[s.model for s in specs],
        total=total,
        success=success,
        asr_overall=(success / total) if total else 0.0,
        asr_by_technique=asr_by_tech,
        asr_by_delivery=asr_by_del,
        asr_by_severity=asr_by_sev,
        tokens_in_total=sum(r.tokens_in for r in results),
        tokens_out_total=sum(r.tokens_out for r in results),
        latency_p50_ms=percentile(lat, 0.50),
        latency_p95_ms=percentile(lat, 0.95),
    )
    return results, summary
