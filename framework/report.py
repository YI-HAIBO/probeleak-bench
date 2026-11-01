"""Report writers: JSON / CSV / Markdown (stdlib-only)."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import EvalSummary, TargetResult


def write_json(results: list[TargetResult], summary: EvalSummary, out: Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(
            {"summary": summary.to_dict(), "results": [r.to_dict() for r in results]},
            f, ensure_ascii=False, indent=2,
        )
    return out


def write_csv(results: list[TargetResult], summary: EvalSummary, out: Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["model_name", "payload_id", "attack_technique", "attack_delivery",
              "success", "reason", "latency_ms", "tokens_in", "tokens_out"]
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = {k: getattr(r, k) for k in fields}
            w.writerow(row)
    return out


def write_markdown(results: list[TargetResult], summary: EvalSummary, out: Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    L: list[str] = []
    L.append("# LLM Attack Evaluation Report")
    L.append("")
    L.append(f"- **Run ID**: `{summary.run_id}`")
    L.append(f"- **Started**: {summary.started_at}")
    L.append(f"- **Finished**: {summary.finished_at}")
    L.append(f"- **Models**: {', '.join(summary.models) or '(none)'}")
    L.append(f"- **Corpora**: {', '.join(summary.corpora) or '(none)'}")
    L.append("")
    L.append("## Overall")
    L.append("")
    L.append(f"- Total probes: **{summary.total}**")
    L.append(f"- Successful attacks: **{summary.success}**")
    L.append(f"- Overall ASR: **{summary.asr_overall:.3f}**")
    L.append(f"- Tokens in / out: **{summary.tokens_in_total} / {summary.tokens_out_total}**")
    L.append(f"- Latency p50 / p95 (ms): **{summary.latency_p50_ms:.0f} / {summary.latency_p95_ms:.0f}**")
    L.append("")
    L.append("## ASR by technique")
    L.append("")
    L.append("| Technique | ASR |")
    L.append("| --- | --- |")
    for k, v in sorted(summary.asr_by_technique.items(), key=lambda x: -x[1]):
        L.append(f"| `{k}` | {v:.3f} |")
    L.append("")
    L.append("## ASR by delivery")
    L.append("")
    L.append("| Delivery | ASR |")
    L.append("| --- | --- |")
    for k, v in sorted(summary.asr_by_delivery.items(), key=lambda x: -x[1]):
        L.append(f"| `{k}` | {v:.3f} |")
    L.append("")
    L.append("## ASR by severity")
    L.append("")
    L.append("| Severity | ASR |")
    L.append("| --- | --- |")
    for k, v in summary.asr_by_severity.items():
        L.append(f"| `{k}` | {v:.3f} |")
    L.append("")
    L.append("## Sample successful attacks (up to 20)")
    L.append("")
    shown = 0
    for r in results:
        if not r.success:
            continue
        L.append(f"- **{r.model_name}** / `{r.payload_id}` / `{r.attack_technique}`")
        L.append(f"  - prompt: `{(r.user_prompt or '')[:120]}`")
        L.append(f"  - output: `{(r.output or '')[:200]}`")
        L.append(f"  - reason: {r.reason}")
        shown += 1
        if shown >= 20:
            break
    out.write_text("\n".join(L), encoding="utf-8")
    return out
