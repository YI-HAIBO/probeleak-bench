"""CLI (stdlib: argparse).

Usage:
    python -m llm_attack_eval.cli list corpora/
    python -m llm_attack_eval.cli run -c configs/default.yaml -k corpora/ -o results/ --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .corpus import load_directory, sample as corpus_sample, technique_counts
from .engine import evaluate
from .models import ModelSpec
from .report import write_csv, write_json, write_markdown


def _load_models(cfg: dict) -> list[ModelSpec]:
    return [ModelSpec.from_dict(m) for m in cfg.get("models", [])]


def _filter(payloads, only: list[str] | None):
    if not only:
        return payloads
    keep = set(only)
    return [p for p in payloads if p.technique in keep]


def _parse_yaml_lite(text: str) -> dict:
    """Very small YAML-subset parser for our default config.

    Only supports: nested dicts, list of dicts, `${VAR}` env expansion (handled
    in ModelSpec.from_dict), inline strings/numbers/booleans.
    If PyYAML is available we use it; otherwise we fall back to a tiny parser
    that covers the shipped `configs/default.yaml`.
    """
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except Exception:
        pass
    # Minimal fallback: parse a subset. Not general YAML.
    root: dict = {}
    stack: list[tuple[int, object]] = [(0, root)]
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, _, rest = stripped.partition(":")
        key = key.strip()
        rest = rest.strip()
        # pop stack to current indent
        while stack and indent < stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if not isinstance(parent, dict):
            i += 1
            continue
        if rest == "":
            # look ahead for list-of-dicts or empty dict
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or lines[j].strip().startswith("#")):
                j += 1
            if j < len(lines) and lines[j].lstrip().startswith("- "):
                # list
                lst = []
                cur: dict | None = None
                parent[key] = lst
                while j < len(lines):
                    ln = lines[j]
                    ss = ln.strip()
                    if not ss or ss.startswith("#"):
                        j += 1
                        continue
                    ind = len(ln) - len(ln.lstrip(" "))
                    if ind <= indent:
                        break
                    if ss.startswith("- "):
                        cur = {}
                        lst.append(cur)
                        first_line = ss[2:].strip()
                        if ":" in first_line:
                            k, _, v = first_line.partition(":")
                            cur[k.strip()] = _coerce(v.strip())
                    elif cur is not None and ":" in ss:
                        k, _, v = ss.partition(":")
                        cur[k.strip()] = _coerce(v.strip())
                    j += 1
                i = j
                continue
            else:
                parent[key] = {}
                stack.append((indent + 2, parent[key]))
                i += 1
                continue
        else:
            parent[key] = _coerce(rest)
        i += 1
    return root


def _coerce(v: str):
    if v in ("true", "True"):
        return True
    if v in ("false", "False"):
        return False
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    # strip surrounding quotes
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v


def cmd_list(args):
    items = _load_payloads(Path(args.corpora))
    print(f"Found {len(items)} payloads in {args.corpora}")
    for k, v in sorted(technique_counts(items).items(), key=lambda x: -x[1]):
        print(f"  {k:25s}  {v}")


def _load_payloads(path: Path) -> list:
    """Load payloads from a directory OR a single .jsonl file."""
    from .corpus import load_jsonl
    if path.is_file():
        return load_jsonl(path)
    return load_directory(path)


def cmd_run(args):
    cfg_text = Path(args.config).read_text(encoding="utf-8")
    cfg = _parse_yaml_lite(cfg_text)
    models = _load_models(cfg)
    payloads = _filter(_load_payloads(Path(args.corpora)), args.only)
    if args.sample:
        payloads = corpus_sample(payloads, args.sample, seed=int(cfg.get("seed", 0)))
    print(f"Loaded {len(payloads)} payloads x {len(models)} models = {len(payloads) * len(models)} probes")

    if args.dry_run:
        print("Dry run - no API calls made.")
        for m in models:
            key = m.api_key[:4] + "..." if m.api_key else "<EMPTY>"
            print(f"  model={m.model:30s} base_url={m.base_url} key={key}")
        return

    use_judge = bool(args.judge)
    if use_judge and "judge" in cfg:
        judge_spec = ModelSpec.from_dict(cfg["judge"])
    else:
        judge_spec = None

    def on_result(r):
        print(f"  {r.model_name:25s} {r.payload_id:12s} success={r.success} {r.reason[:40]}")

    results, summary = evaluate(
        payloads, models,
        concurrency=args.concurrency,
        system_prompt=args.system,
        use_judge=use_judge,
        judge_spec=judge_spec,
        on_result=on_result,
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    jp = out / f"run_{summary.run_id}.json"
    cp = out / f"run_{summary.run_id}.csv"
    mp = out / f"run_{summary.run_id}.md"
    write_json(results, summary, jp)
    write_csv(results, summary, cp)
    write_markdown(results, summary, mp)
    # (report API accepts summary in signature for consistency)
    print(f"Done ASR={summary.asr_overall:.3f}")
    print(f"  JSON: {jp}")
    print(f"  CSV : {cp}")
    print(f"  MD  : {mp}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llm-eval", description="LLM attack evaluation CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="List payloads in a corpora dir")
    pl.add_argument("corpora")
    pl.set_defaults(func=cmd_list)

    pr = sub.add_parser("run", help="Run evaluation")
    pr.add_argument("-c", "--config", required=True)
    pr.add_argument("-k", "--corpora", required=True)
    pr.add_argument("-o", "--out", required=True)
    pr.add_argument("-n", "--sample", type=int, default=None)
    pr.add_argument("--only", nargs="*", default=None, help="Technique whitelist")
    pr.add_argument("-C", "--concurrency", type=int, default=4)
    pr.add_argument("--judge", action="store_true", help="Use LLM judge")
    pr.add_argument("--system", default=None, help="Override system prompt")
    pr.add_argument("--dry-run", action="store_true", help="Parse config only")
    pr.set_defaults(func=cmd_run)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
