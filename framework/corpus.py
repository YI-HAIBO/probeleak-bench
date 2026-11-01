"""Attack corpus loaders (stdlib-only)."""
from __future__ import annotations

import json
from pathlib import Path

from .models import AttackPayload


def load_jsonl(path: Path) -> list[AttackPayload]:
    items: list[AttackPayload] = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                items.append(AttackPayload.from_dict(json.loads(line)))
            except Exception as e:
                raise ValueError(f"Line {i} in {path} failed: {e}") from e
    return items


def load_directory(corpora_dir: Path) -> list[AttackPayload]:
    items: list[AttackPayload] = []
    for p in sorted(Path(corpora_dir).glob("*.jsonl")):
        items.extend(load_jsonl(p))
    return items


def sample(items: list[AttackPayload], n: int, seed: int = 0) -> list[AttackPayload]:
    """Stratified deterministic sample by technique."""
    import random
    rng = random.Random(seed)
    by_t: dict[str, list[AttackPayload]] = {}
    for it in items:
        by_t.setdefault(it.technique, []).append(it)
    out: list[AttackPayload] = []
    per = max(1, int(n / max(1, len(by_t))))
    for _, lst in by_t.items():
        out.extend(rng.sample(lst, min(per, len(lst))))
    rng.shuffle(out)
    return out[:n]


def technique_counts(items: list[AttackPayload]) -> dict[str, int]:
    c: dict[str, int] = {}
    for p in items:
        c[p.technique] = c.get(p.technique, 0) + 1
    return c
