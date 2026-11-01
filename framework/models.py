"""Data models (stdlib-only: dataclasses)."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Technique(str, Enum):
    prompt_injection = "prompt_injection"
    indirect_injection = "indirect_injection"
    jailbreak = "jailbreak"
    prompt_extraction = "prompt_extraction"
    data_exfiltration = "data_exfiltration"
    tool_abuse = "tool_abuse"
    rag_poisoning = "rag_poisoning"
    output_injection = "output_injection"
    reasoning_dos = "reasoning_dos"
    supply_chain = "supply_chain"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Language(str, Enum):
    zh = "zh"
    en = "en"
    mixed = "mixed"


@dataclass
class AttackPayload:
    id: str
    payload: str
    technique: str  # str(technique_enum.value)
    delivery: str = "direct"
    evasion: str = "none"
    intent: str = "safety_bypass"
    severity: str = "high"
    language: str = "en"
    source: str = "unknown"
    benchmark: Optional[str] = None
    target_keywords: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    notes: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "AttackPayload":
        aliases = {
            "prompt": "payload",
            "attack_type": "technique",
            "modality": "delivery",
        }
        d = dict(d)
        for k, v in aliases.items():
            if k in d and v not in d:
                d[v] = d.pop(k)
        # normalize technique name (allowlist; unknown → keep as-is, don't coerce)
        tech = str(d.get("technique", "prompt_injection"))
        tech_map = {
            "jailbreak": "jailbreak",
            "prompt_injection": "prompt_injection",
            "indirect_injection": "indirect_injection",
            "indirect_prompt_injection": "indirect_injection",
            "prompt_extraction": "prompt_extraction",
            "prompt_leak": "prompt_extraction",
            "data_exfiltration": "data_exfiltration",
            "data_leak": "data_exfiltration",
            "tool_abuse": "tool_abuse",
            "rag_poisoning": "rag_poisoning",
            "output_injection": "output_injection",
            "reasoning_dos": "reasoning_dos",
            "supply_chain": "supply_chain",
        }
        d["technique"] = tech_map.get(tech, tech)  # passthrough, no fallback to prompt_injection
        allowed = set(cls.__dataclass_fields__.keys())
        return cls(**{k: v for k, v in d.items() if k in allowed})

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ModelSpec:
    name: str
    api_key: str
    base_url: str
    model: str
    temperature: float = 0.7
    max_tokens: int = 512

    @classmethod
    def from_dict(cls, d: dict) -> "ModelSpec":
        import os
        d = dict(d)
        # expand ${VAR}
        for k in ("api_key", "base_url"):
            v = d.get(k, "")
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                d[k] = os.environ.get(v[2:-1], "")
        return cls(**{k: v for k, v in d.items()
                      if k in cls.__dataclass_fields__})


@dataclass
class TargetResult:
    model_name: str
    model_id: str
    payload_id: str
    attack_technique: str
    attack_delivery: str
    system_prompt: Optional[str] = None
    user_prompt: str = ""
    output: Optional[str] = None
    latency_ms: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    success: bool = False
    reason: str = ""
    # Dual-verdict support (v0.4): heuristic verdict is always stored;
    # `success`/`reason` hold the final verdict (LLM-judge if available,
    # else heuristic).
    heuristic_success: Optional[bool] = None
    heuristic_reason: str = ""
    judge_success: Optional[bool] = None
    judge_reason: str = ""
    raw_response: Optional[dict] = None
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        d = asdict(self)
        # keep raw_response small in JSON dump
        return d


@dataclass
class EvalSummary:
    run_id: str
    started_at: str
    finished_at: str
    corpora: list[str]
    models: list[str]
    total: int = 0
    success: int = 0
    asr_overall: float = 0.0
    asr_by_technique: dict[str, float] = field(default_factory=dict)
    asr_by_delivery: dict[str, float] = field(default_factory=dict)
    asr_by_severity: dict[str, float] = field(default_factory=dict)
    tokens_in_total: int = 0
    tokens_out_total: int = 0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)
