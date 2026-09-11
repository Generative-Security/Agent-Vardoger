"""Data models for detection results, signatures, and risk state.

These are pure data classes with no infrastructure dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RegexPattern:
    """A single regex-based detection signature."""

    id: str
    severity: str
    category: str
    pattern: str
    mitre_atlas_id: str = ""
    description: str = ""
    author: str = ""


@dataclass
class HashLookup:
    """A known-malicious prompt identified by its SHA-256 hash."""

    id: str
    severity: str
    category: str
    hash: str


@dataclass
class PolicyMatch:
    """A single detection policy rule match with its severity and score."""

    rule_id: str
    category: str
    severity: str
    score: int
    matched_terms: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class DetectionPolicyResult:
    """Aggregated result from the detection policy evaluation pass."""

    customer_state: str
    decision: str
    risk_score: int
    risk_bucket: str
    risk_recommendation: str
    risk_signals: list[str]
    matched_policy_rules: list[str]
    matched_terms: list[str]
    critical_signal: bool
    escalation_required: bool
    escalation_reason: str | None
    safe_intent: bool
    debug_trace: dict[str, Any] = field(default_factory=dict)


@dataclass
class PromptNormalizationResult:
    """Output of prompt normalization including corrected and compact forms."""

    raw_prompt: str
    normalized_prompt: str
    compact_prompt: str
    corrected_prompt: str
    canonical_features: list[str] = field(default_factory=list)
    detected_language_hints: list[str] = field(default_factory=list)
    typo_corrections: list[dict[str, str]] = field(default_factory=list)
    phrase_canonicalizations: list[dict[str, str]] = field(default_factory=list)


@dataclass
class SessionRiskState:
    """Accumulated risk state for a session across multiple prompts."""

    score: float = 0.0
    last_seen_epoch: float = 0.0
    prompts_seen: int = 0
    intent_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    """Final detection verdict combining signature, hash, policy, and risk results."""

    decision: str
    matched_signature_ids: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_bucket: str = "low"
    risk_signals: list[str] = field(default_factory=list)
    risk_recommendation: str = "allow"
    session_risk_score: int = 0
    session_risk_bucket: str = "low"
    session_risk_recommendation: str = "allow"
    attack_intents: list[str] = field(default_factory=list)
    session_signal_counts: dict[str, int] = field(default_factory=dict)
    matched_policy_rules: list[str] = field(default_factory=list)
    matched_terms: list[str] = field(default_factory=list)
    critical_signal: bool = False
    escalation_reason: str = ""
    detection_debug_trace: dict[str, Any] = field(default_factory=dict)
