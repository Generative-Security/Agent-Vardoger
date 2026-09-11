"""Response/request models for management endpoints (sources, policy,
signatures, evaluation, managed-upgrade)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SourcesResponse(BaseModel):
    scope_id: str = ""
    sources: list[str] = []
    count: int = 0


# Enforcement mode is an enum, not a free string, so a typo can't silently
# disable protection or slip past the mode check.
PolicyMode = Literal["off", "shadow", "enforce"]


class SecurityPolicy(BaseModel):
    """Tier 2 / Tier 3 policy for the scope. Mirrors the fields used by
    vardoger/tier2/handler.py DEFAULT_TENANT_POLICY and the tier3 policy.

    Bounds are enforced so a single admin PUT cannot configure a total
    agent-DoS (e.g. kill_threshold=0, min_sessions=0 in enforce mode). Kill
    thresholds are floored to sane minimums rather than allowed down to 0.
    """

    # Tier 2
    tier2_mode: PolicyMode = "shadow"
    tier2_default_kill_threshold: float = Field(default=0.97, ge=0.5, le=1.0)
    tier2_high_risk_threshold: float = Field(default=0.85, ge=0.5, le=1.0)
    tier2_require_repeated_malicious: bool = True
    tier2_min_malicious_verdicts_for_kill: int = Field(default=2, ge=1, le=100)
    tier2_allow_single_verdict_kill_threshold: float = Field(default=0.99, ge=0.5, le=1.0)
    # Tier 3
    tier3_mode: PolicyMode = "shadow"
    tier3_min_sessions_for_kill: int = Field(default=3, ge=1, le=1000)
    tier3_similarity_threshold: float = Field(default=0.90, ge=0.5, le=1.0)
    tier3_kill_threshold: float = Field(default=0.95, ge=0.5, le=1.0)
    # Metadata. policy_version is server-owned (incremented on write); a value
    # supplied by the client is ignored — see policy_service.put_policy.
    policy_version: int = 1
    updated_by: str = ""
    updated_at: int = 0


class SignaturesResponse(BaseModel):
    community_count: int = 0
    categories: list[str] = []
    premium_enabled: bool = False
    marketplace_link: str = ""
    aws_account_id: str = ""


class CustomSignatureRequest(BaseModel):
    signature_id: str = Field(default="", max_length=128)
    category: str = Field(default="", max_length=64)
    # Cap the pattern length: an unbounded regex in the inline interceptor is a
    # ReDoS/latency risk. The service also compiles it and screens for
    # catastrophic backtracking before storing.
    pattern: str = Field(default="", max_length=1000)
    severity: str = Field(default="medium", max_length=16)
    description: str = Field(default="", max_length=500)


class CustomSignatureResponse(BaseModel):
    # True on any 200 response: a write that failed now returns 503, and a
    # pattern that failed validation returns 400, so this endpoint no longer
    # reports a non-event as success.
    stored: bool = False
    signature_id: str = ""
    scope_id: str = ""
    store: str = ""
    # Populated when the signature was rejected (bad regex / ReDoS risk).
    error: str = ""
    # Custom signatures ARE loaded by the inline interceptor (append-only,
    # scope-keyed). True once stored; the rule goes live after the scanner
    # refresh interval on warm containers, or immediately on the next cold
    # start. `note` carries that timing detail for the UI.
    enforced: bool = False
    note: str = ""


class EvaluationSummary(BaseModel):
    scope_id: str = ""
    true_positive: int = 0
    true_negative: int = 0
    false_positive: int = 0
    false_negative: int = 0
    unknown: int = 0
    total: int = 0


class EvaluationRunResponse(BaseModel):
    status: str = "accepted"
    run_id: str = ""
    detail: str = ""


class ManagedUpgradeInfo(BaseModel):
    telemetry_mode: str = ""
    handoff_text: str = ""
    intake_url: str = ""
    intent_recorded: bool = False
    instructions: str = ""
