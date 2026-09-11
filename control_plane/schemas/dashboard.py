"""Dashboard response models."""
from __future__ import annotations

from pydantic import BaseModel


class SessionInfo(BaseModel):
    session_id: str
    created_at: int = 0
    scope_id: str = ""
    source: str = ""
    status: str = "active"
    last_decision: str = ""
    last_risk_score: int = 0
    last_matched_signatures: list[str] = []
    last_evaluated_at: int = 0


class SessionSummary(BaseModel):
    active_count: int
    terminated_count: int
    active_sessions: list[SessionInfo] = []
    terminated_sessions: list[SessionInfo] = []


class DetectionEvent(BaseModel):
    timestamp: str
    session_id: str
    decision: str
    matched_signatures: list[str] = []
    risk_score: int = 0
    attack_intents: list[str] = []
    matched_policy_rules: list[str] = []


class TimelinePoint(BaseModel):
    timestamp: str
    detection_count: int
    block_count: int = 0
    allow_count: int = 0


class CategoryBreakdown(BaseModel):
    category: str
    count: int
    percentage: float = 0.0


class SignatureHit(BaseModel):
    signature_id: str
    category: str = ""
    hit_count: int = 0
    last_seen: str = ""


class Tier3Finding(BaseModel):
    event_id: str = ""
    timestamp: str = ""
    scope_id: str = ""
    # source = "<aws_account_id>/<agent>" segmentation attribute. A Tier 3
    # finding can span multiple sources within the scope (see affected_sources).
    source: str = ""
    # provenance holds the OLD meaning of "source" (e.g. "tier3").
    provenance: str = "tier3"
    affected_sources: list[str] = []
    burst_id: str = ""
    category: str = ""
    attack_style: str = ""
    confidence: float = 0.0
    affected_session_count: int = 0
    affected_sessions: list[str] = []
    example_prompt_ids: list[str] = []
    similarity_method: str = ""
    threshold_used: str = ""
    action_taken: str = ""
    kill_triggered: bool = False
    model_version: str = ""


class DashboardSummary(BaseModel):
    """Every dashboard panel in one response.

    Exists so the SPA can render the dashboard from a single request instead of
    six concurrent ones, each of which scanned the same table. Field values are
    identical to the corresponding standalone endpoints.
    """

    sessions: SessionSummary
    detections: list[DetectionEvent] = []
    timeline: list[TimelinePoint] = []
    categories: list[CategoryBreakdown] = []
    signatures: list[SignatureHit] = []
    tier3_findings: list[Tier3Finding] = []
