"""Prompt history response models."""
from __future__ import annotations

from pydantic import BaseModel


class PromptHistoryRecord(BaseModel):
    scope_id: str = ""
    source: str = ""
    session_id: str = ""
    prompt_id: str = ""
    timestamp: str = ""
    prompt: str = ""
    decision: str = ""
    risk_score: int = 0
    matched_signatures: list[str] = []
    attack_intents: list[str] = []
    matched_policy_rules: list[str] = []
    prompt_length: int = 0
    agent_runtime_arn: str = ""
    ingested_at: int = 0
    tier2_status: str = ""
    tier2_label: str = ""
    tier2_confidence: float = 0.0
    tier2_suspicious: bool = False
    tier2_risk_score: float = 0.0
    tier2_prompt_score: float = 0.0
    tier2_session_score_after: float = 0.0
    tier2_category: str = ""
    tier2_ml_verdict: str = ""
    tier2_action_taken: str = ""
    tier2_threshold_used: str = ""
    tier2_kill_triggered: bool = False
    tier2_safe_intent_reason: str = ""
    tier2_error: str = ""


class PromptHistoryResponse(BaseModel):
    records: list[PromptHistoryRecord] = []
    count: int = 0
    scanned_count: int = 0
    warning: str = ""
