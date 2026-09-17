"""Dedicated enforcement Lambda for asynchronous (Tier 2 / Tier 3) kills.

Tier 2 and Tier 3 detect malicious sessions out of band and ask for the live
agent session to be terminated. They invoke THIS handler (not the gateway
dispatcher) with a flat enforcement request::

    {
        "action": "terminate",
        "session_id": "...",
        "runtime_session_id": "...",      # the real AgentCore runtime session
        "agent_runtime_arn": "arn:aws:bedrock-agentcore:...",
        "scope_id": "local",
        "source": "<account>/<agent>",
        "matched_signature_ids": [...],
        "risk_score": 12,
        "attack_intents": [...],
        "matched_policy_rules": [...],
        "detection_source": "tier2_ml" | "tier3",
        "reason": "..."
    }

It validates the request, calls ``StopRuntimeSession`` against the supplied
runtime session id, marks the session terminated, and records a durable
detection event. The precise kill outcome (confirmed / unverified / failed) is
returned and logged so an unverified kill is never silently reported as success.
"""
from __future__ import annotations

import logging
from typing import Any

from adapters.agentcore import enforcement
from adapters.agentcore.session_registry import (
    mark_session_decision,
    record_detection_event,
)
from vardoger.logging_setup import configure_logging

logger = logging.getLogger(__name__)
# Applies VARDOGER_LOG_LEVEL. Without this the runtime's own root level
# applies and every INFO line is dropped, leaving the log group empty.
configure_logging()

_VALID_ACTIONS = frozenset({"terminate"})


def _process_one(request: dict[str, Any]) -> dict[str, Any]:
    """Validate and execute a single enforcement request."""
    action = str(request.get("action") or "").strip().lower()
    if action not in _VALID_ACTIONS:
        raise ValueError(f"Unsupported enforcement action {action!r}; expected 'terminate'")

    session_id = str(request.get("session_id") or "").strip()
    agent_runtime_arn = str(request.get("agent_runtime_arn") or "").strip()
    if not session_id:
        raise ValueError("Enforcement request missing session_id")
    if not agent_runtime_arn:
        raise ValueError("Enforcement request missing agent_runtime_arn")

    runtime_session_id = str(request.get("runtime_session_id") or "").strip()
    scope_id = str(request.get("scope_id") or "local").strip() or "local"
    source = str(request.get("source") or "").strip()
    matched_signature_ids = request.get("matched_signature_ids") or []
    attack_intents = request.get("attack_intents") or []
    matched_policy_rules = request.get("matched_policy_rules") or []
    risk_score = int(request.get("risk_score") or 0)
    detection_source = str(request.get("detection_source") or "async").strip()
    reason = str(request.get("reason") or detection_source or "async detection")

    outcome = enforcement.terminate_session_detailed(
        session_id=session_id,
        agent_runtime_arn=agent_runtime_arn,
        reason=reason,
        runtime_session_id=runtime_session_id,
    )

    # Persist the decision and a durable audit event regardless of outcome; the
    # session is blocked either way, and the outcome is recorded for triage.
    try:
        mark_session_decision(
            session_id=session_id,
            decision="block",
            risk_score=risk_score,
            matched_signature_ids=list(matched_signature_ids),
        )
    except Exception:
        logger.exception("Failed to mark session decision for %s", session_id)

    record_detection_event(
        session_id=session_id,
        scope_id=scope_id,
        source=source,
        decision="block",
        risk_score=risk_score,
        matched_signature_ids=list(matched_signature_ids),
        attack_intents=list(attack_intents),
        matched_policy_rules=list(matched_policy_rules),
    )

    logger.info(
        "Enforcement processed: session_id=%s detection_source=%s outcome=%s",
        session_id,
        detection_source,
        outcome,
    )
    return {"session_id": session_id, "outcome": outcome, "detection_source": detection_source}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Enforcement entry point for Tier 2 / Tier 3 asynchronous kills.

    Accepts either a single enforcement request or a batch under a ``requests``
    key. Fails closed on validation errors (raises) so a malformed request is
    surfaced rather than silently dropped.
    """
    if not isinstance(event, dict):
        raise ValueError("Enforcement handler requires a dict event")

    requests = event.get("requests")
    if isinstance(requests, list):
        results = [_process_one(r) for r in requests if isinstance(r, dict)]
        return {"processed": len(results), "results": results}

    result = _process_one(event)
    return {"processed": 1, "results": [result]}
