"""DynamoDB session registry — session state, risk tracking, and detection events.

Implements session lifecycle management for the AgentCore adapter.

Everything here runs on the **inline interceptor path**, so all clients use the
short-timeout ``inline`` profile (see ``vardoger/aws.py``): the dispatcher is
fail-closed, and an AWS call that hangs past the Lambda ceiling blocks a
legitimate user rather than merely slowing them down.

Round trips are deliberately minimized. Reading status and risk used to be two
``get_item`` calls against the same key, and the post-detection state update was
two more ``update_item`` calls against that same item. Both pairs are now single
calls, taking the inline path from five DynamoDB round trips per prompt to
three.
"""
from __future__ import annotations

import logging
import time
from typing import Any
from uuid import uuid4

from vardoger import aws, config
from vardoger.coerce import to_float, to_int
from vardoger.health import DETECTION_EVENTS, ENFORCEMENT, report_degraded

logger = logging.getLogger(__name__)


def _table():
    return aws.table(config.SESSION_TABLE_NAME, kind="inline")


def _events_table():
    return aws.table(config.DETECTION_EVENTS_TABLE_NAME, kind="inline")


def get_session(session_id: str) -> dict[str, Any]:
    """Return the session's status and accumulated risk state in ONE read.

    The dispatcher needs both on every request. Returns a dict with ``status``
    (``"active"``/``"terminated"``/``None``) plus the risk fields; an absent
    record yields ``status=None`` and zeroed risk, which is the correct reading
    for a first-seen session.
    """
    resp = _table().get_item(Key={"session_id": session_id})
    item = resp.get("Item")
    if not item:
        return {
            "status": None,
            "accumulated_risk_score": 0.0,
            "prompts_seen": 0,
            "intent_counts": {},
            "last_risk_epoch": 0.0,
        }
    return {
        "status": item.get("status"),
        "accumulated_risk_score": to_float(item.get("accumulated_risk_score")),
        "prompts_seen": to_int(item.get("prompts_seen")),
        "intent_counts": item.get("intent_counts", {}) or {},
        "last_risk_epoch": to_float(item.get("last_risk_epoch")),
    }


def get_session_status(session_id: str) -> str | None:
    """Return 'active', 'terminated', or None.

    Retained for callers that need only the status. The dispatcher uses
    ``get_session`` instead, to avoid a second read of the same item.
    """
    return get_session(session_id)["status"]


def get_session_risk(session_id: str) -> dict[str, Any]:
    """Load accumulated risk state for a session.

    Retained for callers that need only risk. The dispatcher uses
    ``get_session`` instead. Returns ``{}`` for an unknown session, matching the
    "no prior state" contract the risk scorer expects.
    """
    session = get_session(session_id)
    if session["status"] is None and not session["prompts_seen"]:
        return {}
    return {
        "accumulated_risk_score": session["accumulated_risk_score"],
        "prompts_seen": session["prompts_seen"],
        "intent_counts": session["intent_counts"],
        "last_risk_epoch": session["last_risk_epoch"],
    }


def ensure_session(
    session_id: str,
    agent_runtime_arn: str,
    scope_id: str = "local",
    source: str = "",
) -> None:
    """Create or refresh a session record (idempotent upsert).

    Called before evaluation so the session is recorded even if detection later
    raises and the request fails closed.
    """
    ttl = int(time.time()) + config.SESSION_TTL_MINUTES * 60
    _table().update_item(
        Key={"session_id": session_id},
        UpdateExpression=(
            "SET agent_runtime_arn = if_not_exists(agent_runtime_arn, :arn), "
            "scope_id = if_not_exists(scope_id, :scope), "
            "#src = if_not_exists(#src, :source), "
            "created_at = if_not_exists(created_at, :now), "
            "#ttl_attr = :ttl"
        ),
        ExpressionAttributeNames={"#ttl_attr": "ttl", "#src": "source"},
        ExpressionAttributeValues={
            ":arn": agent_runtime_arn,
            ":scope": scope_id,
            ":source": source,
            ":now": int(time.time()),
            ":ttl": ttl,
        },
    )


def record_session_evaluation(
    session_id: str,
    *,
    accumulated_risk_score: float,
    prompts_seen: int,
    intent_counts: dict[str, int],
    decision: str,
    risk_score: int = 0,
    matched_signature_ids: list[str] | None = None,
) -> None:
    """Persist risk state and the allow/block decision in ONE write.

    These were previously two ``update_item`` calls against the same key
    (``update_session_risk`` then ``mark_session_decision``). Merging them halves
    the post-detection write cost and makes the two updates atomic, so a session
    can no longer be observed with new risk but a stale decision.
    """
    now = int(time.time())
    status = "terminated" if decision == "block" else "active"
    _table().update_item(
        Key={"session_id": session_id},
        UpdateExpression=(
            "SET accumulated_risk_score = :score, prompts_seen = :seen, "
            "intent_counts = :intents, last_risk_epoch = :epoch, "
            "#status = :status, last_decision = :decision, "
            "last_risk_score = :risk_score, last_matched_signatures = :signatures, "
            "last_evaluated_at = :now"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            # Risk values are stored as strings (not Decimal) to match the
            # existing item shape; changing the stored type would break readers.
            ":score": str(accumulated_risk_score),
            ":seen": prompts_seen,
            ":intents": intent_counts,
            ":epoch": str(time.time()),
            ":status": status,
            ":decision": decision,
            ":risk_score": risk_score,
            ":signatures": matched_signature_ids or [],
            ":now": now,
        },
    )


def update_session_risk(
    session_id: str,
    accumulated_risk_score: float,
    prompts_seen: int,
    intent_counts: dict[str, int],
) -> None:
    """Persist updated risk state only.

    Retained for callers that update risk without a decision. The dispatcher
    uses ``record_session_evaluation`` to do both in one write.
    """
    _table().update_item(
        Key={"session_id": session_id},
        UpdateExpression=(
            "SET accumulated_risk_score = :score, prompts_seen = :seen, "
            "intent_counts = :intents, last_risk_epoch = :epoch"
        ),
        ExpressionAttributeValues={
            ":score": str(accumulated_risk_score),
            ":seen": prompts_seen,
            ":intents": intent_counts,
            ":epoch": str(time.time()),
        },
    )


def mark_session_decision(
    session_id: str,
    decision: str,
    risk_score: int = 0,
    matched_signature_ids: list[str] | None = None,
) -> None:
    """Record the latest allow/block decision only.

    Retained for the enforcement handler, which marks a decision without having
    recomputed risk.
    """
    now = int(time.time())
    status = "terminated" if decision == "block" else "active"
    _table().update_item(
        Key={"session_id": session_id},
        UpdateExpression=(
            "SET #status = :status, last_decision = :decision, "
            "last_risk_score = :risk_score, last_matched_signatures = :signatures, "
            "last_evaluated_at = :now"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": status,
            ":decision": decision,
            ":risk_score": risk_score,
            ":signatures": matched_signature_ids or [],
            ":now": now,
        },
    )


def record_kill_outcome(
    session_id: str,
    outcome: str,
    runtime_session_id: str = "",
) -> None:
    """Record what the session kill actually did.

    Without this the outcome lived only in the SQS alert message, so nothing an
    operator can query knew whether StopRuntimeSession succeeded, was refused,
    or was never attempted. "Session terminated" and "we asked AWS to terminate
    the session and it declined" are very different facts, and they were
    indistinguishable.

    Written twice per kill by design: once by the dispatcher with the outcome it
    has when it returns (including ``deferred``), then again by the alert Lambda
    with the real result. A row still reading ``deferred`` long after the fact
    therefore means the deferred kill never ran -- which is itself the signal.

    Best-effort: failing to record the outcome must not change what the kill
    did. Reported as degraded so a silently missing outcome is visible.
    """
    now = int(time.time())
    try:
        _table().update_item(
            Key={"session_id": session_id},
            UpdateExpression=(
                "SET kill_outcome = :outcome, kill_outcome_at = :now"
                ", kill_runtime_session_id = :rt"
            ),
            ExpressionAttributeValues={
                ":outcome": outcome,
                ":now": now,
                ":rt": runtime_session_id or session_id,
            },
        )
    except Exception as exc:
        logger.exception("Failed to record kill outcome for session %s", session_id)
        report_degraded(
            ENFORCEMENT,
            f"kill outcome write failed: {type(exc).__name__}",
            session_id=session_id,
        )


def record_detection_event(
    session_id: str,
    scope_id: str,
    source: str,
    decision: str,
    risk_score: int = 0,
    matched_signature_ids: list[str] | None = None,
    attack_intents: list[str] | None = None,
    matched_policy_rules: list[str] | None = None,
) -> None:
    """Write a durable detection event for audit/compliance.

    Best-effort: an audit-write failure must not block the detection path. It is
    reported as degraded so a silently-empty audit trail is visible.
    """
    now = int(time.time())
    retention_seconds = config.DETECTION_RETENTION_DAYS * 24 * 3600
    item = {
        "event_id": f"{now}-{uuid4().hex}",
        "event_ts": now,
        "ttl": now + retention_seconds,
        "session_id": session_id,
        "scope_id": scope_id,
        "source": source,
        "decision": decision,
        "risk_score": risk_score,
        "matched_signatures": matched_signature_ids or [],
        "attack_intents": attack_intents or [],
        "matched_policy_rules": matched_policy_rules or [],
    }
    try:
        _events_table().put_item(Item=item)
    except Exception as exc:
        logger.exception("Failed to record detection event")
        report_degraded(
            DETECTION_EVENTS,
            f"detection event write failed: {type(exc).__name__}",
            session_id=session_id,
        )
