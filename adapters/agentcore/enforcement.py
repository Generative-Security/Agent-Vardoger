"""AgentCore session termination — calls StopRuntimeSession.

Implements session killing for AWS Bedrock AgentCore Gateway.
"""
from __future__ import annotations

import hashlib
import logging

from botocore.exceptions import BotoCoreError, ClientError, ParamValidationError

from vardoger import aws
from vardoger.health import ENFORCEMENT, report_degraded

logger = logging.getLogger(__name__)


# Outcome of a StopRuntimeSession attempt. "unverified" means AWS reported the
# runtime session did not exist (ResourceNotFoundException): we could neither
# confirm a live session was stopped nor that our session-id mapping was
# correct, so callers must NOT treat it as a confirmed kill.
TERMINATE_CONFIRMED = "confirmed"
TERMINATE_UNVERIFIED = "unverified"
TERMINATE_FAILED = "failed"
# The kill was handed to the alert queue rather than executed inline, so the
# agent can finish answering the triggering prompt first (Tier 1 sidecar mode).
# Distinct from "confirmed": at the time the dispatcher returned, no
# StopRuntimeSession call had been made yet. The session is already recorded as
# terminated in the registry, so the next prompt on it is refused regardless.
TERMINATE_DEFERRED = "deferred"


def _default_runtime_session_id(session_id: str) -> str:
    """Return the AgentCore runtime session ID used by the sandbox chat target.

    This is a *fallback* mapping for the bundled chat-target convention. When a
    caller already knows the real runtime session id (e.g. Tier 2/3, which read
    it from the session registry), it should pass ``runtime_session_id``
    explicitly rather than rely on this derivation.
    """
    if not session_id or len(session_id) >= 33:
        return session_id
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return f"vardoger-chat-{digest}"


def terminate_session_detailed(
    session_id: str,
    agent_runtime_arn: str,
    reason: str = "Security detection",
    runtime_session_id: str = "",
) -> str:
    """Call StopRuntimeSession and report a precise outcome.

    Returns one of ``TERMINATE_CONFIRMED``, ``TERMINATE_UNVERIFIED``, or
    ``TERMINATE_FAILED``. ``ResourceNotFoundException`` maps to *unverified*
    rather than success: a nonexistent runtime session can mean the session is
    genuinely gone OR that our mcp->runtime session mapping is wrong, and a
    security product must not silently log the latter as a kill.
    """
    if not agent_runtime_arn:
        logger.error("No agent_runtime_arn for session %s; cannot terminate", session_id)
        return TERMINATE_FAILED

    # Prefer an explicitly supplied runtime session id; fall back to the
    # sandbox derivation only when none was provided.
    effective_runtime_session_id = (runtime_session_id or "").strip() or _default_runtime_session_id(session_id)
    # Inline profile: the kill happens inside the interceptor, which is
    # fail-closed — a hung StopRuntimeSession must not burn the budget.
    client = aws.client("bedrock-agentcore", kind="inline")
    try:
        client.stop_runtime_session(
            agentRuntimeArn=agent_runtime_arn,
            runtimeSessionId=effective_runtime_session_id,
        )
        logger.info("Session terminated: runtime_session_id=%s reason=%s", effective_runtime_session_id, reason)
        return TERMINATE_CONFIRMED
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ResourceNotFoundException":
            logger.warning(
                "StopRuntimeSession: runtime session not found (session_id=%s runtime_session_id=%s). "
                "Treating as UNVERIFIED, not a confirmed kill.",
                session_id,
                effective_runtime_session_id,
            )
            return TERMINATE_UNVERIFIED
        logger.error("Failed to terminate session %s: %s", session_id, exc)
        report_degraded(ENFORCEMENT, f"StopRuntimeSession failed: {type(exc).__name__}", session_id=session_id)
        return TERMINATE_FAILED
    except (BotoCoreError, ParamValidationError, ValueError) as exc:
        logger.error("Failed to terminate session %s: %s", session_id, exc)
        report_degraded(ENFORCEMENT, f"StopRuntimeSession failed: {type(exc).__name__}", session_id=session_id)
        return TERMINATE_FAILED


def terminate_session(
    session_id: str,
    agent_runtime_arn: str,
    reason: str = "Security detection",
    runtime_session_id: str = "",
) -> bool:
    """Backwards-compatible wrapper around :func:`terminate_session_detailed`.

    Returns True when the stop call succeeded OR the runtime session was already
    gone (unverified). Prefer :func:`terminate_session_detailed` when the
    caller needs to distinguish a confirmed kill from an unverified one.
    """
    outcome = terminate_session_detailed(
        session_id=session_id,
        agent_runtime_arn=agent_runtime_arn,
        reason=reason,
        runtime_session_id=runtime_session_id,
    )
    return outcome in (TERMINATE_CONFIRMED, TERMINATE_UNVERIFIED)
