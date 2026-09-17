"""AgentCore Gateway dispatcher Lambda handler.

The main REQUEST interceptor entry point. Parses the event, runs detection, and
decides what the gateway does with the request.

ARCHITECTURE: Tier 1 is a SIDECAR, not a gate (config.TIER1_MODE, default
"sidecar"). On a detection it terminates the SESSION and lets the triggering
prompt through — every tier then converges on one lever, session termination,
and a security component that is wrong or broken cannot refuse the agent's
traffic. Set TIER1_MODE="gate" to also refuse the triggering prompt with a 403,
which is the stricter posture when a single successful malicious prompt is
itself unacceptable.

Three inputs are refused in BOTH modes, because they are attack-shaped rather
than merely suspicious:

  * a body too large or too deeply nested to inspect (evasion by overflow)
  * a request with no establishable source identity (unattributable, unscopable)
  * a request on a session that has already been terminated

A detection FAILURE — the engine raised, or a dependency is down — is governed
separately by config.DETECTION_FAILURE_POLICY (default "fail_open"): the prompt
passes, a degraded metric is emitted, and the DegradedComponents alarm fires.
The reasoning is that a broken monitor should not also break the thing it
monitors. Set "fail_closed" to invert that.
"""
from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any
from uuid import uuid4

from adapters.agentcore import crypto, enforcement
from adapters.agentcore.event_parser import envelope_of, parse_gateway_event
from adapters.agentcore.session_registry import (
    ensure_session,
    get_session,
    record_detection_event,
    record_session_evaluation,
)
from vardoger import aws, config
from vardoger.detection.engine import DetectionEngine
from vardoger.detection.models import EvaluationResult
from vardoger.health import (
    ENFORCEMENT,
    EVIDENCE_STORE,
    INLINE_DETECTION,
    PROMPT_TELEMETRY,
    report_degraded,
)

logger = logging.getLogger(__name__)

_engine: DetectionEngine | None = None

# Returned to the caller on a block, in both envelopes. Deliberately says
# nothing about which signature matched: a refusal is not a place to tell an
# attacker what tripped it.
_BLOCK_MESSAGE = "Session terminated by security monitor"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _get_engine() -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine(scanner_reinit_seconds=config.SCANNER_REINIT_SECONDS)
    return _engine


def _get_sqs():
    """SQS client on the inline profile — fail fast rather than stall the
    interceptor (see vardoger/aws.py)."""
    return aws.client("sqs", kind="inline")


def _gateway_request(event: dict[str, Any], envelope: str) -> dict[str, Any]:
    """Return the gatewayRequest block for whichever envelope this event uses."""
    section = event.get(envelope) if isinstance(event.get(envelope), dict) else {}
    request = section.get("gatewayRequest") if isinstance(section, dict) else None
    return request if isinstance(request, dict) else {}


def _passthrough_response(event: dict[str, Any]) -> dict[str, Any]:
    """Build a Gateway response that lets the prompt through unchanged.

    The reply must use the SAME envelope the gateway sent. Replying in the wrong
    one yields "Received invalid response from interceptor" — which fails closed,
    but by accident rather than by design, and looks like an outage.
    """
    envelope = envelope_of(event) or "mcp"
    body = _gateway_request(event, envelope).get("body", {} if envelope == "mcp" else "")
    # The http body is already base64 and is echoed back verbatim. Note that
    # `path` and `httpMethod` are NOT accepted here, only the body.
    return {
        "interceptorOutputVersion": "1.0",
        envelope: {"transformedGatewayRequest": {"body": body}},
    }


def _terminate_response(event: dict[str, Any]) -> dict[str, Any]:
    """Build a Gateway response that blocks the prompt with HTTP 403."""
    envelope = envelope_of(event) or "mcp"
    if envelope == "http":
        # A plain HTTP caller, not a JSON-RPC client: no request id to echo, and
        # the body must be base64 like the inbound one.
        payload = json.dumps({"error": _BLOCK_MESSAGE}).encode("utf-8")
        return {
            "interceptorOutputVersion": "1.0",
            "http": {
                "transformedGatewayResponse": {
                    "statusCode": 403,
                    "body": base64.b64encode(payload).decode("ascii"),
                }
            },
        }

    request_body = _gateway_request(event, "mcp").get("body", {})
    request_id = request_body.get("id", "unknown") if isinstance(request_body, dict) else "unknown"
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 403,
                "body": {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32600,
                        "message": _BLOCK_MESSAGE,
                    },
                },
            }
        },
    }


def _publish_to_sqs(queue_url: str, message: dict[str, Any], queue_name: str) -> bool:
    """Send a JSON message to an SQS queue. Never raises.

    Returns True only if the message was actually accepted. Callers rely on this:
    in sidecar mode the session kill is carried BY this message, so a silent
    failure here would mean no kill at all.
    """
    if not queue_url:
        return False
    try:
        _get_sqs().send_message(QueueUrl=queue_url, MessageBody=json.dumps(message))
        return True
    except Exception:
        logger.exception("Failed to publish to %s; non-blocking", queue_name)
        return False


def _copy_prompt_telemetry(message: dict[str, Any]) -> str:
    """Copy prompt to the telemetry destination for the configured mode.

    - ``disabled``: no telemetry.
    - ``managed``:  cross-account send to the managed intake queue.
    - ``local``:    same-account send to the prompt intake queue that feeds
                    Tier 2 (and, downstream, PromptHistory / Tier 3).

    A configured destination that fails to send is governed by
    ``TRANSPORT_FAILURE_POLICY``. A mode with no destination configured is a
    no-op (returns the mode name), never a failure.
    """
    mode = config.PROMPT_TELEMETRY_MODE
    if mode == "disabled":
        return "disabled"

    if mode == "managed":
        queue_url = config.MANAGED_INTAKE_URL
    else:  # local (default)
        queue_url = config.PROMPT_INTAKE_QUEUE_URL

    if not queue_url:
        # No destination wired for this mode: nothing to send. This is a
        # configuration no-op, not a transport failure.
        return mode

    try:
        message["saas_sqs_send_started_at"] = _now_ms()
        _get_sqs().send_message(QueueUrl=queue_url, MessageBody=json.dumps(message))
        return "sent"
    except Exception as error:
        policy = config.TRANSPORT_FAILURE_POLICY
        logger.warning("Telemetry copy failed: %s policy=%s", type(error).__name__, policy)
        # Telemetry feeds Tier 2/3 and PromptHistory. A silent failure here
        # means the async tiers are starved while the system looks healthy —
        # Surface it as a metric so a starved pipeline is visible.
        report_degraded(
            PROMPT_TELEMETRY,
            f"{mode} telemetry send failed: {type(error).__name__}",
            transport_policy=policy,
        )
        if policy == "fail_closed":
            return "fail_closed"
        return "degraded"


def _build_prompt_message(
    session_id: str,
    agent_runtime_arn: str,
    scope_id: str,
    source: str,
    account_id: str,
    prompt: str,
    result: EvaluationResult,
    request_id: str = "",
) -> dict[str, Any]:
    """Assemble the prompt telemetry record."""
    return {
        "prompt_id": uuid4().hex,
        "request_id": request_id,
        "session_id": session_id,
        # The runtime session id the inline kill targeted. Carrying it means the
        # alert Lambda's re-terminate uses the SAME value rather than
        # independently re-deriving it. NOTE: this is the sandbox derivation
        # until the real mcp->runtime session mapping is confirmed live (#7).
        "runtime_session_id": enforcement._default_runtime_session_id(session_id),
        "agent_runtime_arn": agent_runtime_arn,
        "scope_id": scope_id,
        "source": source,
        "account_id": account_id,
        "prompt": prompt,
        "prompt_length": len(prompt),
        "decision": result.decision,
        "risk_score": result.risk_score,
        "risk_bucket": result.risk_bucket,
        "matched_signature_ids": result.matched_signature_ids,
        "attack_intents": result.attack_intents,
        "matched_policy_rules": result.matched_policy_rules,
        "timestamp": int(time.time()),
        "dispatcher_received_at": _now_ms(),
        "transport_status": "sent",
        # provenance = which component produced this record (was previously the
        # overloaded "source" field). "source" above is the account+agent key.
        "provenance": "dispatcher",
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Dispatcher Lambda entry point — REQUEST interceptor on AgentCore Gateway.

    For every inbound prompt: parse it, run detection, and either pass through or block + kill.
    """
    # This handler is the AgentCore Gateway REQUEST interceptor. A well-formed
    # interceptor event always carries an "mcp" envelope. Anything without it is
    # not gateway traffic (e.g. an enforcement payload mis-routed here, or a
    # malformed invoke). Refuse it explicitly rather than harvesting its fields
    # as a "prompt" and writing bogus session/detection records.
    if not envelope_of(event):
        logger.error(
            "Dispatcher received a non-interceptor event (no 'mcp' or 'http' envelope); rejecting"
        )
        raise ValueError(
            "Dispatcher requires an AgentCore interceptor event with an 'mcp' or 'http' envelope"
        )

    try:
        parsed = parse_gateway_event(event)
    except Exception as exc:
        # Parsing is not detection, but failing it has the same consequence:
        # the prompt was never judged. Left unhandled this escapes as a Lambda
        # error and the gateway returns 500 to the CALLER, so a parser bug
        # takes the agent down with it — precisely what fail-open exists to
        # prevent. Governed by the same policy as a detection failure.
        logger.exception(
            "Could not parse the interceptor event; policy=%s",
            config.DETECTION_FAILURE_POLICY,
        )
        report_degraded(
            INLINE_DETECTION,
            f"event parse failed: {type(exc).__name__}",
            policy=config.DETECTION_FAILURE_POLICY,
        )
        if config.DETECTION_FAILURE_POLICY == "fail_closed":
            return _terminate_response(event)
        return _passthrough_response(event)

    # No inspectable text — protocol control message, pass through
    if not parsed.has_inspectable_text:
        return _passthrough_response(event)

    # Body too large/deep to fully inspect. Refused in BOTH modes: an
    # uninspectable body is the cheapest evasion there is, so treating it as an
    # attack rather than as a failure is deliberate. Not governed by
    # DETECTION_FAILURE_POLICY — nothing failed here.
    if parsed.truncated:
        logger.warning("Request body exceeded inspection limits; refusing")
        return _terminate_response(event)

    # No source identity. Refused in BOTH modes: without a known account/agent
    # we cannot attribute, scope, or select policy for the request — and in
    # sidecar mode we could not even identify a session to terminate, so
    # passing it through would mean no control at all.
    if not parsed.source:
        logger.error("No source identity could be established; refusing")
        return _terminate_response(event)

    try:
        # One read for both status and risk — these live on the same item, and
        # this is the inline path. Inside the fail-closed try: a DynamoDB error
        # here must block, not raise unhandled.
        session = get_session(parsed.session_id)
        if session["status"] == "terminated":
            return _terminate_response(event)

        # The risk scorer expects "no prior state" as an empty dict, not zeros.
        session_state: dict[str, Any] = (
            {}
            if session["status"] is None and not session["prompts_seen"]
            else {
                "accumulated_risk_score": session["accumulated_risk_score"],
                "prompts_seen": session["prompts_seen"],
                "intent_counts": session["intent_counts"],
                "last_risk_epoch": session["last_risk_epoch"],
            }
        )

        ensure_session(
            session_id=parsed.session_id,
            agent_runtime_arn=parsed.agent_runtime_arn,
            scope_id=parsed.scope_id,
            source=parsed.source,
        )

        # Core detection. The engine is source/scope agnostic — it evaluates
        # text and session risk; attribution is handled by the caller.
        engine = _get_engine()
        result = engine.evaluate(
            prompt=parsed.inspectable_text,
            session_id=parsed.session_id,
            tenant_id=parsed.source,
            session_state=session_state,
        )

        # Persist risk state and the decision in a single write. Keeping these
        # atomic means a session can never be read with new risk but a stale
        # decision.
        record_session_evaluation(
            session_id=parsed.session_id,
            accumulated_risk_score=result.session_risk_score,
            prompts_seen=session_state.get("prompts_seen", 0) + 1,
            intent_counts=result.session_signal_counts or {},
            decision=result.decision,
            risk_score=result.risk_score,
            matched_signature_ids=result.matched_signature_ids,
        )
        record_detection_event(
            session_id=parsed.session_id,
            scope_id=parsed.scope_id,
            source=parsed.source,
            decision=result.decision,
            risk_score=result.risk_score,
            matched_signature_ids=result.matched_signature_ids,
            attack_intents=result.attack_intents,
            matched_policy_rules=result.matched_policy_rules,
        )

        # Telemetry
        message = _build_prompt_message(
            session_id=parsed.session_id,
            agent_runtime_arn=parsed.agent_runtime_arn,
            scope_id=parsed.scope_id,
            source=parsed.source,
            account_id=parsed.account_id,
            prompt=parsed.prompt,
            result=result,
            request_id=str(event.get("mcp", {}).get("gatewayRequest", {}).get("body", {}).get("id", "")),
        )
        transport_outcome = _copy_prompt_telemetry(message)

        if result.decision == "block":
            # The session dies in BOTH modes. What differs is WHEN.
            #
            #   gate    — kill inline. The prompt is refused anyway, so there is
            #             no in-flight answer to protect.
            #   sidecar — hand the kill to the alert queue and return. The agent
            #             gets to finish answering the triggering prompt, which
            #             is the point of sidecar mode: a StopRuntimeSession
            #             issued before the passthrough would race the very
            #             response we promised to deliver.
            #
            # Either way record_session_evaluation above has ALREADY marked the
            # session terminated, so the next prompt on it is refused by the
            # check at the top of this handler even while a deferred kill is
            # still in flight.
            reason = f"Inline detection: {', '.join(result.matched_signature_ids[:5]) or 'policy/risk'}"
            deferred = config.TIER1_MODE == "sidecar"
            kill_outcome = enforcement.TERMINATE_DEFERRED if deferred else enforcement.TERMINATE_FAILED
            if not deferred:
                try:
                    kill_outcome = enforcement.terminate_session_detailed(
                        session_id=parsed.session_id,
                        agent_runtime_arn=parsed.agent_runtime_arn,
                        reason=reason,
                    )
                except Exception:
                    logger.exception("StopRuntimeSession failed; still refusing the prompt")
            message["kill_outcome"] = kill_outcome

            # Persist encrypted prompt evidence for forensics (best-effort; a
            # no-op when no KMS key / evidence bucket is configured). This is
            # what backs the "encrypted at rest (KMS)" evidence claim.
            try:
                crypto.encrypt_and_log(
                    prompt_text=parsed.prompt,
                    session_id=parsed.session_id,
                    decision=result.decision,
                    risk_score=result.risk_score,
                    matched_signature_ids=result.matched_signature_ids,
                    attack_intents=result.attack_intents,
                    agent_runtime_arn=parsed.agent_runtime_arn,
                )
            except Exception as exc:
                logger.exception("Evidence encryption failed; non-blocking")
                report_degraded(
                    EVIDENCE_STORE,
                    f"evidence encryption failed: {type(exc).__name__}",
                    session_id=parsed.session_id,
                )

            # Alert queue. In sidecar mode this message IS the kill order — the
            # alert Lambda terminates every session it reads — so its delivery
            # is load-bearing, not best-effort.
            queued = _publish_to_sqs(config.ALERT_QUEUE_URL, message, "alert-queue")

            if deferred and not queued:
                # The deferred kill had one carrier and it did not land. There
                # is no retry behind this, so fall back to killing inline: a
                # late answer is a far smaller problem than a live session that
                # was supposed to be terminated and never was.
                logger.error(
                    "Alert queue publish failed; falling back to an inline kill for session %s",
                    parsed.session_id,
                )
                report_degraded(
                    ENFORCEMENT,
                    "deferred kill could not be queued; killed inline instead",
                    session_id=parsed.session_id,
                )
                try:
                    message["kill_outcome"] = enforcement.terminate_session_detailed(
                        session_id=parsed.session_id,
                        agent_runtime_arn=parsed.agent_runtime_arn,
                        reason=reason,
                    )
                except Exception:
                    logger.exception("Fallback StopRuntimeSession failed for session %s", parsed.session_id)
                    message["kill_outcome"] = enforcement.TERMINATE_FAILED

            if config.TIER1_MODE == "gate":
                return _terminate_response(event)

            logger.info(
                "Tier 1 detection on session %s: session marked terminated, kill deferred, prompt passed through",
                parsed.session_id,
            )
            return _passthrough_response(event)

        if transport_outcome == "fail_closed":
            return _terminate_response(event)

    except Exception as exc:
        # Detection could not run. This is a FAILURE, not a detection — the
        # prompt was never judged. Under the default fail-open policy it passes
        # and the degraded metric (which alarms) is the record that traffic went
        # uninspected; a monitor that is down should not take the agent with it.
        logger.exception("Inline detection failed; policy=%s", config.DETECTION_FAILURE_POLICY)
        report_degraded(
            INLINE_DETECTION,
            f"inline detection failed: {type(exc).__name__}",
            policy=config.DETECTION_FAILURE_POLICY,
            session_id=parsed.session_id,
        )
        if config.DETECTION_FAILURE_POLICY == "fail_closed":
            return _terminate_response(event)
        return _passthrough_response(event)

    return _passthrough_response(event)
