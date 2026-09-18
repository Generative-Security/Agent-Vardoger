"""Degraded-component reporting.

This codebase deliberately degrades rather than fails: a premium signature feed
that will not load, a telemetry queue that rejects a send, an outcome-ledger
write that errors — none of those should take down detection. The established
idiom is "log the exception, return a safe default, keep serving".

That idiom is how a security function ends up silently off in production while
the system still looks healthy: the telemetry hand-off to the async tiers can
fail on every request, and nothing outside the log observes it. For a security
product, "detections quietly reduced" is the failure mode that matters most, and
it is precisely the one a log line does not surface.

``report_degraded`` is the one-line companion to those handlers. It emits a
CloudWatch Embedded Metric Format record so a single alarm on
``AgentVardoger/DegradedComponents`` catches every such path, with the component
name as a dimension for triage.

EMF is used rather than a PutMetricData call on purpose: it is a structured log
write with no network call, no IAM permission, and no added latency — safe to
call from the inline interceptor path.
"""
from __future__ import annotations

import json
import logging
import time

logger = logging.getLogger(__name__)

_NAMESPACE = "AgentVardoger"
_METRIC = "DegradedComponents"

# Component identifiers. Kept as constants so the alarm dimension values are a
# closed set rather than free-form strings drifting across call sites.
PREMIUM_SIGNATURES = "premium_signatures"
CUSTOM_SIGNATURES = "custom_signatures"
SIGNATURE_REFRESH = "signature_refresh"
PROMPT_TELEMETRY = "prompt_telemetry"
SESSION_REGISTRY = "session_registry"
DETECTION_EVENTS = "detection_events"
OUTCOME_LEDGER = "outcome_ledger"
EVIDENCE_STORE = "evidence_store"
TENANT_POLICY = "tenant_policy"
ENFORCEMENT = "enforcement"
# Notification, not containment: the kill still happened. But an operator whose
# alerting is quietly broken believes nothing is happening at all.
ALERTING = "alerting"
# Tier 1 could not evaluate a prompt at all. Under a fail-open detection policy
# this is the ONLY signal that traffic went uninspected, so it must alarm.
INLINE_DETECTION = "inline_detection"
ML_INFERENCE = "ml_inference"
DASHBOARD_QUERY = "dashboard_query"


def report_degraded(component: str, reason: str, **context: object) -> None:
    """Record that ``component`` is operating in a degraded state.

    Call this from every "log and continue with a safe default" handler, in
    addition to the existing log line. Never raises: a reporting failure must
    not escalate into the failure it is reporting.
    """
    try:
        payload = {
            "_aws": {
                "Timestamp": int(time.time() * 1000),
                "CloudWatchMetrics": [
                    {
                        "Namespace": _NAMESPACE,
                        "Dimensions": [["component"]],
                        "Metrics": [{"Name": _METRIC, "Unit": "Count"}],
                    }
                ],
            },
            "component": component,
            "reason": reason,
            _METRIC: 1,
        }
        for key, value in context.items():
            # Context is for triage only; coerce to str so an unserializable
            # object cannot break the emit.
            payload[key] = value if isinstance(value, (str, int, float, bool)) else str(value)
        # EMF is consumed from stdout by the Lambda log agent.
        print(json.dumps(payload))
        logger.warning("DEGRADED component=%s reason=%s", component, reason)
    except Exception:  # pragma: no cover - reporting must never raise
        logger.warning("DEGRADED component=%s reason=%s (metric emit failed)", component, reason)
