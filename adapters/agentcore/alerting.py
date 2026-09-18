"""AWS alerting — SNS publishing and Security Hub findings.

Alert Lambda handler: receives blocked-session messages from the alert queue,
publishes SNS alerts, and imports Security Hub findings.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from adapters.agentcore.enforcement import TERMINATE_NOT_CONFIGURED, terminate_session_detailed
from adapters.agentcore.session_registry import record_kill_outcome
from vardoger import aws, config
from vardoger.health import ALERTING, ENFORCEMENT, report_degraded
from vardoger.logging_setup import configure_logging

logger = logging.getLogger(__name__)
# Applies VARDOGER_LOG_LEVEL. Without this the runtime's own root level
# applies and every INFO line is dropped, leaving the log group empty.
configure_logging()


def _publish_sns_alert(record: dict[str, Any]) -> None:
    """Publish a session-terminated alert to the configured SNS topic."""
    topic_arn = config.SNS_TOPIC_ARN
    if not topic_arn:
        return

    session_id = record["session_id"]
    message = {
        "event_type": "SESSION_TERMINATED",
        "session_id": session_id,
        "decision": record.get("decision", "block"),
        "matched_signature_ids": record.get("matched_signature_ids", []),
        "risk_score": record.get("risk_score", 0),
        "risk_bucket": record.get("risk_bucket", "high"),
        "attack_intents": record.get("attack_intents", []),
        "timestamp": record.get("timestamp", int(time.time())),
    }
    try:
        aws.client("sns").publish(
            TopicArn=topic_arn,
            Subject=_alert_subject(session_id, str(record.get("kill_outcome", ""))),
            Message=json.dumps(message, indent=2),
        )
    except Exception as exc:
        # The kill already happened; only the notification is lost. But an
        # operator whose alerting is quietly broken believes nothing is
        # happening, so this has to surface somewhere other than the log.
        logger.exception("Failed to publish SNS alert for session %s", session_id)
        report_degraded(ALERTING, f"SNS publish failed: {exc}", session_id=session_id)


def _alert_subject(session_id: str, kill_outcome: str) -> str:
    """Subject line that matches what actually happened to the session.

    This asserted "terminated" unconditionally, including on the path where no
    runtime ARN was configured and no kill was ever attempted.
    """
    short = session_id[:8]
    if kill_outcome == TERMINATE_NOT_CONFIGURED:
        return f"Agent Vardøger Alert: Session {short} flagged (NOT terminated)"
    if kill_outcome in {"failed", "unsupported"}:
        return f"Agent Vardøger Alert: Session {short} flagged, termination {kill_outcome}"
    if kill_outcome == "unverified":
        return f"Agent Vardøger Alert: Session {short} termination unverified"
    return f"Agent Vardøger Alert: Session {short} terminated"


def _severity_label(risk_score: int) -> str:
    """Map the 0-12 detection risk score to a Security Hub severity label."""
    if risk_score >= 10:
        return "CRITICAL"
    if risk_score >= 7:
        return "HIGH"
    if risk_score >= 4:
        return "MEDIUM"
    if risk_score >= 1:
        return "LOW"
    return "INFORMATIONAL"


def _publish_security_hub_finding(record: dict[str, Any]) -> None:
    """Import a Security Hub finding for the terminated session."""
    session_id = record["session_id"]
    risk_score = int(record.get("risk_score", 0))
    matched_sigs = record.get("matched_signature_ids", [])
    ts = record.get("timestamp", int(time.time()))
    iso_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

    try:
        sts = aws.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        region = config.AWS_REGION

        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"vardoger/{session_id}/{ts}",
            "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
            "GeneratorId": "agent-vardoger-detection",
            "AwsAccountId": account_id,
            # This is adversary behavior, not a config/compliance check. Use the
            # TTPs taxonomy so it lands in the right Security Hub category.
            "Types": ["TTPs/Initial Access", "Unusual Behaviors/Application"],
            "CreatedAt": iso_ts,
            "UpdatedAt": iso_ts,
            # Prefer the Label severity; map the 0-12 risk score to a band.
            "Severity": {"Label": _severity_label(risk_score)},
            "Title": "Agent Vardøger: Malicious prompt detected",
            "Description": (
                f"Session {session_id} terminated. "
                f"Risk score: {risk_score}. Matched: {', '.join(matched_sigs[:5])}."
            ),
            "Resources": [{
                "Type": "Other",
                "Id": record.get("agent_runtime_arn", session_id),
                "Region": region,
            }],
        }
        aws.client("securityhub", region=region).batch_import_findings(Findings=[finding])
    except Exception:
        logger.warning("Failed to publish Security Hub finding; non-blocking", exc_info=True)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Alert Lambda: publish SNS alerts and Security Hub findings for blocked sessions.

    Returns SQS partial-batch failures so ONLY the records that failed are
    retried (and eventually sent to the DLQ), rather than reprocessing the whole
    batch — which previously produced duplicate Security Hub findings.
    """
    batch_item_failures: list[dict[str, str]] = []
    processed = 0

    for sqs_record in event.get("Records", []):
        message_id = sqs_record.get("messageId", "")
        try:
            body = json.loads(sqs_record["body"])

            # Execute the kill. In sidecar mode THIS is the kill -- the
            # dispatcher deferred it here so the agent could finish answering
            # the triggering prompt -- and in gate mode it re-terminates in case
            # the inline attempt was partial. Prefer the real runtime session id
            # when the producer supplied it.
            agent_runtime_arn = body.get("agent_runtime_arn", "")
            if agent_runtime_arn:
                runtime_session_id = body.get("runtime_session_id", "")
                # _detailed, not the boolean wrapper: the outcome is the point.
                # Discarding it left every session recorded as "deferred"
                # forever, so a kill that failed and a kill still in flight were
                # the same row.
                outcome = terminate_session_detailed(
                    session_id=body["session_id"],
                    agent_runtime_arn=agent_runtime_arn,
                    reason=body.get("reason", "Security detection"),
                    runtime_session_id=runtime_session_id,
                )
                body["kill_outcome"] = outcome
                record_kill_outcome(
                    body["session_id"], outcome, runtime_session_id=runtime_session_id
                )
            else:
                # Nothing to call. This previously fell straight through to the
                # alert, so an operator was told the session was terminated
                # while the registry row sat on "deferred" forever -- the two
                # records disagreeing, with nothing raised either way.
                body["kill_outcome"] = TERMINATE_NOT_CONFIGURED
                record_kill_outcome(body["session_id"], TERMINATE_NOT_CONFIGURED)
                report_degraded(
                    ENFORCEMENT,
                    "no agent runtime ARN configured; session flagged but NOT terminated",
                    session_id=body.get("session_id", ""),
                )

            _publish_sns_alert(body)
            _publish_security_hub_finding(body)
            processed += 1
        except Exception:
            logger.exception("Failed to process alert record %s", message_id)
            if message_id:
                batch_item_failures.append({"itemIdentifier": message_id})

    return {"processed": processed, "batchItemFailures": batch_item_failures}
