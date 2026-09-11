"""AWS alerting — SNS publishing and Security Hub findings.

Alert Lambda handler: receives blocked-session messages from the alert queue,
publishes SNS alerts, and imports Security Hub findings.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from adapters.agentcore.enforcement import terminate_session
from vardoger import aws, config

logger = logging.getLogger(__name__)


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
            Subject=f"Agent Vardøger Alert: Session {session_id[:8]} terminated",
            Message=json.dumps(message, indent=2),
        )
    except Exception:
        logger.exception("Failed to publish SNS alert for session %s", session_id)


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

            # Re-terminate in case the inline kill was partial. Prefer the real
            # runtime session id when the producer supplied it.
            agent_runtime_arn = body.get("agent_runtime_arn", "")
            if agent_runtime_arn:
                terminate_session(
                    body["session_id"],
                    agent_runtime_arn,
                    runtime_session_id=body.get("runtime_session_id", ""),
                )

            _publish_sns_alert(body)
            _publish_security_hub_finding(body)
            processed += 1
        except Exception:
            logger.exception("Failed to process alert record %s", message_id)
            if message_id:
                batch_item_failures.append({"itemIdentifier": message_id})

    return {"processed": processed, "batchItemFailures": batch_item_failures}
