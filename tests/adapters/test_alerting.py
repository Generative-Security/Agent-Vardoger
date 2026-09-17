"""Tests for the alert Lambda: partial-batch responses and severity mapping."""
from __future__ import annotations

import json
from unittest.mock import patch

from adapters.agentcore import alerting


def _sqs_event(records):
    return {"Records": [{"messageId": mid, "body": json.dumps(body)} for mid, body in records]}


def _alert_body(session_id="s1", risk_score=12):
    return {
        "session_id": session_id,
        "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/x",
        "runtime_session_id": "rt-1",
        "decision": "block",
        "risk_score": risk_score,
        "matched_signature_ids": ["sig-1"],
    }


class TestPartialBatch:
    @patch("adapters.agentcore.alerting._publish_security_hub_finding")
    @patch("adapters.agentcore.alerting._publish_sns_alert")
    @patch("adapters.agentcore.alerting.record_kill_outcome")
    @patch("adapters.agentcore.alerting.terminate_session_detailed")
    def test_all_success_no_failures(self, mock_term, mock_record, mock_sns, mock_sh):
        event = _sqs_event([("m1", _alert_body("a")), ("m2", _alert_body("b"))])
        result = alerting.lambda_handler(event, None)
        assert result["processed"] == 2
        assert result["batchItemFailures"] == []

    @patch("adapters.agentcore.alerting._publish_security_hub_finding")
    @patch("adapters.agentcore.alerting._publish_sns_alert")
    @patch("adapters.agentcore.alerting.record_kill_outcome")
    @patch("adapters.agentcore.alerting.terminate_session_detailed")
    def test_one_failure_only_that_item_retried(self, mock_term, mock_record, mock_sns, mock_sh):
        # Make the SNS publish blow up for the second record only.
        def sns_side_effect(body):
            if body["session_id"] == "b":
                raise RuntimeError("sns down")

        mock_sns.side_effect = sns_side_effect
        event = _sqs_event([("m1", _alert_body("a")), ("m2", _alert_body("b"))])
        result = alerting.lambda_handler(event, None)

        assert result["processed"] == 1
        assert result["batchItemFailures"] == [{"itemIdentifier": "m2"}]

    @patch("adapters.agentcore.alerting._publish_security_hub_finding")
    @patch("adapters.agentcore.alerting._publish_sns_alert")
    @patch("adapters.agentcore.alerting.record_kill_outcome")
    @patch("adapters.agentcore.alerting.terminate_session_detailed")
    def test_forwards_runtime_session_id_on_reterminate(self, mock_term, mock_record, mock_sns, mock_sh):
        event = _sqs_event([("m1", _alert_body("a"))])
        alerting.lambda_handler(event, None)
        _, kwargs = mock_term.call_args
        assert kwargs.get("runtime_session_id") == "rt-1"


class TestSeverityLabel:
    def test_bands(self):
        assert alerting._severity_label(12) == "CRITICAL"
        assert alerting._severity_label(8) == "HIGH"
        assert alerting._severity_label(5) == "MEDIUM"
        assert alerting._severity_label(2) == "LOW"
        assert alerting._severity_label(0) == "INFORMATIONAL"
