"""Tests for the dedicated async enforcement handler (Tier 2/3 kills)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from adapters.agentcore import enforcement, enforcement_handler


def _valid_request(**overrides):
    req = {
        "action": "terminate",
        "session_id": "sess-1",
        "runtime_session_id": "rt-abc",
        "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/x",
        "scope_id": "local",
        "source": "111122223333/agent",
        "matched_signature_ids": ["ml-tier2-malicious"],
        "attack_intents": ["ml:MALICIOUS"],
        "matched_policy_rules": ["tier2_ml_detection"],
        "risk_score": 12,
        "detection_source": "tier2_ml",
        "reason": "unit test",
    }
    req.update(overrides)
    return req


@patch("adapters.agentcore.enforcement_handler.record_detection_event")
@patch("adapters.agentcore.enforcement_handler.mark_session_decision")
@patch("adapters.agentcore.enforcement_handler.enforcement.terminate_session_detailed")
class TestEnforcementHandler:
    def test_terminate_calls_stop_with_runtime_session_id(
        self, mock_terminate, mock_mark, mock_record,
    ):
        mock_terminate.return_value = enforcement.TERMINATE_CONFIRMED
        result = enforcement_handler.lambda_handler(_valid_request(), None)

        assert result["processed"] == 1
        assert result["results"][0]["outcome"] == enforcement.TERMINATE_CONFIRMED
        # The real runtime session id must be forwarded, not re-derived.
        _, kwargs = mock_terminate.call_args
        assert kwargs["runtime_session_id"] == "rt-abc"
        assert kwargs["agent_runtime_arn"].endswith("runtime/x")

    def test_records_decision_and_event(self, mock_terminate, mock_mark, mock_record):
        mock_terminate.return_value = enforcement.TERMINATE_CONFIRMED
        enforcement_handler.lambda_handler(_valid_request(), None)

        mock_mark.assert_called_once()
        mock_record.assert_called_once()

    def test_unverified_outcome_still_records(self, mock_terminate, mock_mark, mock_record):
        # An unverified kill is still blocked/audited, and the outcome surfaces.
        mock_terminate.return_value = enforcement.TERMINATE_UNVERIFIED
        result = enforcement_handler.lambda_handler(_valid_request(), None)
        assert result["results"][0]["outcome"] == enforcement.TERMINATE_UNVERIFIED
        mock_record.assert_called_once()

    def test_missing_action_raises(self, mock_terminate, mock_mark, mock_record):
        with pytest.raises(ValueError):
            enforcement_handler.lambda_handler(_valid_request(action=""), None)
        mock_terminate.assert_not_called()

    def test_missing_session_id_raises(self, mock_terminate, mock_mark, mock_record):
        with pytest.raises(ValueError):
            enforcement_handler.lambda_handler(_valid_request(session_id=""), None)
        mock_terminate.assert_not_called()

    def test_missing_agent_runtime_arn_raises(self, mock_terminate, mock_mark, mock_record):
        with pytest.raises(ValueError):
            enforcement_handler.lambda_handler(_valid_request(agent_runtime_arn=""), None)
        mock_terminate.assert_not_called()

    def test_batch_requests(self, mock_terminate, mock_mark, mock_record):
        mock_terminate.return_value = enforcement.TERMINATE_CONFIRMED
        event = {"requests": [_valid_request(session_id="a"), _valid_request(session_id="b")]}
        result = enforcement_handler.lambda_handler(event, None)
        assert result["processed"] == 2


class TestTerminateSessionDetailed:
    def test_resource_not_found_is_unverified(self):
        from botocore.exceptions import ClientError

        err = ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "StopRuntimeSession")
        with patch("adapters.agentcore.enforcement.aws.client") as mock_client:
            mock_client.return_value.stop_runtime_session.side_effect = err
            outcome = enforcement.terminate_session_detailed(
                session_id="s", agent_runtime_arn="arn:x", runtime_session_id="rt"
            )
        assert outcome == enforcement.TERMINATE_UNVERIFIED

    def test_success_is_confirmed(self):
        with patch("adapters.agentcore.enforcement.aws.client") as mock_client:
            mock_client.return_value.stop_runtime_session.return_value = {}
            outcome = enforcement.terminate_session_detailed(
                session_id="s", agent_runtime_arn="arn:x", runtime_session_id="rt"
            )
        assert outcome == enforcement.TERMINATE_CONFIRMED

    def test_missing_arn_is_failed(self):
        outcome = enforcement.terminate_session_detailed(
            session_id="s", agent_runtime_arn="", runtime_session_id="rt"
        )
        assert outcome == enforcement.TERMINATE_FAILED

    def test_explicit_runtime_session_id_bypasses_sandbox_derivation(self):
        with patch("adapters.agentcore.enforcement.aws.client") as mock_client:
            mock_client.return_value.stop_runtime_session.return_value = {}
            enforcement.terminate_session_detailed(
                session_id="short", agent_runtime_arn="arn:x", runtime_session_id="explicit-rt"
            )
            _, kwargs = mock_client.return_value.stop_runtime_session.call_args
            assert kwargs["runtimeSessionId"] == "explicit-rt"
