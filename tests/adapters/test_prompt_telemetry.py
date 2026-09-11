"""Tests for dispatcher prompt-telemetry routing across modes."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from adapters.agentcore import dispatcher


class TestCopyPromptTelemetry:
    def test_local_mode_sends_to_prompt_intake_queue(self):
        sqs = MagicMock()
        with patch("vardoger.config.PROMPT_TELEMETRY_MODE", "local"), \
                patch("vardoger.config.PROMPT_INTAKE_QUEUE_URL", "https://sqs/local-intake"), \
                patch("adapters.agentcore.dispatcher._get_sqs", return_value=sqs):
            outcome = dispatcher._copy_prompt_telemetry({"prompt_id": "p1"})

        assert outcome == "sent"
        sqs.send_message.assert_called_once()
        _, kwargs = sqs.send_message.call_args
        assert kwargs["QueueUrl"] == "https://sqs/local-intake"

    def test_local_mode_without_queue_is_noop(self):
        sqs = MagicMock()
        with patch("vardoger.config.PROMPT_TELEMETRY_MODE", "local"), \
                patch("vardoger.config.PROMPT_INTAKE_QUEUE_URL", ""), \
                patch("adapters.agentcore.dispatcher._get_sqs", return_value=sqs):
            outcome = dispatcher._copy_prompt_telemetry({"prompt_id": "p1"})

        assert outcome == "local"
        sqs.send_message.assert_not_called()

    def test_managed_mode_sends_to_managed_intake(self):
        sqs = MagicMock()
        with patch("vardoger.config.PROMPT_TELEMETRY_MODE", "managed"), \
                patch("vardoger.config.MANAGED_INTAKE_URL", "https://sqs/managed"), \
                patch("adapters.agentcore.dispatcher._get_sqs", return_value=sqs):
            outcome = dispatcher._copy_prompt_telemetry({"prompt_id": "p1"})

        assert outcome == "sent"
        _, kwargs = sqs.send_message.call_args
        assert kwargs["QueueUrl"] == "https://sqs/managed"

    def test_disabled_mode_is_noop(self):
        sqs = MagicMock()
        with patch("vardoger.config.PROMPT_TELEMETRY_MODE", "disabled"), \
                patch("adapters.agentcore.dispatcher._get_sqs", return_value=sqs):
            outcome = dispatcher._copy_prompt_telemetry({"prompt_id": "p1"})

        assert outcome == "disabled"
        sqs.send_message.assert_not_called()

    def test_send_failure_respects_fail_closed_policy(self):
        sqs = MagicMock()
        sqs.send_message.side_effect = RuntimeError("network")
        with patch("vardoger.config.PROMPT_TELEMETRY_MODE", "local"), \
                patch("vardoger.config.PROMPT_INTAKE_QUEUE_URL", "https://sqs/local-intake"), \
                patch("vardoger.config.TRANSPORT_FAILURE_POLICY", "fail_closed"), \
                patch("adapters.agentcore.dispatcher._get_sqs", return_value=sqs):
            outcome = dispatcher._copy_prompt_telemetry({"prompt_id": "p1"})

        assert outcome == "fail_closed"
