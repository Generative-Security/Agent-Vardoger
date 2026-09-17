"""A kill that is unavailable must not look like a kill that is broken.

Measured live against the bundled test harness:

    ValidationException: The agent runtime arn:...:runtime/harness_... is
    managed by a harness and cannot be invoked directly

Everything leading up to that call was correct — detection fired at risk 12,
the session was recorded terminated, the deferred kill reached the alert
Lambda, and StopRuntimeSession was invoked with the right session id and the
right runtime ARN. AgentCore simply does not permit stopping a session on a
harness-managed runtime. No retry, permission or configuration change makes it
succeed.

Reported as a bare "StopRuntimeSession failed: ValidationException", that reads
as a defect in the call, and an operator would go looking for one. The
distinction that matters to them is whether the kill is BROKEN (fixable) or
UNAVAILABLE (a property of how the agent was deployed), because only one of
those has an action attached.

What still holds when the kill is unavailable: the session stays recorded as
terminated, so further tool calls through the gateway are refused. Containment
degrades to tool denial rather than disappearing.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from adapters.agentcore import enforcement

RUNTIME_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:701364614161:runtime/"
    "harness_vardoger_test_701364614161-GsuLs0BR25"
)
SESSION = "e8969809-2066-4c58-963c-646d3e20b967"

# Verbatim from the live failure.
_HARNESS_MESSAGE = (
    f"The agent runtime {RUNTIME_ARN} is managed by a harness and cannot be "
    "invoked directly"
)


def _client_raising(code: str, message: str) -> MagicMock:
    client = MagicMock()
    client.stop_runtime_session.side_effect = ClientError(
        {"Error": {"Code": code, "Message": message}}, "StopRuntimeSession"
    )
    return client


def _terminate(client: MagicMock) -> str:
    with patch.object(enforcement.aws, "client", return_value=client):
        return enforcement.terminate_session_detailed(
            session_id=SESSION,
            agent_runtime_arn=RUNTIME_ARN,
            reason="Inline detection",
        )


class TestHarnessManagedIsItsOwnOutcome:
    def test_it_is_not_reported_as_a_generic_failure(self) -> None:
        outcome = _terminate(_client_raising("ValidationException", _HARNESS_MESSAGE))
        assert outcome == enforcement.TERMINATE_UNSUPPORTED
        assert outcome != enforcement.TERMINATE_FAILED

    def test_it_is_not_reported_as_unverified(self) -> None:
        """`unverified` means the session id might be wrong. Here it is not.

        Confirmed live: the id the dispatcher recorded matched the runtime's
        own sessionId exactly. Nothing about the identifier is in doubt.
        """
        outcome = _terminate(_client_raising("ValidationException", _HARNESS_MESSAGE))
        assert outcome != enforcement.TERMINATE_UNVERIFIED

    def test_the_boolean_wrapper_does_not_call_it_success(self) -> None:
        """terminate_session() returns True for confirmed AND unverified.

        Adding this outcome to that set would be the exact success-shaped lie
        the outcome exists to prevent: the runtime is still running, and will
        stay running.
        """
        with patch.object(
            enforcement, "terminate_session_detailed",
            return_value=enforcement.TERMINATE_UNSUPPORTED,
        ):
            assert enforcement.terminate_session(SESSION, RUNTIME_ARN) is False

    def test_the_degraded_reason_names_the_cause(self) -> None:
        """"ValidationException" sends an operator hunting for a bug.

        The alarm fires either way; what differs is whether the reason tells
        them there is nothing to fix.
        """
        with patch.object(enforcement, "report_degraded") as reported:
            _terminate(_client_raising("ValidationException", _HARNESS_MESSAGE))
        assert reported.called
        assert "harness-managed" in reported.call_args.args[1]

    def test_it_still_reports_degraded(self) -> None:
        """Unavailable enforcement is still degraded enforcement.

        The operator is not getting the containment they believe they have, so
        this must reach the DegradedComponents alarm rather than pass quietly.
        """
        with patch.object(enforcement, "report_degraded") as reported:
            _terminate(_client_raising("ValidationException", _HARNESS_MESSAGE))
        assert reported.called


class TestOtherFailuresAreUnaffected:
    """The match must be narrow: only this message, only this code."""

    def test_an_unrelated_validation_exception_is_still_a_failure(self) -> None:
        outcome = _terminate(
            _client_raising("ValidationException", "runtimeSessionId is too short")
        )
        assert outcome == enforcement.TERMINATE_FAILED

    def test_a_missing_session_is_still_unverified(self) -> None:
        outcome = _terminate(
            _client_raising("ResourceNotFoundException", "no such session")
        )
        assert outcome == enforcement.TERMINATE_UNVERIFIED

    def test_access_denied_is_still_a_failure(self) -> None:
        """A permissions gap IS fixable and must not be excused as structural."""
        outcome = _terminate(
            _client_raising("AccessDeniedException", "not authorized")
        )
        assert outcome == enforcement.TERMINATE_FAILED

    def test_a_successful_stop_is_confirmed(self) -> None:
        client = MagicMock()
        client.stop_runtime_session.return_value = {}
        assert _terminate(client) == enforcement.TERMINATE_CONFIRMED


class TestTheOutcomeVocabularyStaysDistinct:
    def test_every_outcome_is_a_different_string(self) -> None:
        outcomes = [
            enforcement.TERMINATE_CONFIRMED,
            enforcement.TERMINATE_UNVERIFIED,
            enforcement.TERMINATE_FAILED,
            enforcement.TERMINATE_DEFERRED,
            enforcement.TERMINATE_UNSUPPORTED,
        ]
        assert len(set(outcomes)) == len(outcomes), (
            "two outcomes share a value, so they cannot be told apart in a "
            "record or a dashboard"
        )

    @pytest.mark.parametrize("outcome", ["confirmed", "unverified", "failed",
                                         "deferred", "unsupported"])
    def test_the_documented_values_exist(self, outcome: str) -> None:
        """These strings land in DynamoDB and the dashboard; renaming one
        silently changes what historical records mean."""
        assert outcome in {
            enforcement.TERMINATE_CONFIRMED,
            enforcement.TERMINATE_UNVERIFIED,
            enforcement.TERMINATE_FAILED,
            enforcement.TERMINATE_DEFERRED,
            enforcement.TERMINATE_UNSUPPORTED,
        }
