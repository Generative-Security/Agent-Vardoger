"""Whether the kill landed must be answerable after the fact.

`kill_outcome` existed only inside the SQS alert message. Nothing wrote it to
DynamoDB, so no query an operator can run knew whether StopRuntimeSession
succeeded, was refused, or was never attempted — and the alert Lambda called
the boolean wrapper and discarded even that.

The consequence is the one this project keeps hitting: "the session was
terminated" and "we asked AWS to terminate the session and it declined" are
different facts that looked identical from the outside. A whole day went into
telling them apart by hand, from X-ray traces and botocore debug logging.

Two writes close the loop, and both matter:

    dispatcher    the outcome it has when it returns, including "deferred", so
                  a kill in flight reads as in flight rather than as nothing.
    alert Lambda  what StopRuntimeSession actually returned, replacing it.

A row still reading "deferred" long afterwards therefore means the deferred
kill never ran — which is a signal rather than an absence of one.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from adapters.agentcore import alerting, dispatcher, enforcement


def _alert_record(session_id: str = "s-1", runtime_session_id: str = "rt-1") -> dict:
    return {"Records": [{"messageId": "m1", "body": json.dumps({
        "session_id": session_id,
        "runtime_session_id": runtime_session_id,
        "agent_runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/a",
        "risk_score": 12,
        "reason": "Inline detection",
    })}]}


class TestTheAlertLambdaRecordsWhatHappened:
    @pytest.mark.parametrize("outcome", [
        enforcement.TERMINATE_CONFIRMED,
        enforcement.TERMINATE_UNVERIFIED,
        enforcement.TERMINATE_UNSUPPORTED,
        enforcement.TERMINATE_FAILED,
    ])
    def test_every_outcome_is_persisted(self, outcome: str) -> None:
        with patch.object(alerting, "terminate_session_detailed", return_value=outcome), \
                patch.object(alerting, "record_kill_outcome") as recorded, \
                patch.object(alerting, "_publish_sns_alert"), \
                patch.object(alerting, "_publish_security_hub_finding"):
            alerting.lambda_handler(_alert_record(), None)
        assert recorded.called, f"{outcome} was not written back"
        assert recorded.call_args.args[1] == outcome

    def test_the_real_runtime_session_id_is_recorded(self) -> None:
        """Which id the kill actually targeted is what makes a failure
        diagnosable; deriving it again later is guesswork."""
        with patch.object(alerting, "terminate_session_detailed",
                          return_value=enforcement.TERMINATE_CONFIRMED), \
                patch.object(alerting, "record_kill_outcome") as recorded, \
                patch.object(alerting, "_publish_sns_alert"), \
                patch.object(alerting, "_publish_security_hub_finding"):
            alerting.lambda_handler(_alert_record(runtime_session_id="rt-real"), None)
        assert recorded.call_args.kwargs.get("runtime_session_id") == "rt-real"

    def test_it_uses_the_detailed_call_not_the_boolean_wrapper(self) -> None:
        """terminate_session() collapses four outcomes into True/False, and
        the discarded detail is exactly what was needed."""
        assert not hasattr(alerting, "terminate_session"), (
            "the alert Lambda imports the boolean wrapper again; the outcome "
            "it returns cannot distinguish confirmed from unverified"
        )

    def test_the_message_carries_the_outcome_onward(self) -> None:
        """SNS and Security Hub consumers see the real result, not 'deferred'."""
        published = {}
        with patch.object(alerting, "terminate_session_detailed",
                          return_value=enforcement.TERMINATE_UNSUPPORTED), \
                patch.object(alerting, "record_kill_outcome"), \
                patch.object(alerting, "_publish_sns_alert",
                             side_effect=lambda b: published.update(b)), \
                patch.object(alerting, "_publish_security_hub_finding"):
            alerting.lambda_handler(_alert_record(), None)
        assert published.get("kill_outcome") == enforcement.TERMINATE_UNSUPPORTED


class TestTheDispatcherRecordsTheInitialOutcome:
    """Without this, a deferred kill is invisible until the queue drains."""

    SOURCE_MARKER = "record_kill_outcome(parsed.session_id, kill_outcome)"

    def test_the_dispatcher_writes_the_outcome_it_has(self) -> None:
        source = (
            __import__("pathlib").Path(dispatcher.__file__).read_text(encoding="utf-8")
        )
        assert self.SOURCE_MARKER in source, (
            "the dispatcher does not record kill_outcome, so a session shows no "
            "kill state at all until the alert Lambda runs — and shows none ever "
            "if it does not"
        )


class TestRecordingNeverBreaksTheKill:
    """Bookkeeping must not be able to undo enforcement."""

    def test_a_write_failure_does_not_raise(self) -> None:
        from adapters.agentcore import session_registry

        with patch.object(session_registry, "_table", side_effect=RuntimeError("ddb down")), \
                patch.object(session_registry, "report_degraded") as degraded:
            session_registry.record_kill_outcome("s-1", enforcement.TERMINATE_CONFIRMED)
        assert degraded.called, "a lost outcome must be visible as degraded"

    def test_the_degraded_reason_names_the_write(self) -> None:
        from adapters.agentcore import session_registry

        with patch.object(session_registry, "_table", side_effect=RuntimeError("ddb down")), \
                patch.object(session_registry, "report_degraded") as degraded:
            session_registry.record_kill_outcome("s-1", enforcement.TERMINATE_FAILED)
        assert "kill outcome" in degraded.call_args.args[1].lower()
