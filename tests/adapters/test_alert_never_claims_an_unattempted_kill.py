"""An alert must not report a termination that was never attempted.

With no `agent_runtime_arn` on the queued message there is nothing to call, and
the handler skipped straight to publishing. The operator got a "Session ...
terminated" alert; the registry row stayed on `deferred` forever, because the
write-back only happened inside the branch that ran the kill; and nothing
alarmed. Two records disagreeing, with the wrong one being the one a human
reads.

This is reachable in normal operation, not only through misconfiguration: on a
first deploy of the demo runtime or the test harness, pass one passes an empty
AgentRuntimeArn because the runtime does not exist yet, and only the second pass
fills it in.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from adapters.agentcore import alerting
from adapters.agentcore.enforcement import TERMINATE_NOT_CONFIGURED


def _event(**overrides):
    body = {
        "session_id": "sess-no-arn",
        "agent_runtime_arn": "",
        "reason": "Security detection",
        "risk_score": 12,
    }
    body.update(overrides)
    return {"Records": [{"messageId": "m-1", "body": json.dumps(body)}]}


@pytest.fixture
def spies():
    with patch.object(alerting, "record_kill_outcome") as record, \
         patch.object(alerting, "report_degraded") as degraded, \
         patch.object(alerting, "terminate_session_detailed") as terminate, \
         patch.object(alerting, "_publish_sns_alert") as sns, \
         patch.object(alerting, "_import_security_hub_finding", create=True):
        yield {"record": record, "degraded": degraded, "terminate": terminate, "sns": sns}


def test_no_runtime_arn_records_an_outcome_instead_of_leaving_it_deferred(spies) -> None:
    alerting.lambda_handler(_event(), None)

    spies["terminate"].assert_not_called()
    spies["record"].assert_called_once()
    args = spies["record"].call_args[0]
    assert args[0] == "sess-no-arn"
    assert args[1] == TERMINATE_NOT_CONFIGURED, (
        "the row must say the kill was never attempted, not sit on 'deferred'"
    )


def test_no_runtime_arn_raises_a_degraded_signal(spies) -> None:
    alerting.lambda_handler(_event(), None)
    spies["degraded"].assert_called_once()
    reason = str(spies["degraded"].call_args)
    assert "NOT terminated" in reason or "not terminated" in reason.lower()


def test_the_alert_subject_does_not_claim_termination(spies) -> None:
    alerting.lambda_handler(_event(), None)
    published = spies["sns"].call_args[0][0]
    subject = alerting._alert_subject(published["session_id"], published.get("kill_outcome", ""))
    assert "NOT terminated" in subject, f"subject still claims success: {subject!r}"


def test_a_real_kill_still_reports_termination(spies) -> None:
    """The guard must not make every alert hedge."""
    spies["terminate"].return_value = "confirmed"
    alerting.lambda_handler(_event(agent_runtime_arn="arn:aws:bedrock-agentcore:us-east-1:1:runtime/r"), None)

    spies["terminate"].assert_called_once()
    spies["degraded"].assert_not_called()
    published = spies["sns"].call_args[0][0]
    subject = alerting._alert_subject(published["session_id"], published["kill_outcome"])
    assert subject.endswith("terminated")
    assert "NOT" not in subject


@pytest.mark.parametrize("outcome,expected", [
    ("confirmed", "terminated"),
    ("unverified", "unverified"),
    ("failed", "failed"),
    ("unsupported", "unsupported"),
    (TERMINATE_NOT_CONFIGURED, "NOT terminated"),
])
def test_subject_matches_each_outcome(outcome: str, expected: str) -> None:
    assert expected in alerting._alert_subject("sess-abcdef12", outcome)
