"""Tier 2 with no ML endpoint configured — the DEFAULT self-hosted deployment.

Tier2Function is deployed in every configuration because it is the only writer
of PromptHistory, which the Prompt History page and Tier 3 both read. When no
SageMaker endpoint is attached it must still consume the queue and record the
prompt, and must do so as a *skip* rather than an error: counting it as an error
would retry every prompt to the dead-letter queue and bury genuine failures in
the error tally.
"""
import json

import pytest

from vardoger.tier2 import handler


@pytest.fixture
def captured(monkeypatch):
    """Stub every I/O boundary and capture what each path would have written."""
    seen: dict[str, list] = {"history": [], "results": [], "outcomes": [], "ml": []}

    monkeypatch.setattr(handler, "_put_prompt_history", lambda item: seen["history"].append(item) or True)
    monkeypatch.setattr(handler, "_mark_tenant_prompt_seen", lambda *a, **k: None)
    monkeypatch.setattr(handler, "_load_tenant_policy", lambda scope_id: {"policy_version": 3})
    monkeypatch.setattr(handler, "_record_tier2_result", lambda **kw: seen["results"].append(kw))
    monkeypatch.setattr(handler, "_write_tier2_outcome", lambda **kw: seen["outcomes"].append(kw))

    def _no_ml(*args, **kwargs):
        seen["ml"].append(args)
        raise AssertionError("ML must not be invoked when no endpoint is configured")

    monkeypatch.setattr(handler, "_invoke_ml", _no_ml)
    return seen


def _record(**overrides):
    body = {
        "prompt": "what are your store hours?",
        "session_id": "sess-1",
        "scope_id": "local",
        "source": "123456789012/support-agent",
        "decision": "allow",
        "timestamp": 1757000000,
        "prompt_id": "p-1",
        "agent_runtime_arn": "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/r",
        "runtime_session_id": "rt-1",
    }
    body.update(overrides)
    return {"body": json.dumps(body)}


class TestNoEndpointConfigured:
    def test_record_is_skipped_not_errored(self, monkeypatch, captured):
        monkeypatch.setattr(handler, "SAGEMAKER_ENDPOINT", "")
        outcome = handler._process_record(_record())
        # "skipped", not "error": a missing optional component is a
        # configuration state. An error status would send it back to the queue
        # and eventually to the DLQ, on every single prompt.
        assert outcome.status == "skipped"
        assert outcome.killed is False

    def test_prompt_history_is_still_written(self, monkeypatch, captured):
        """The whole point of deploying the function unconditionally."""
        monkeypatch.setattr(handler, "SAGEMAKER_ENDPOINT", "")
        handler._process_record(_record())
        assert len(captured["history"]) == 1
        assert captured["history"][0]["prompt"] == "what are your store hours?"

    def test_skip_reason_is_distinguishable_from_policy_off(self, monkeypatch, captured):
        """An operator must be able to tell "no model" from "I turned it off"."""
        monkeypatch.setattr(handler, "SAGEMAKER_ENDPOINT", "")
        handler._process_record(_record())

        (result,) = captured["results"]
        assert result["category"] == "tier2_no_endpoint"
        assert result["ml_verdict"] == "skipped_no_endpoint"
        assert result["kill_triggered"] is False

        (ledger,) = captured["outcomes"]
        assert ledger["category"] == "tier2_no_endpoint"
        assert ledger["kill_denied_reason"] == "no_ml_endpoint"
        assert ledger["model_version"] == "none"

    def test_tenant_policy_off_still_reports_policy_as_the_reason(self, monkeypatch, captured):
        """Policy is checked first: the explicit operator choice wins the label."""
        monkeypatch.setattr(handler, "SAGEMAKER_ENDPOINT", "")
        monkeypatch.setattr(handler, "_load_tenant_policy", lambda scope_id: {"tier2_mode": "off"})
        handler._process_record(_record())
        assert captured["outcomes"][0]["category"] == "tier2_disabled"
        assert captured["outcomes"][0]["kill_denied_reason"] == "tenant_mode_not_enforce"

    def test_tenant_supplied_endpoint_still_reaches_the_scored_path(self, monkeypatch, captured):
        """An endpoint in tenant policy overrides an empty environment default.

        Asserted at the routing boundary: the downstream scored path does its
        own session-history I/O, which is not what this test is about.
        """
        monkeypatch.setattr(handler, "SAGEMAKER_ENDPOINT", "")
        monkeypatch.setattr(
            handler, "_load_tenant_policy",
            lambda scope_id: {"tier2_model_endpoint": "my-endpoint", "tier2_mode": "shadow"},
        )
        routed = []
        monkeypatch.setattr(
            handler, "_handle_scored",
            lambda ctx: routed.append(ctx) or handler._RecordOutcome("processed"),
        )
        assert handler._process_record(_record()).status == "processed"
        assert routed and routed[0].tier2_model_endpoint == "my-endpoint"
        assert not captured["outcomes"], "must not take the no-endpoint shortcut"

    def test_layer1_block_takes_precedence_over_endpoint_state(self, monkeypatch, captured):
        """A Tier 1 block is recorded for audit regardless of ML availability."""
        monkeypatch.setattr(handler, "SAGEMAKER_ENDPOINT", "")
        routed = []
        monkeypatch.setattr(
            handler, "_handle_layer1_blocked",
            lambda ctx: routed.append(ctx) or handler._RecordOutcome("skipped"),
        )
        assert handler._process_record(_record(decision="block")).status == "skipped"
        assert routed, "a Tier 1 block must be audited, not dropped as no-endpoint"
        assert not captured["outcomes"], "must not take the no-endpoint shortcut"


class TestInvokeMlGuard:
    def test_empty_endpoint_names_the_cause(self, monkeypatch):
        """Defense in depth if the routing guard is ever bypassed."""
        monkeypatch.setattr(handler, "SAGEMAKER_ENDPOINT", "")
        with pytest.raises(ValueError, match="No Tier 2 ML endpoint configured"):
            handler._invoke_ml("some prompt")
