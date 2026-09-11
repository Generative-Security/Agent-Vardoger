"""Inline-path round-trip budget for the session registry.

Tier 1 runs synchronously in the gateway with a <30ms detection budget and a
fail-closed design, so every avoidable DynamoDB round trip is latency charged to
a real user's request. Status and risk live on the same item, and so do the two
post-detection updates; each pair is now a single call.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from adapters.agentcore import session_registry


class TestSingleRead:
    def test_get_session_reads_the_item_once(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "session_id": "s1",
                "status": "active",
                "accumulated_risk_score": "4.5",
                "prompts_seen": 2,
                "intent_counts": {"instruction_override": 1},
                "last_risk_epoch": "1700000000.0",
            }
        }
        with patch.object(session_registry, "_table", return_value=table):
            session = session_registry.get_session("s1")

        assert table.get_item.call_count == 1
        assert session["status"] == "active"
        assert session["accumulated_risk_score"] == 4.5
        assert session["prompts_seen"] == 2

    def test_unknown_session_yields_first_seen_state(self):
        table = MagicMock()
        table.get_item.return_value = {}
        with patch.object(session_registry, "_table", return_value=table):
            session = session_registry.get_session("nope")

        assert session["status"] is None
        assert session["prompts_seen"] == 0
        assert session["intent_counts"] == {}

    def test_get_session_risk_returns_empty_for_unknown_session(self):
        # The risk scorer treats {} as "no prior state"; zeros would be wrong.
        table = MagicMock()
        table.get_item.return_value = {}
        with patch.object(session_registry, "_table", return_value=table):
            assert session_registry.get_session_risk("nope") == {}


class TestSingleWrite:
    def test_risk_and_decision_persist_in_one_update(self):
        table = MagicMock()
        with patch.object(session_registry, "_table", return_value=table):
            session_registry.record_session_evaluation(
                "s1",
                accumulated_risk_score=9.0,
                prompts_seen=3,
                intent_counts={"secret_extraction": 1},
                decision="block",
                risk_score=12,
                matched_signature_ids=["sig-001"],
            )

        assert table.update_item.call_count == 1
        kwargs = table.update_item.call_args.kwargs
        expr = kwargs["UpdateExpression"]
        # Both halves in one atomic expression: a session can never be observed
        # with new risk but a stale decision.
        assert "accumulated_risk_score" in expr and "last_decision" in expr
        values = kwargs["ExpressionAttributeValues"]
        assert values[":status"] == "terminated"   # block => terminated
        assert values[":signatures"] == ["sig-001"]

    def test_allow_decision_keeps_session_active(self):
        table = MagicMock()
        with patch.object(session_registry, "_table", return_value=table):
            session_registry.record_session_evaluation(
                "s1",
                accumulated_risk_score=1.0,
                prompts_seen=1,
                intent_counts={},
                decision="allow",
            )
        assert table.update_item.call_args.kwargs["ExpressionAttributeValues"][":status"] == "active"


class TestAuditFailureIsObservable:
    def test_detection_event_write_failure_reports_degraded(self, capsys):
        table = MagicMock()
        table.put_item.side_effect = RuntimeError("ddb down")
        with patch.object(session_registry, "_events_table", return_value=table):
            # Must not raise: an audit-write failure cannot break detection.
            session_registry.record_detection_event(
                session_id="s1", scope_id="local", source="acct/agent", decision="block"
            )
        assert "detection_events" in capsys.readouterr().out
