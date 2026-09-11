"""The dashboard must derive all its panels from ONE DetectionEvents scan.

Before this, the timeline, category breakdown, signature breakdown and Tier 3
findings each issued their own full table scan, so a single 30s dashboard poll
cost five scans of the same table and every extra viewer multiplied it.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from control_plane.services import session_query


def _event(ts, decision="block", provenance="dispatcher", sigs=("sig-001",)):
    return {
        "event_id": f"e-{ts}",
        "event_ts": ts,
        "scope_id": "local",
        "source": "111122223333/agent",
        "decision": decision,
        "matched_signatures": list(sigs),
        "risk_score": 9,
        "attack_intents": ["instruction_override"],
        "matched_policy_rules": [],
        "provenance": provenance,
    }


def _rows():
    now = int(time.time())
    return [
        _event(now - 60),
        _event(now - 120, decision="allow"),
        _event(now - 180, provenance="tier3"),
    ]


class TestScanCollapse:
    def setup_method(self):
        session_query.invalidate_detection_cache()

    def teardown_method(self):
        session_query.invalidate_detection_cache()

    def test_summary_issues_one_detection_events_scan(self):
        """The whole dashboard costs one scan of DetectionEvents."""
        table = MagicMock()
        table.scan.return_value = {"Items": _rows()}

        with patch.object(session_query, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            summary = session_query.get_dashboard_summary(hours=24, interval="1h")

        # One scan for DetectionEvents + one for SessionRegistry (a different
        # table, reached through the same mock).
        assert table.scan.call_count == 2
        assert summary.timeline and summary.detections
        # Tier 3 findings are filtered in memory from the same rows.
        assert [f.event_id for f in summary.tier3_findings] == [_rows()[2]["event_id"]]

    def test_derived_views_share_the_cached_scan(self):
        table = MagicMock()
        table.scan.return_value = {"Items": _rows()}

        with patch.object(session_query, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            session_query.get_detection_events(24)
            session_query.get_detection_timeline(24, "1h")
            session_query.get_detections_by_category(24)
            session_query.get_detections_by_signature(24)
            session_query.get_tier3_findings(24)

        assert table.scan.call_count == 1, "five views must share one scan"

    def test_cache_is_keyed_by_source_so_filters_do_not_leak(self):
        """A source-filtered view must never be served another source's rows."""
        table = MagicMock()
        table.scan.return_value = {"Items": _rows()}

        with patch.object(session_query, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            session_query.get_detection_events(24, source="111122223333/agent")
            session_query.get_detection_events(24, source="999988887777/other")

        assert table.scan.call_count == 2, "different sources must not share a cache entry"

    def test_scan_failure_degrades_to_empty_not_exception(self):
        table = MagicMock()
        table.scan.side_effect = RuntimeError("dynamo down")

        with patch.object(session_query, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            assert session_query.get_detection_events(24) == []
            assert session_query.get_tier3_findings(24) == []


class TestFailurePathDoesNotFanOut:
    """A failing table must not turn one poll into five scans.

    The cache originally memoized only SUCCESS, so when the scan raised, every
    derived view retried independently — the most load on the table at exactly
    the moment it was least able to serve it, plus a degraded metric per retry.
    """

    def setup_method(self):
        session_query.invalidate_detection_cache()

    def teardown_method(self):
        session_query.invalidate_detection_cache()

    def test_summary_scans_once_even_when_the_scan_fails(self):
        table = MagicMock()
        table.scan.side_effect = RuntimeError("no credentials")

        with patch.object(session_query, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            summary = session_query.get_dashboard_summary(hours=24, interval="1h")

        # One DetectionEvents attempt + one SessionRegistry attempt.
        assert table.scan.call_count == 2
        assert summary.detections == [] and summary.tier3_findings == []

    def test_failure_is_cached_so_derived_views_do_not_retry(self):
        table = MagicMock()
        table.scan.side_effect = RuntimeError("no credentials")

        with patch.object(session_query, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            session_query.get_detection_events(24)
            session_query.get_detection_timeline(24, "1h")
            session_query.get_detections_by_category(24)
            session_query.get_tier3_findings(24)

        assert table.scan.call_count == 1, "a failed scan must not be retried per view"

    def test_failure_never_raises_to_the_caller(self):
        table = MagicMock()
        table.scan.side_effect = RuntimeError("boom")
        with patch.object(session_query, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            assert session_query.get_detection_events(24) == []
            assert session_query.get_detections_by_signature(24) == []
