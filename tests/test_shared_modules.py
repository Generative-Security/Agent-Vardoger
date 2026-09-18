"""Tests for the shared infrastructure modules extracted during the
code-quality pass: bounded AWS clients, degraded-state reporting, coercion,
and the unified tier policy parser.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from vardoger import aws, coerce, health, policy


class TestAwsClientProfiles:
    def test_inline_profile_is_short_and_single_attempt(self):
        # The inline profile guards the fail-closed interceptor: a hung AWS call
        # must not burn the Lambda budget and block a legitimate user.
        cfg = aws.INLINE_CONFIG
        assert cfg.connect_timeout <= 1.0
        assert cfg.read_timeout <= 2.0
        assert cfg.retries["max_attempts"] == 1

    def test_async_profile_favours_durability(self):
        cfg = aws.ASYNC_CONFIG
        assert cfg.read_timeout >= cfg.connect_timeout
        assert cfg.retries["max_attempts"] > 1

    def test_clients_are_cached_per_kind(self):
        aws.reset_cache()
        with patch("boto3.client") as mock_client:
            mock_client.side_effect = lambda *a, **k: MagicMock()
            first = aws.client("sqs", kind="inline")
            second = aws.client("sqs", kind="inline")
            other = aws.client("sqs", kind="async")
        assert first is second           # cached
        assert first is not other        # but not across profiles
        aws.reset_cache()

    def test_unknown_kind_rejected(self):
        aws.reset_cache()
        try:
            aws.client("sqs", kind="whatever")
        except ValueError as exc:
            assert "inline" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ValueError for unknown client kind")


class TestReportDegraded:
    def test_emits_emf_metric_with_component_dimension(self, capsys):
        health.report_degraded(health.PREMIUM_SIGNATURES, "s3 unavailable", bucket="b")
        payload = json.loads(capsys.readouterr().out.strip().splitlines()[0])
        assert payload["component"] == health.PREMIUM_SIGNATURES
        assert payload["DegradedComponents"] == 1
        assert payload["bucket"] == "b"
        metric = payload["_aws"]["CloudWatchMetrics"][0]
        assert metric["Namespace"] == "AgentVardoger"
        assert metric["Dimensions"] == [["component"]]

    def test_never_raises_on_unserializable_context(self):
        # Reporting a degradation must never become the failure it reports.
        health.report_degraded(health.ENFORCEMENT, "boom", obj=object())


class TestCoerce:
    def test_to_int_handles_decimal_string_and_junk(self):
        from decimal import Decimal

        assert coerce.to_int(Decimal("7")) == 7
        assert coerce.to_int("3.0") == 3
        assert coerce.to_int(None, 5) == 5
        assert coerce.to_int("nonsense", 5) == 5
        assert coerce.to_int("", 5) == 5

    def test_to_bool_defaults_true_for_missing_guard_flags(self):
        # Policy guards make killing HARDER; a missing flag must not disable one.
        assert coerce.to_bool(None) is True
        assert coerce.to_bool("false") is False
        assert coerce.to_bool(False) is False

    def test_str_list_and_tuple_normalize_scalars_and_sets(self):
        assert coerce.to_str_list("a") == ["a"]
        assert sorted(coerce.to_str_list({"a", "b"})) == ["a", "b"]
        assert coerce.to_str_tuple(None) == ()
        assert isinstance(coerce.to_str_tuple(["a"]), tuple)


class TestPolicyParser:
    def test_unknown_mode_falls_back_to_shadow_never_enforce(self):
        assert policy.normalize_mode("bogus", "enforce") == "shadow"
        assert policy.normalize_mode(None, "enforce") == "enforce"

    def test_counts_clamp_to_at_least_one(self):
        # A stored 0 would mean "terminate with no corroborating evidence".
        parsed = policy.policy_from_item({
            "tier3_min_sessions_for_kill": 0,
            "tier2_min_malicious_verdicts_for_kill": 0,
        })
        assert parsed["tier3_min_sessions_for_kill"] == 1
        assert parsed["tier2_min_malicious_verdicts_for_kill"] == 1

    def test_both_tiers_parse_the_same_record_identically(self):
        # The drift this module exists to fix: Tier 2 honored a stored 0 while
        # Tier 3 replaced it with the default.
        from vardoger.tier2 import handler as t2
        from vardoger.tier3 import handler as t3

        item = {"tier3_min_sessions_for_kill": 0, "tier3_kill_threshold": 0.5}
        assert (
            t2._tenant_policy_from_item(item)["tier3_min_sessions_for_kill"]
            == t3._tenant_policy_from_item(item)["tier3_min_sessions_for_kill"]
        )

    def test_legacy_enabled_false_maps_to_off(self):
        parsed = policy.policy_from_item({"tier2_enabled": False}, tier2_mode="shadow")
        assert parsed["tier2_mode"] == "off"

    def test_read_failure_returns_shadow_defaults_and_reports_degraded(self, capsys):
        policy.invalidate_cache()
        with patch("vardoger.policy.aws.table", side_effect=RuntimeError("ddb down")):
            result = policy.load("local", "SomeTable", tier2_mode="enforce")
        # Fails safe: never enforce off a failed read.
        assert result["tier2_mode"] == "enforce"  # the caller's configured default
        assert result["tier3_min_sessions_for_kill"] == 3
        assert health.TENANT_POLICY in capsys.readouterr().out
        policy.invalidate_cache()

    def test_load_is_cached_within_ttl(self):
        policy.invalidate_cache()
        table = MagicMock()
        table.get_item.return_value = {"Item": {"scope_id": "local", "tier2_mode": "enforce"}}
        with patch("vardoger.policy.aws.table", return_value=table):
            first = policy.load("local", "T")
            second = policy.load("local", "T")
        assert first["tier2_mode"] == "enforce"
        assert second["tier2_mode"] == "enforce"
        # One DynamoDB read served both calls — this is what removes a round
        # trip from every Tier 2 prompt.
        assert table.get_item.call_count == 1
        policy.invalidate_cache()


class TestConfigIsolation:
    """A client must not be able to rewrite the profile the next one gets."""

    def test_building_a_client_does_not_mutate_the_shared_profile(self):
        """botocore normalises `retries` IN PLACE on the Config it is handed.

        Handing out the module-level object let the first client constructed
        replace `max_attempts` with `total_max_attempts` for every later client.
        Nothing caught it until a test happened to build a real client first.
        """
        before = dict(aws.ASYNC_CONFIG.retries)
        aws.reset_cache()
        try:
            aws.client("sns", kind="async", region="us-east-1")
        except Exception:
            pass  # no credentials in CI; construction alone is what mutates
        finally:
            aws.reset_cache()
        assert aws.ASYNC_CONFIG.retries == before, (
            "building a client rewrote the shared ASYNC_CONFIG; every later "
            "client would get a different retry profile than the one declared"
        )

    def test_each_client_gets_its_own_config_object(self):
        assert aws._config("async") is not aws.ASYNC_CONFIG
        assert aws._config("async") is not aws._config("async")
        assert aws._config("async").retries == aws.ASYNC_CONFIG.retries
