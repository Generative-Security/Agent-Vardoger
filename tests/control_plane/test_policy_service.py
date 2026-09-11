"""Tests for the admin policy-write path (control_plane/services/policy_service)."""
from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch

from control_plane.schemas.management import SecurityPolicy
from control_plane.services import policy_service


class TestPutPolicy:
    def test_put_policy_persists_and_bumps_version(self):
        table = MagicMock()
        with patch("control_plane.services.policy_service._dynamodb") as mock_ddb, \
                patch("control_plane.config.scope_id", return_value="local"), \
                patch("control_plane.services.policy_service.get_policy",
                      return_value=SecurityPolicy(policy_version=3)):
            mock_ddb.return_value.Table.return_value = table
            # The client's policy_version is ignored; the server increments the
            # stored version (3 -> 4).
            policy = SecurityPolicy(policy_version=999)
            result = policy_service.put_policy(policy, updated_by="admin-user")

        table.put_item.assert_called_once()
        item = table.put_item.call_args.kwargs["Item"]
        assert item["scope_id"] == "local"
        assert item["updated_by"] == "admin-user"
        # Version is server-owned: stored 3 + 1, not the client's 999.
        assert item["policy_version"] == 4
        assert result.policy_version == 4

    def test_thresholds_stored_as_decimal(self):
        table = MagicMock()
        with patch("control_plane.services.policy_service._dynamodb") as mock_ddb, \
                patch("control_plane.config.scope_id", return_value="local"):
            mock_ddb.return_value.Table.return_value = table
            policy_service.put_policy(SecurityPolicy(), updated_by="a")

        item = table.put_item.call_args.kwargs["Item"]
        # DynamoDB requires Decimal, not float, for numeric attributes.
        assert isinstance(item["tier2_high_risk_threshold"], Decimal)

    def test_get_policy_defaults_on_read_error(self):
        with patch("control_plane.services.policy_service._dynamodb") as mock_ddb, \
                patch("control_plane.config.scope_id", return_value="local"):
            mock_ddb.return_value.Table.return_value.get_item.side_effect = RuntimeError("ddb down")
            policy = policy_service.get_policy()
        # Fail-safe default is shadow mode (non-enforcing).
        assert policy.tier2_mode == "shadow"
        assert policy.tier3_mode == "shadow"
