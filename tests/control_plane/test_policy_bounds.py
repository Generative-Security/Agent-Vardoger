"""SecurityPolicy must bound thresholds/counts so a single admin PUT cannot
configure a total agent-DoS (kill everything), and policy_version is
server-owned."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from control_plane.schemas.management import SecurityPolicy
from control_plane.services import policy_service


class TestPolicyBounds:
    def test_zero_kill_threshold_rejected(self):
        with pytest.raises(ValidationError):
            SecurityPolicy(tier2_default_kill_threshold=0.0)

    def test_zero_min_sessions_rejected(self):
        with pytest.raises(ValidationError):
            SecurityPolicy(tier3_min_sessions_for_kill=0)

    def test_threshold_above_one_rejected(self):
        with pytest.raises(ValidationError):
            SecurityPolicy(tier3_kill_threshold=1.5)

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValidationError):
            SecurityPolicy(tier2_mode="killeverything")

    def test_sane_policy_accepted(self):
        p = SecurityPolicy(tier2_mode="enforce", tier2_default_kill_threshold=0.9)
        assert p.tier2_mode == "enforce"
        assert p.tier2_default_kill_threshold == 0.9


class TestPolicyVersionServerOwned:
    def test_version_is_incremented_from_stored_not_client(self):
        table = MagicMock()
        with patch("control_plane.services.policy_service._dynamodb") as mock_ddb, \
                patch("control_plane.config.scope_id", return_value="local"), \
                patch("control_plane.services.policy_service.get_policy",
                      return_value=SecurityPolicy(policy_version=7)):
            mock_ddb.return_value.Table.return_value = table
            # Client tries to force version 999; server must ignore it.
            result = policy_service.put_policy(SecurityPolicy(policy_version=999), updated_by="admin")
        item = table.put_item.call_args.kwargs["Item"]
        assert item["policy_version"] == 8  # stored 7 + 1, client's 999 ignored
        assert result.policy_version == 8
