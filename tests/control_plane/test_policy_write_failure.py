"""A failed policy write must be reported as a failure, never as success.

This policy governs whether the async tiers may terminate live sessions, so an
operator who believes they switched to enforce (or back to shadow) when the
write never landed is operating on a false picture. The write path originally
had no error handling at all, so a store failure surfaced as an unhandled 500.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import NoCredentialsError
from fastapi import HTTPException

from control_plane.routers import policy as policy_router
from control_plane.schemas.management import SecurityPolicy
from control_plane.services import policy_service


class TestPolicyWriteFailure:
    def test_store_failure_raises_domain_error_not_boto_error(self, capsys):
        table = MagicMock()
        table.put_item.side_effect = NoCredentialsError()
        with patch.object(policy_service, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            with pytest.raises(policy_service.PolicyWriteError) as excinfo:
                policy_service.put_policy(SecurityPolicy(), updated_by="tester")

        assert "could not be saved" in str(excinfo.value).lower()
        # The operator is told the previous policy still applies.
        assert "still in effect" in str(excinfo.value).lower()
        assert "tenant_policy" in capsys.readouterr().out

    def test_router_translates_to_503_with_detail(self):
        with patch.object(
            policy_service, "put_policy", side_effect=policy_service.PolicyWriteError("store down")
        ):
            with pytest.raises(HTTPException) as excinfo:
                policy_router.put_policy(SecurityPolicy(), principal=MagicMock(subject="admin"))

        # 503, not a generic 500 — and the reason reaches the dashboard.
        assert excinfo.value.status_code == 503
        assert "store down" in excinfo.value.detail

    def test_successful_write_returns_the_stored_policy(self):
        table = MagicMock()
        with patch.object(policy_service, "_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = table
            mock_ddb.return_value.Table.return_value.get_item.return_value = {}
            result = policy_service.put_policy(SecurityPolicy(tier2_mode="enforce"), updated_by="admin")

        assert table.put_item.call_count == 1
        assert result.tier2_mode == "enforce"
        assert result.updated_by == "admin"
