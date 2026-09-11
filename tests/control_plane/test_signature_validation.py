"""Custom signatures must be validated (compile + ReDoS) before storage."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from control_plane.schemas.management import CustomSignatureRequest
from control_plane.services import signatures_service


def _store():
    """Patch the DynamoDB table so a stored signature does not hit AWS."""
    table = MagicMock()
    ddb = patch("control_plane.services.signatures_service._dynamodb")
    scope = patch("control_plane.config.scope_id", return_value="local")
    return table, ddb, scope


class TestAddCustomSignature:
    def test_valid_pattern_is_stored_but_not_enforced(self):
        table, ddb, scope = _store()
        with ddb as mock_ddb, scope:
            mock_ddb.return_value.Table.return_value = table
            resp = signatures_service.add_custom_signature(
                CustomSignatureRequest(pattern=r"(?i)ignore\s+previous\s+instructions", category="jailbreak")
            )
        assert resp.stored is True
        assert resp.error == ""
        # Custom signatures are now loaded by the inline scanner (append-only).
        assert resp.enforced is True
        assert "enforced" in resp.note.lower()
        table.update_item.assert_called_once()

    def test_redos_pattern_is_rejected_and_not_stored(self):
        table, ddb, scope = _store()
        with ddb as mock_ddb, scope:
            mock_ddb.return_value.Table.return_value = table
            resp = signatures_service.add_custom_signature(
                CustomSignatureRequest(pattern=r"(a+)+$", category="x")
            )
        assert resp.stored is False
        assert "redos" in resp.error.lower()
        table.update_item.assert_not_called()

    def test_invalid_regex_is_rejected(self):
        table, ddb, scope = _store()
        with ddb as mock_ddb, scope:
            mock_ddb.return_value.Table.return_value = table
            resp = signatures_service.add_custom_signature(
                CustomSignatureRequest(pattern=r"(unclosed", category="x")
            )
        assert resp.stored is False
        assert "invalid regex" in resp.error.lower()
        table.update_item.assert_not_called()

    def test_empty_pattern_is_rejected(self):
        table, ddb, scope = _store()
        with ddb as mock_ddb, scope:
            mock_ddb.return_value.Table.return_value = table
            resp = signatures_service.add_custom_signature(CustomSignatureRequest(pattern="   "))
        assert resp.stored is False
        assert resp.error
        table.update_item.assert_not_called()
