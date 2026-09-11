"""Prompt history must degrade like every other read endpoint, not 500.

It originally caught only ClientError. NoCredentialsError (and every other
BotoCoreError subclass) escaped, making this the single read endpoint that
returned HTTP 500 while the rest returned empty-and-degraded.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from botocore.exceptions import NoCredentialsError

from control_plane.services import prompt_history_service


class TestPromptHistoryDegrades:
    def test_missing_credentials_returns_warning_not_exception(self, capsys):
        table = MagicMock()
        table.query.side_effect = NoCredentialsError()
        with patch.object(prompt_history_service, "aws") as mock_aws:
            mock_aws.resource.return_value.Table.return_value = table
            result = prompt_history_service.search_prompt_history(hours=24, limit=10)

        assert result.records == []
        assert "unavailable" in (result.warning or "").lower()
        assert "dashboard_query" in capsys.readouterr().out

    def test_generic_failure_also_degrades(self):
        table = MagicMock()
        table.query.side_effect = RuntimeError("network down")
        with patch.object(prompt_history_service, "aws") as mock_aws:
            mock_aws.resource.return_value.Table.return_value = table
            result = prompt_history_service.search_prompt_history(hours=24, limit=10)
        assert result.records == [] and result.warning
