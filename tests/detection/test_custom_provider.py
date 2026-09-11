"""Custom-signature loading: opt-in, validated, append-only into the scanner."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from vardoger.detection import custom_provider
from vardoger.detection.signature_scanner import ALL_BUNDLED_SIGNATURES, build_scanner


def _item(custom_signatures):
    return {"Item": {"scope_id": "local", "custom_signatures": custom_signatures}}


def _entry(sig_id, pattern, **kw):
    e = {"signature_id": sig_id, "pattern": pattern, "category": "custom", "severity": "high"}
    e.update(kw)
    return e


class TestLoadCustomSignatures:
    def test_disabled_by_default_returns_empty(self):
        # No env flag -> no DynamoDB call, empty result.
        with patch("vardoger.detection.custom_provider.aws.table") as mock_table:
            out = custom_provider.load_custom_signatures()
        assert out == []
        mock_table.assert_not_called()

    def test_enabled_loads_valid_signatures(self):
        table = MagicMock()
        table.get_item.return_value = _item([_entry("custom-1", r"attack-\d+")])
        with patch.dict("os.environ", {"VARDOGER_LOAD_CUSTOM_SIGNATURES": "true"}), \
                patch("vardoger.detection.custom_provider.aws.table", return_value=table):
            out = custom_provider.load_custom_signatures()
        assert [s.id for s in out] == ["custom-1"]

    def test_enabled_skips_redos_and_invalid(self):
        table = MagicMock()
        table.get_item.return_value = _item([
            _entry("bad-redos", r"(a+)+$"),
            _entry("bad-regex", r"(unclosed"),
            _entry("good", r"safe-pattern"),
            {"pattern": "no-id"},
        ])
        with patch.dict("os.environ", {"VARDOGER_LOAD_CUSTOM_SIGNATURES": "true"}), \
                patch("vardoger.detection.custom_provider.aws.table", return_value=table):
            out = custom_provider.load_custom_signatures()
        assert [s.id for s in out] == ["good"]

    def test_read_error_is_failsafe_empty(self):
        table = MagicMock()
        table.get_item.side_effect = RuntimeError("ddb down")
        with patch.dict("os.environ", {"VARDOGER_LOAD_CUSTOM_SIGNATURES": "true"}), \
                patch("vardoger.detection.custom_provider.aws.table", return_value=table):
            out = custom_provider.load_custom_signatures()
        assert out == []


class TestBuildScannerCustomAppendOnly:
    def test_custom_cannot_override_community(self):
        community_id = ALL_BUNDLED_SIGNATURES[0].id
        with patch("vardoger.detection.premium_provider.load_premium_signatures", return_value=[]), \
                patch("vardoger.detection.custom_provider.load_custom_signatures",
                      return_value=[
                          custom_provider.RegexPattern(
                              id=community_id, severity="high", category="custom",
                              pattern="SHOULD_NOT_REPLACE",
                          )
                      ]):
            scanner = build_scanner()
        matching = [e for e in scanner._compiled if e[0] == community_id]
        assert len(matching) == 1
        assert matching[0][3].pattern == ALL_BUNDLED_SIGNATURES[0].pattern

    def test_custom_new_id_is_added(self):
        with patch("vardoger.detection.premium_provider.load_premium_signatures", return_value=[]), \
                patch("vardoger.detection.custom_provider.load_custom_signatures",
                      return_value=[
                          custom_provider.RegexPattern(
                              id="custom-new", severity="high", category="custom",
                              pattern="brand-new-pattern",
                          )
                      ]):
            scanner = build_scanner()
        assert "custom-new" in {e[0] for e in scanner._compiled}
