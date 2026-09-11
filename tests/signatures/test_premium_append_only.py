"""Premium signatures must be append-only (cannot override community)."""
from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

from vardoger.detection.models import RegexPattern
from vardoger.detection.signature_scanner import ALL_BUNDLED_SIGNATURES, build_scanner


def _fake_pattern(sig_id: str, pattern: str = "zzz-unlikely-to-match-anything") -> RegexPattern:
    # Clone a real bundled signature and swap id/pattern so we match the exact
    # dataclass shape without hardcoding its fields.
    return replace(ALL_BUNDLED_SIGNATURES[0], id=sig_id, pattern=pattern)


class TestAppendOnly:
    def test_premium_new_id_is_added(self):
        premium = [_fake_pattern("premium-new-001")]
        with patch("vardoger.detection.premium_provider.load_premium_signatures", return_value=premium):
            scanner = build_scanner(include_premium=True)
        ids = {entry[0] for entry in scanner._compiled}
        assert "premium-new-001" in ids
        # Community set is fully retained.
        assert {s.id for s in ALL_BUNDLED_SIGNATURES}.issubset(ids)

    def test_premium_cannot_override_community_id(self):
        community_id = ALL_BUNDLED_SIGNATURES[0].id
        community_pattern = ALL_BUNDLED_SIGNATURES[0].pattern
        # A premium entry reusing a community id with a never-matching pattern.
        premium = [_fake_pattern(community_id, pattern="THIS_SHOULD_NEVER_REPLACE")]
        with patch("vardoger.detection.premium_provider.load_premium_signatures", return_value=premium):
            scanner = build_scanner(include_premium=True)
        # The community id is present exactly once and NOT replaced by premium.
        # _compiled entries are (id, severity, category, compiled_regex).
        matching = [entry for entry in scanner._compiled if entry[0] == community_id]
        assert len(matching) == 1
        assert matching[0][3].pattern == community_pattern

    def test_no_premium_uses_community_only(self):
        with patch("vardoger.detection.premium_provider.load_premium_signatures", return_value=[]):
            scanner = build_scanner(include_premium=True)
        assert scanner.pattern_count == len(ALL_BUNDLED_SIGNATURES)
