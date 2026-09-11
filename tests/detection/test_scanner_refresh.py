"""The engine's scanner refresh must never downgrade mid-life.

A transient premium/custom load blip yields a smaller signature set; the engine
must keep the richer previous scanner rather than silently dropping to
community-only (which would weaken detection on a warm container).
"""
from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

from vardoger.detection.engine import DetectionEngine
from vardoger.detection.signature_scanner import ALL_BUNDLED_SIGNATURES, SignatureScanner


def _scanner_with(n_extra: int) -> SignatureScanner:
    sigs = list(ALL_BUNDLED_SIGNATURES)
    for i in range(n_extra):
        sigs.append(replace(ALL_BUNDLED_SIGNATURES[0], id=f"extra-{i}", pattern=f"extra-pattern-{i}"))
    return SignatureScanner(sigs)


class TestRefreshNoDowngrade:
    def _engine(self):
        # Construct with explicit signatures so __init__ does not hit the
        # network, then force the refresh time gate open.
        engine = DetectionEngine(scanner_reinit_seconds=1.0, signatures=list(ALL_BUNDLED_SIGNATURES))
        engine._signature_scanner_loaded_at = 0.0  # make the interval elapse
        return engine

    def test_keeps_previous_when_refresh_is_smaller(self):
        engine = self._engine()
        # Seed a richer scanner (as if premium was loaded).
        engine.signature_scanner = _scanner_with(5)
        rich_count = engine.signature_scanner.pattern_count

        # Refresh returns community-only (premium blip) -> must NOT downgrade.
        with patch("vardoger.detection.engine.build_scanner", return_value=_scanner_with(0)):
            engine._refresh_signature_scanner_if_needed()

        assert engine.signature_scanner.pattern_count == rich_count

    def test_accepts_larger_or_equal_refresh(self):
        engine = self._engine()
        engine.signature_scanner = _scanner_with(2)
        with patch("vardoger.detection.engine.build_scanner", return_value=_scanner_with(9)):
            engine._refresh_signature_scanner_if_needed()
        assert engine.signature_scanner.pattern_count == _scanner_with(9).pattern_count

    def test_refresh_exception_keeps_previous(self):
        engine = self._engine()
        engine.signature_scanner = _scanner_with(3)
        rich_count = engine.signature_scanner.pattern_count
        with patch("vardoger.detection.engine.build_scanner", side_effect=RuntimeError("s3 down")):
            engine._refresh_signature_scanner_if_needed()
        assert engine.signature_scanner.pattern_count == rich_count
