"""Validate that all shipped signatures pass ReDoS screening.

This test runs in CI on every signature contribution to prevent
catastrophic backtracking patterns from reaching production.
"""
from __future__ import annotations

import re

import pytest

from vardoger.detection.signature_scanner import ALL_BUNDLED_SIGNATURES, redos_risk


class TestReDoSSafety:
    """All bundled signatures must pass the ReDoS screen."""

    @pytest.mark.parametrize("sig", ALL_BUNDLED_SIGNATURES, ids=lambda s: s.id)
    def test_signature_is_redos_safe(self, sig):
        """Each signature pattern must not have catastrophic backtracking risk."""
        reason = redos_risk(sig.pattern)
        assert reason == "", f"Signature {sig.id} has ReDoS risk: {reason}"

    @pytest.mark.parametrize("sig", ALL_BUNDLED_SIGNATURES, ids=lambda s: s.id)
    def test_signature_compiles(self, sig):
        """Each signature pattern must be valid Python regex."""
        try:
            re.compile(sig.pattern)
        except re.error as exc:
            pytest.fail(f"Signature {sig.id} does not compile: {exc}")


class TestReDoSScreener:
    """The ReDoS screener correctly identifies known-dangerous patterns."""

    def test_nested_quantifier_detected(self):
        assert redos_risk(r"(a+)+$") != ""

    def test_alternation_under_quantifier_detected(self):
        assert redos_risk(r"(a|a)*$") != ""

    def test_safe_pattern_passes(self):
        assert redos_risk(r"(?i)ignore\s+previous\s+instructions") == ""

    def test_bounded_repetition_passes(self):
        assert redos_risk(r"(?i).{0,80}(password|secret)") == ""
