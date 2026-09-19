"""A signature package applies whole, or not at all.

This is the property that keeps a bad publish from semi-corrupting a running
deployment: premium and custom packages are validated as a unit, and any failure
drops the whole package and falls back to what was already loaded. It is also
what lets the same design serve a SaaS "wholesale replace" model and the OSS
"community floor" model without the two disagreeing -- community is a fixed
base, each additive package is atomic, and collisions resolve one way.

Two holes existed. A malformed entry -- missing id or pattern -- was skipped
rather than rejecting the package, so a publish with three bad entries loaded as
a valid package minus three detections, indistinguishable from a package that
was published that way. And the check that the bundled floor had not shrunk only
logged, making the one case that means "the community set itself is gone" the
quietest signal in the module.

No test covered either, which is why both survived.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from vardoger.detection import signature_scanner
from vardoger.detection.signature_scanner import build_scanner, validate_and_parse


def _entries(count: int, start: int = 0) -> list[dict]:
    return [
        {"id": f"sig-test-{i:03d}", "pattern": f"attack{i}", "severity": "high", "category": "test"}
        for i in range(start, start + count)
    ]


# --- the package is atomic -------------------------------------------------

def test_a_clean_package_parses() -> None:
    parsed = validate_and_parse(_entries(25), min_patterns=20)
    assert parsed is not None and len(parsed) == 25


@pytest.mark.parametrize("bad", [
    pytest.param({"pattern": "attack", "severity": "high"}, id="missing-id"),
    pytest.param({"id": "sig-x", "severity": "high"}, id="missing-pattern"),
    pytest.param({"id": "", "pattern": "attack"}, id="empty-id"),
    pytest.param({"id": "sig-x", "pattern": ""}, id="empty-pattern"),
])
def test_one_malformed_entry_rejects_the_whole_package(bad: dict) -> None:
    """Not 'skip the bad one'. A partially applied package is the thing we are
    protecting against, and a silently smaller package is exactly that."""
    package = _entries(25) + [bad]
    assert validate_and_parse(package, min_patterns=20) is None


def test_one_bad_regex_rejects_the_whole_package() -> None:
    package = _entries(25) + [{"id": "sig-bad", "pattern": "([a-z]+", "severity": "high"}]
    assert validate_and_parse(package, min_patterns=20) is None


def test_one_redos_pattern_rejects_the_whole_package() -> None:
    package = _entries(25) + [{"id": "sig-redos", "pattern": "(a+)+$", "severity": "high"}]
    assert validate_and_parse(package, min_patterns=20) is None


def test_an_undersized_package_is_rejected() -> None:
    assert validate_and_parse(_entries(3), min_patterns=20) is None


# --- the community floor alarms -------------------------------------------

def test_a_healthy_build_does_not_alarm() -> None:
    """The guard must be quiet when nothing is wrong."""
    with patch.object(signature_scanner, "report_degraded") as degraded:
        build_scanner(include_premium=False, include_custom=False)
    assert degraded.call_count == 0


def test_the_floor_check_is_wired_to_report_degraded() -> None:
    """Structural, and deliberately so.

    The branch is UNREACHABLE in the current code: `signatures` starts as a copy
    of the community list and `_append_only` only ever appends, so the count can
    never fall below the number of distinct community ids. It is defense in
    depth against a future change to how the set is assembled.

    That makes it a guard nobody can trigger, which is exactly the kind that
    rots. Asserting its shape is the honest thing available -- pretending to
    exercise it would be theatre.
    """
    import inspect
    source = inspect.getsource(build_scanner)
    assert "report_degraded" in source, (
        "build_scanner logs a shrinking community floor but does not alarm; the "
        "refresh path alarms, so this was the quieter of the two signals"
    )
    assert "logger.error" in source, "the log line was removed along with it"
