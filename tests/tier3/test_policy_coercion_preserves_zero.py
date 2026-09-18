"""A stored threshold of 0.0 must survive being read.

`_to_float(x) or default` treats a legitimately stored 0.0 as absent and
restores the default -- so an operator who set a threshold to zero (the way you
disable one) silently got 0.90 back. Tier 2 used the value-preserving form on
the same record, so one policy row was interpreted two different ways depending
on which tier read it. vardoger/policy.py exists to stop exactly that.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from vardoger.coerce import to_float

TIER3 = Path(__file__).resolve().parents[2] / "vardoger" / "tier3" / "handler.py"


def test_to_float_distinguishes_zero_from_absent() -> None:
    assert to_float(0.0, 0.90) == 0.0
    assert to_float(None, 0.90) == 0.90
    assert to_float("", 0.90) == 0.90


@pytest.mark.parametrize("knob", ["tier3_similarity_threshold", "tier3_kill_threshold"])
def test_thresholds_are_not_read_with_the_or_default_pattern(knob: str) -> None:
    source = TIER3.read_text(encoding="utf-8")
    bad = re.search(rf'_to_float\([^)]*{knob}[^)]*\)\s*or\s', source)
    assert not bad, (
        f"{knob} is read as `_to_float(...) or default`, which turns a stored "
        "0.0 into the default and disagrees with how Tier 2 reads the same record"
    )
    # The default must be passed as _to_float's second argument. Matching from
    # the knob name forward, since `.get(...)` closes a paren in between.
    good = re.search(rf'{knob}"\s*\)\s*,\s*0\.\d+\)', source)
    assert good, f"{knob} no longer passes its default to _to_float"
