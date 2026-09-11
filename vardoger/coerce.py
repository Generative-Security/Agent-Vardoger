"""Defensive type coercion for values read from DynamoDB and the environment.

DynamoDB returns numbers as ``Decimal``, optional attributes as absent keys, and
list-ish attributes as list, set, or bare scalar depending on how they were
written. Env vars are always strings and may be typo'd. Every consumer needs the
same small set of "give me an int, and never raise" helpers.

Before this module those helpers existed five times over — twice in the Tier 2
handler, twice in Tier 3, and again across three control-plane services — and
they had **drifted**: Tier 2's ``_to_int`` took an explicit default while
Tier 3's did not, so the two tiers could read the same stored policy record and
disagree about what it said. See ``vardoger/policy.py`` for how that is now
resolved.

Every function here is total: it returns the supplied default rather than
raising, because these sit on the detection path where an exception means a
fail-closed block of a legitimate request.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any


def to_int(value: Any, default: int = 0) -> int:
    """Return ``value`` as an int, or ``default`` when absent/unparseable.

    Routed through ``float`` first so a Decimal("3.0") or the string "3.0"
    coerces cleanly rather than raising.
    """
    if isinstance(value, Decimal):
        return int(value)
    if value is None or value == "":
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: float = 0.0) -> float:
    """Return ``value`` as a float, or ``default`` when absent/unparseable."""
    if isinstance(value, Decimal):
        return float(value)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def to_bool(value: Any, default: bool = True) -> bool:
    """Return ``value`` as a bool, or ``default`` when absent.

    Note the default is True: these are policy flags whose safe reading is
    "enabled" (e.g. ``tier2_require_repeated_malicious``, a guard that makes
    killing *harder*). A missing guard flag must not silently disable the guard.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    if value is None:
        return default
    return bool(value)


def to_str_list(value: Any) -> list[str]:
    """Normalize a list/set/scalar attribute into a list of strings."""
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    if value:
        return [str(value)]
    return []


def to_str_tuple(value: Any) -> tuple[str, ...]:
    """Normalize a list/set/scalar attribute into a tuple of strings.

    Tuple variant for the frozen dataclasses in Tier 3, which need hashable
    fields.
    """
    return tuple(to_str_list(value))
