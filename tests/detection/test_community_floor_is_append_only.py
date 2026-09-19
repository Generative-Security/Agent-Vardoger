"""Remote and operator content may raise the detection floor, never lower it.

Premium signatures load from an S3 bucket outside the repository; custom
signatures come from an operator's own table. Neither is reviewed by whoever
reviews the bundled set. If either could claim an existing id, a compromised
feed, a bad publish or a careless custom rule could silently disable a bundled
detection by shipping the same id with a weaker pattern — and nothing would
fail. The scanner would simply stop catching something it used to catch.

DESIGN-DECISIONS.md described the opposite of the shipped behaviour for a while
("premium overriding community on id collision"), which is why this guards the
document as well as the code. A security property that only one of the two
states is a property nobody can rely on.
"""
from __future__ import annotations

from pathlib import Path

from vardoger.detection.models import RegexPattern
from vardoger.detection.signature_scanner import _append_only

DESIGN_DOC = Path(__file__).resolve().parents[2] / "DESIGN-DECISIONS.md"


def _sig(sig_id: str, pattern: str = "attack") -> RegexPattern:
    return RegexPattern(id=sig_id, severity="high", category="test", pattern=pattern)


def test_an_addition_cannot_replace_a_protected_id() -> None:
    community = [_sig("sig-community-1", "dangerous")]
    protected = {"sig-community-1"}
    seen = {"sig-community-1"}

    dropped = _append_only(
        community,
        [_sig("sig-community-1", "harmless")],  # same id, weaker pattern
        protected,
        seen,
        "premium",
    )

    assert dropped == 1
    assert len(community) == 1
    assert community[0].pattern == "dangerous", (
        "a premium signature overwrote a bundled one; the community floor is gone"
    )


def test_a_new_id_is_still_accepted() -> None:
    """Append-only must not mean append-nothing."""
    community = [_sig("sig-community-1")]
    dropped = _append_only(
        community, [_sig("sig-premium-9")], {"sig-community-1"}, {"sig-community-1"}, "premium",
    )
    assert dropped == 0
    assert [s.id for s in community] == ["sig-community-1", "sig-premium-9"]


def test_duplicate_additions_are_not_double_counted() -> None:
    community: list[RegexPattern] = []
    seen: set[str] = set()
    _append_only(community, [_sig("sig-premium-9")], set(), seen, "premium")
    _append_only(community, [_sig("sig-premium-9")], set(), seen, "custom")
    assert [s.id for s in community] == ["sig-premium-9"]


def test_custom_signatures_are_held_to_the_same_rule() -> None:
    """An operator must not be able to shadow a bundled detection either."""
    community = [_sig("sig-community-1", "dangerous")]
    dropped = _append_only(
        community, [_sig("sig-community-1", "")], {"sig-community-1"}, {"sig-community-1"}, "custom",
    )
    assert dropped == 1
    assert community[0].pattern == "dangerous"


def test_the_design_doc_does_not_claim_premium_overrides_community() -> None:
    text = DESIGN_DOC.read_text(encoding="utf-8").lower()
    assert "premium overriding community" not in text, (
        "DESIGN-DECISIONS.md claims premium overrides community on id collision; "
        "the scanner is append-only and drops such additions"
    )
    assert "append-only" in text, (
        "DESIGN-DECISIONS.md no longer explains the community floor, which is a "
        "security property rather than an implementation detail"
    )
