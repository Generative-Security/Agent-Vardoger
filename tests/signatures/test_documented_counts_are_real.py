"""The signature counts in the docs must match the signatures that ship.

README.md and docs/capabilities.md both advertise "92 bundled signatures", and
capabilities.md prices Tier 1 latency as "92 regexes over the text". CONTRIBUTING
actively asks for signature contributions, so the first accepted one makes every
copy of that number wrong -- quietly, because nothing else reads it.

A wrong count is a small thing to be wrong about and a bad thing to be caught
being wrong about: it is the most checkable claim on the front page, and a
reader who counts is a reader deciding whether to trust the rest.

This fails on any change to the bundled set, which is the point. Update the
number in the listed files, then update NUMBERS here.
"""
from __future__ import annotations

import re
from pathlib import Path

from signatures.community.hash_lookups import ALL_HASH_LOOKUPS
from signatures.community.mitre_atlas import ALL_MITRE_ATLAS
from signatures.community.named_jailbreaks import ALL_COMMUNITY_INTEL
from signatures.community.zero_day_patterns import ALL_ZERO_DAY

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every doc location that states a count, and which count it states.
CLAIMS = {
    "README.md": ["92 bundled signatures"],
    "docs/capabilities.md": [
        "92 bundled signatures",
        "92 bundled regex signatures + 6 known-bad hashes",
        "92 regexes over the text",
    ],
}


def test_bundled_signature_count_is_ninety_two() -> None:
    total = len(ALL_MITRE_ATLAS) + len(ALL_COMMUNITY_INTEL) + len(ALL_ZERO_DAY)
    assert total == 92, (
        f"bundled signature count is now {total}, not 92. Update the count in "
        f"{', '.join(CLAIMS)} and in NUMBERS in this test."
    )


def test_bundled_hash_count_is_six() -> None:
    assert len(ALL_HASH_LOOKUPS) == 6, (
        f"known-bad hash count is now {len(ALL_HASH_LOOKUPS)}, not 6. "
        "docs/capabilities.md states it."
    )


def test_docs_state_the_counts_they_are_supposed_to() -> None:
    """Guard the phrasing too, so a reworded doc cannot drop the claim silently."""
    for relative, phrases in CLAIMS.items():
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for phrase in phrases:
            assert phrase in text, f"{relative} no longer says {phrase!r}"


def test_no_other_doc_states_a_different_signature_count() -> None:
    """A count that drifted into another doc would not be covered by CLAIMS."""
    pattern = re.compile(r"(\d+)\s+(?:bundled\s+)?(?:regex\s+)?signatures")
    for path in sorted(REPO_ROOT.glob("docs/*.md")) + [REPO_ROOT / "README.md"]:
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            assert match.group(1) == "92", (
                f"{path.name} states {match.group(0)!r}, which disagrees with the "
                "92 signatures that actually ship"
            )
