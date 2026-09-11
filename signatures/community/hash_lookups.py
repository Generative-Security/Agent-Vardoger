"""Known-malicious prompt hashes.

SHA-256 hashes of confirmed malicious prompts for fast O(1) matching.
These are checked before the more expensive regex scan.
"""
from __future__ import annotations

from vardoger.detection.models import HashLookup

ALL_HASH_LOOKUPS: list[HashLookup] = [
    HashLookup(id="sig-h-001", severity="critical", category="known_jailbreak",
               hash="sha256:3cfcccf237c8ade4d5caf967f95af81eb9c55c82b3c2c7ef174cabf7465571d1"),
    HashLookup(id="sig-h-002", severity="high", category="prompt_injection",
               hash="sha256:9249e44c1522c277978e3a425049be8fe9c9f334d3cf4314a3ce01f5124212e0"),
    HashLookup(id="sig-h-003", severity="critical", category="skeleton_key",
               hash="sha256:b2be3fbf6a83da8906b401f83033a5b0631b3fe889f3d2267fbb6ed0246ec253"),
    HashLookup(id="sig-h-004", severity="high", category="known_jailbreak",
               hash="sha256:57c5af40373699409bb91e6d3a962cd11755c8096a168a23b6383d124524fef9"),
    HashLookup(id="sig-h-005", severity="high", category="known_jailbreak",
               hash="sha256:7d2650a332c70969dfe2948ce9b81d7398b2c8d715fade19964a26e9fc667102"),
    HashLookup(id="sig-h-006", severity="high", category="known_jailbreak",
               hash="sha256:0674d51fb28887289e464495a5c35f36154dae623825ffc5ac0c70686794da66"),
]
