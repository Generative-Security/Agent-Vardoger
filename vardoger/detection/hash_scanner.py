"""Known-bad prompt hash scanner.

Matches prompts against a lookup table of SHA-256 hashes of known-malicious
prompts. Fast O(1) check before the more expensive regex scan.
"""
from __future__ import annotations

import hashlib

from signatures.community.hash_lookups import ALL_HASH_LOOKUPS


class HashScanner:
    """Match prompts against a lookup table of known-malicious SHA-256 hashes."""

    def __init__(self, lookups: list | None = None):
        self._hashes: dict[str, str] = {}
        source = lookups if lookups is not None else ALL_HASH_LOOKUPS
        for lookup in source:
            hash_value = lookup.hash.removeprefix("sha256:")
            self._hashes[hash_value] = lookup.id

    def scan(self, raw_prompt: str) -> list[str]:
        """Return signature IDs for any hash match against the raw or normalized prompt."""
        prompt_hash = hashlib.sha256(raw_prompt.encode("utf-8")).hexdigest()
        sig_id = self._hashes.get(prompt_hash)
        if sig_id:
            return [sig_id]
        normalized = raw_prompt.strip().lower()
        if normalized != raw_prompt:
            norm_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            sig_id = self._hashes.get(norm_hash)
            if sig_id:
                return [sig_id]
        return []
