"""Similarity helpers for Tier 3 cross-session detection.

SimHash for near-duplicate detection, cosine similarity for optional
embedding clusters, and prompt normalization/hashing utilities.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from collections.abc import Iterable

TOKEN_RE = re.compile(r"[a-z0-9_']+")


def normalize_prompt(text: str) -> str:
    """Normalize prompt text for hashing and lexical similarity."""
    text = (text or "").lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def prompt_hash(text: str) -> str:
    """Return a stable SHA-256 hash of normalized prompt text."""
    return hashlib.sha256(normalize_prompt(text).encode("utf-8")).hexdigest()


def tokens(text: str) -> list[str]:
    """Tokenize normalized prompt text for SimHash."""
    return TOKEN_RE.findall(normalize_prompt(text))


def _character_grams(text: str, size: int = 4) -> list[str]:
    """Build short character n-grams so SimHash catches light wording edits."""
    compact = normalize_prompt(text).replace(" ", "_")
    if len(compact) <= size:
        return [compact] if compact else []
    return [compact[idx: idx + size] for idx in range(0, len(compact) - size + 1)]


def simhash(text: str, bits: int = 64) -> int:
    """Return a 64-bit SimHash for near-duplicate prompt detection."""
    weights = [0] * bits
    counts = Counter(tokens(text) + _character_grams(text))
    for token, count in counts.items():
        digest = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16)
        for idx in range(bits):
            weights[idx] += count if digest & (1 << idx) else -count
    value = 0
    for idx, weight in enumerate(weights):
        if weight >= 0:
            value |= 1 << idx
    return value


def hamming_distance(left: int, right: int) -> int:
    """Return Hamming distance between two integer SimHash values."""
    return bin(int(left) ^ int(right)).count("1")


def cosine_similarity(left: Iterable[float], right: Iterable[float]) -> float:
    """Return cosine similarity for two embedding vectors."""
    left_values = [float(v) for v in left]
    right_values = [float(v) for v in right]
    if len(left_values) != len(right_values) or not left_values:
        return 0.0
    # strict=True is safe: unequal lengths already returned 0.0 above.
    dot = sum(a * b for a, b in zip(left_values, right_values, strict=True))
    left_norm = math.sqrt(sum(a * a for a in left_values))
    right_norm = math.sqrt(sum(b * b for b in right_values))
    if not left_norm or not right_norm:
        return 0.0
    return dot / (left_norm * right_norm)


def stable_hash(parts: Iterable[str]) -> str:
    """Return a stable short hash for deterministic IDs."""
    body = "|".join(str(part) for part in parts)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
