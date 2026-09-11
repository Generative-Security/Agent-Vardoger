"""Regex signature scanner with dynamic loading support.

Scans prompt text against compiled regex patterns. Supports:
- Bundled community signatures (shipped with the repo)
- Dynamic signatures from a SignatureProvider (S3, HTTP feed, or local file)
- ReDoS screening to reject unsafe patterns before caching
"""
from __future__ import annotations

import logging
import re
from typing import Any

# All bundled community signatures.
from signatures.community.mitre_atlas import ALL_MITRE_ATLAS
from signatures.community.named_jailbreaks import ALL_COMMUNITY_INTEL
from signatures.community.zero_day_patterns import ALL_ZERO_DAY
from vardoger.detection.models import RegexPattern

logger = logging.getLogger(__name__)

ALL_BUNDLED_SIGNATURES: list[RegexPattern] = ALL_MITRE_ATLAS + ALL_COMMUNITY_INTEL + ALL_ZERO_DAY


# ---------------------------------------------------------------------------
# ReDoS screening
# ---------------------------------------------------------------------------

_QUANTIFIER_CHARS = frozenset("*+")


def _contains_quantifier(body: str) -> bool:
    """Return true when a regex fragment applies an unbounded quantifier."""
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char in _QUANTIFIER_CHARS:
            return True
        if char == "{":
            closing = body.find("}", index)
            if closing != -1:
                spec = body[index + 1: closing]
                if spec.endswith(","):
                    return True
                index = closing
        index += 1
    return False


def _contains_alternation(body: str) -> bool:
    """Return true when a regex fragment contains a top-level alternation."""
    index = 0
    depth = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            closing = index + 1
            while closing < len(body):
                if body[closing] == "\\":
                    closing += 2
                    continue
                if body[closing] == "]":
                    break
                closing += 1
            index = closing + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            return True
        index += 1
    return False


def _risky_group_body(body: str) -> str:
    """Return a reason when a quantified group's body is a backtracking risk."""
    if _contains_quantifier(body):
        return "nested quantifier"
    if _contains_alternation(body):
        return "alternation under unbounded quantifier"
    return ""


def _has_nested_quantifier(pattern: str) -> str:
    """Return a reason when a quantified group contains a backtracking risk."""
    stack: list[int] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            closing = index + 1
            while closing < len(pattern):
                if pattern[closing] == "\\":
                    closing += 2
                    continue
                if pattern[closing] == "]":
                    break
                closing += 1
            index = closing + 1
            continue
        if char == "(":
            stack.append(index)
        elif char == ")" and stack:
            start = stack.pop()
            following = pattern[index + 1: index + 2]
            is_quantified = following in ("*", "+")
            if following == "{":
                closing = pattern.find("}", index + 1)
                if closing != -1:
                    spec = pattern[index + 2: closing]
                    is_quantified = spec.endswith(",")
            if is_quantified:
                reason = _risky_group_body(pattern[start + 1: index])
                if reason:
                    return reason
        index += 1
    return ""


def redos_risk(pattern_str: str) -> str:
    """Screen a pattern for catastrophic backtracking, without executing it.

    Returns a short reason string when the pattern is unsafe, or "" when it passes.
    """
    return _has_nested_quantifier(pattern_str)


# ---------------------------------------------------------------------------
# Signature loading and validation
# ---------------------------------------------------------------------------


def validate_and_parse(
    data: list[dict[str, Any]],
    manifest_hash: str | None = None,
    raw_body: bytes | None = None,
    min_patterns: int = 20,
) -> list[RegexPattern] | None:
    """Validate a signature package and parse into RegexPattern list.

    Returns None if validation fails (caller should keep previous cache).
    """
    import hashlib as _hashlib

    if manifest_hash and raw_body:
        actual_hash = _hashlib.sha256(raw_body).hexdigest()
        if actual_hash != manifest_hash:
            logger.error("Signature hash mismatch: expected %s, got %s", manifest_hash, actual_hash)
            return None

    if len(data) < min_patterns:
        logger.error("Signature package too small: %d patterns (minimum %d)", len(data), min_patterns)
        return None

    patterns: list[RegexPattern] = []
    for item in data:
        sig_id = item.get("id")
        raw_pattern = item.get("pattern")
        if not sig_id or not raw_pattern:
            continue
        try:
            re.compile(raw_pattern)
        except re.error as exc:
            logger.error("Invalid regex in signature %s: %s", sig_id, exc)
            return None
        unsafe_reason = redos_risk(raw_pattern)
        if unsafe_reason:
            logger.error(
                "Rejecting signature package: pattern %s has catastrophic backtracking risk (%s)",
                sig_id, unsafe_reason,
            )
            return None
        patterns.append(RegexPattern(
            id=sig_id,
            severity=item.get("severity", "medium"),
            category=item.get("category", "unknown"),
            pattern=raw_pattern,
            mitre_atlas_id=item.get("mitre_atlas_id", ""),
        ))

    if len(patterns) < min_patterns:
        logger.error("Too few valid patterns after parsing: %d", len(patterns))
        return None

    return patterns


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SignatureScanner:
    """Scan prompt text against compiled regex detection signatures."""

    def __init__(self, signatures: list[RegexPattern] | None = None):
        """Initialize with explicit signatures or fall back to bundled community set."""
        source = signatures if signatures is not None else ALL_BUNDLED_SIGNATURES
        self._compiled: list[tuple[str, str, str, re.Pattern[str]]] = []
        for sig in source:
            try:
                compiled = re.compile(sig.pattern)
                self._compiled.append((sig.id, sig.severity, sig.category, compiled))
            except re.error as exc:
                logger.error("Failed to compile regex for %s: %s", sig.id, exc)

    def scan(self, text: str) -> list[str]:
        """Return IDs of all signatures matched in the text."""
        matched_ids: list[str] = []
        for sig_id, _severity, _category, pattern in self._compiled:
            if pattern.search(text):
                matched_ids.append(sig_id)
        return matched_ids

    def scan_detailed(self, text: str) -> list[dict[str, str]]:
        """Return detailed match info (id, severity, category) for each matched signature."""
        matches: list[dict[str, str]] = []
        for sig_id, severity, category, pattern in self._compiled:
            if pattern.search(text):
                matches.append({"id": sig_id, "severity": severity, "category": category})
        return matches

    @property
    def pattern_count(self) -> int:
        return len(self._compiled)


# ---------------------------------------------------------------------------
# Scanner construction (community + optional premium)
# ---------------------------------------------------------------------------


def _append_only(
    signatures: list[RegexPattern],
    additions: list[RegexPattern],
    protected_ids: set[str],
    seen_ids: set[str],
    source: str,
) -> int:
    """Append `additions` to `signatures` under the append-only rule.

    An addition may introduce a NEW id but may never override a protected
    (bundled/community) id, nor duplicate an already-seen id. Returns the number
    of additions dropped for attempting to override a protected id.
    """
    dropped = 0
    for sig in additions:
        if sig.id in protected_ids:
            dropped += 1
            continue
        if sig.id in seen_ids:
            continue
        seen_ids.add(sig.id)
        signatures.append(sig)
    if dropped:
        logger.warning(
            "Ignored %d %s signature(s) attempting to override community ids (append-only policy)",
            dropped,
            source,
        )
    return dropped


def build_scanner(include_premium: bool = True, include_custom: bool = True) -> SignatureScanner:
    """Build a scanner from bundled community signatures plus premium + custom.

    Signatures are combined APPEND-ONLY: premium and operator-authored custom
    signatures may add NEW ids but may never override or replace a bundled
    community signature by reusing its id. This prevents a compromised feed or a
    malicious custom entry from neutering community detections. Both sources are
    strictly additive; if either is unconfigured or fails to load, the scanner
    falls back to whatever loaded successfully (community always present).
    """
    community: list[RegexPattern] = list(ALL_BUNDLED_SIGNATURES)
    community_ids = {sig.id for sig in community}
    signatures: list[RegexPattern] = list(community)
    seen_ids: set[str] = set(community_ids)

    if include_premium:
        # Imported lazily to avoid a circular import (premium_provider imports
        # this module for validate_and_parse) and to keep boto3 optional.
        from vardoger.detection import premium_provider

        try:
            premium = premium_provider.load_premium_signatures()
        except Exception:
            logger.warning("Premium signature load failed; continuing without", exc_info=True)
            premium = []
        if premium:
            _append_only(signatures, premium, community_ids, seen_ids, "premium")

    if include_custom:
        from vardoger.detection import custom_provider

        try:
            custom = custom_provider.load_custom_signatures()
        except Exception:
            logger.warning("Custom signature load failed; continuing without", exc_info=True)
            custom = []
        if custom:
            _append_only(signatures, custom, community_ids, seen_ids, "custom")

    # Defense-in-depth: the community floor must never shrink. If it somehow
    # did, log loudly — a security product silently losing detections is worse
    # than a noisy alert.
    community_present = sum(1 for sig in signatures if sig.id in community_ids)
    if community_present < len(community_ids):
        logger.error(
            "Community signature count dropped: expected %d, present %d",
            len(community_ids),
            community_present,
        )

    return SignatureScanner(signatures)
