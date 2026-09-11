"""Shared Tier 2 / Tier 3 enforcement policy loading.

The scope's policy record (written by the control plane, keyed by ``scope_id``)
governs whether the async tiers may terminate a session. Both tier handlers read
the same record, so both must parse it identically.

They previously did not. Tier 2 and Tier 3 each carried their own
``_tenant_policy_from_item``, and the two had drifted:

- Tier 2 read counts as ``to_int(value, default)`` — a stored ``0`` was honored
  as ``0``.
- Tier 3 read them as ``to_int(value) or default`` — a stored ``0`` became the
  default.

So the same record could make Tier 2 believe a kill needed zero corroborating
sessions while Tier 3 required three. This module is the single parser for both.

**Resolution of the drift, and why it is the safe reading:** count fields are
clamped to a minimum of 1. For ``tier3_min_sessions_for_kill`` and
``tier2_min_malicious_verdicts_for_kill``, a lower value makes killing *easier*,
so ``0`` would mean "terminate with no corroborating evidence" — the exact
false-positive-kill scenario the guarded-kill design exists to prevent. The
control plane already rejects values below 1 (``Field(ge=1)``), so a ``0`` can
only arrive from an out-of-band table edit; clamping keeps Tier 3's protective
behavior and removes Tier 2's dangerous one. Threshold (0.0-1.0) fields keep
their stored value — the control plane bounds those too.

Loading is TTL-cached per scope. Policy changes are rare and the Tier 2 event
source delivers one record per invocation, so an uncached read meant a DynamoDB
round trip for **every prompt**. The TTL keeps a policy edit taking effect
within a bounded, documented delay rather than requiring a redeploy.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from vardoger import aws
from vardoger.coerce import to_bool, to_float, to_int
from vardoger.health import TENANT_POLICY, report_degraded

logger = logging.getLogger(__name__)

_ALLOWED_MODES = frozenset({"off", "shadow", "enforce"})

# How long a loaded policy is reused before re-reading. An operator's policy
# change takes effect within this window. Kept short enough to feel responsive
# and long enough to remove the per-prompt read.
POLICY_CACHE_TTL_SECONDS = 60.0

# scope_id -> (loaded_at, policy)
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_lock = threading.Lock()


def normalize_mode(value: Any, default: str) -> str:
    """Return a supported tier mode, defaulting to shadow on anything unknown.

    Shadow is the safe fallback by design: an unrecognized mode must never be
    read as ``enforce`` (which can terminate sessions).
    """
    mode = str(value or default or "shadow").lower()
    return mode if mode in _ALLOWED_MODES else "shadow"


def _count(value: Any, default: int) -> int:
    """Read a count field, clamped to >= 1. See the module docstring."""
    return max(1, to_int(value, default))


def defaults(
    *,
    tier2_mode: str = "shadow",
    tier3_mode: str = "shadow",
    tier2_endpoint: str = "",
    tier3_endpoint: str = "",
) -> dict[str, Any]:
    """Return the canonical default policy.

    Each tier passes its own default-mode constants rather than this module
    reading the environment, because the two handlers historically read the
    tier-3 default from *different* env vars (``VARDOGER_DEFAULT_TIER3_MODE`` in
    Tier 2, ``DEFAULT_TIER3_MODE`` in Tier 3). Unifying those silently would
    change behavior for anyone who had set one; the callers keep their existing
    semantics and this module stays agnostic.
    """
    return {
        "tier2_mode": normalize_mode(tier2_mode, "shadow"),
        "tier3_mode": normalize_mode(tier3_mode, "shadow"),
        "tier2_default_kill_threshold": 0.97,
        "tier2_high_risk_threshold": 0.85,
        "tier2_require_repeated_malicious": True,
        "tier2_min_malicious_verdicts_for_kill": 2,
        "tier2_allow_single_verdict_kill_threshold": 0.99,
        "tier2_model_endpoint": tier2_endpoint,
        "tier3_min_sessions_for_kill": 3,
        "tier3_similarity_threshold": 0.90,
        "tier3_kill_threshold": 0.95,
        "tier3_model_endpoint": tier3_endpoint,
        "policy_version": 1,
        "updated_by": "",
        "updated_at": 0,
    }


def policy_from_item(
    item: dict[str, Any] | None,
    *,
    tier2_mode: str = "shadow",
    tier3_mode: str = "shadow",
    tier2_endpoint: str = "",
    tier3_endpoint: str = "",
) -> dict[str, Any]:
    """Build a full policy dict from a stored scope record.

    Absent fields fall back to ``defaults``. Legacy ``tier2_enabled`` /
    ``tier3_enabled`` booleans are still honored as the *mode default* for
    records written before modes existed: enabled -> the supplied default mode,
    disabled -> "off".
    """
    item = item or {}
    policy = defaults(
        tier2_mode=tier2_mode,
        tier3_mode=tier3_mode,
        tier2_endpoint=tier2_endpoint,
        tier3_endpoint=tier3_endpoint,
    )

    legacy_tier2_on = to_bool(item.get("tier2_enabled"), True)
    legacy_tier3_on = to_bool(item.get("tier3_enabled"), True)
    policy["tier2_mode"] = normalize_mode(
        item.get("tier2_mode"), policy["tier2_mode"] if legacy_tier2_on else "off"
    )
    policy["tier3_mode"] = normalize_mode(
        item.get("tier3_mode"), policy["tier3_mode"] if legacy_tier3_on else "off"
    )

    policy["tier2_default_kill_threshold"] = to_float(
        item.get("tier2_default_kill_threshold"), policy["tier2_default_kill_threshold"]
    )
    policy["tier2_high_risk_threshold"] = to_float(
        item.get("tier2_high_risk_threshold"), policy["tier2_high_risk_threshold"]
    )
    policy["tier2_require_repeated_malicious"] = to_bool(
        item.get("tier2_require_repeated_malicious"), True
    )
    policy["tier2_min_malicious_verdicts_for_kill"] = _count(
        item.get("tier2_min_malicious_verdicts_for_kill"),
        policy["tier2_min_malicious_verdicts_for_kill"],
    )
    policy["tier2_allow_single_verdict_kill_threshold"] = to_float(
        item.get("tier2_allow_single_verdict_kill_threshold"),
        policy["tier2_allow_single_verdict_kill_threshold"],
    )
    policy["tier2_model_endpoint"] = str(item.get("tier2_model_endpoint") or tier2_endpoint)

    policy["tier3_min_sessions_for_kill"] = _count(
        item.get("tier3_min_sessions_for_kill"), policy["tier3_min_sessions_for_kill"]
    )
    policy["tier3_similarity_threshold"] = to_float(
        item.get("tier3_similarity_threshold"), policy["tier3_similarity_threshold"]
    )
    policy["tier3_kill_threshold"] = to_float(
        item.get("tier3_kill_threshold"), policy["tier3_kill_threshold"]
    )
    policy["tier3_model_endpoint"] = str(item.get("tier3_model_endpoint") or tier3_endpoint)

    policy["policy_version"] = _count(item.get("policy_version"), 1)
    policy["updated_by"] = str(item.get("updated_by") or "")
    policy["updated_at"] = to_int(item.get("updated_at"), 0)
    return policy


def load(
    scope_id: str,
    table_name: str,
    *,
    tier2_mode: str = "shadow",
    tier3_mode: str = "shadow",
    tier2_endpoint: str = "",
    tier3_endpoint: str = "",
    ttl_seconds: float = POLICY_CACHE_TTL_SECONDS,
) -> dict[str, Any]:
    """Load a scope's policy, TTL-cached, falling back to safe defaults.

    A read failure returns defaults (shadow mode — never ``enforce``) and is
    reported as degraded, so a policy that silently reverted to defaults is
    visible rather than mysterious.
    """
    safe_defaults = defaults(
        tier2_mode=tier2_mode,
        tier3_mode=tier3_mode,
        tier2_endpoint=tier2_endpoint,
        tier3_endpoint=tier3_endpoint,
    )
    if not scope_id or not table_name:
        return safe_defaults

    now = time.time()
    cached = _cache.get(scope_id)
    if cached and (now - cached[0]) < ttl_seconds:
        return dict(cached[1])

    try:
        response = aws.table(table_name).get_item(Key={"scope_id": scope_id})
        policy = policy_from_item(
            response.get("Item") or {},
            tier2_mode=tier2_mode,
            tier3_mode=tier3_mode,
            tier2_endpoint=tier2_endpoint,
            tier3_endpoint=tier3_endpoint,
        )
    except Exception as exc:
        logger.exception("Failed to read policy for scope=%s; using safe defaults", scope_id)
        report_degraded(TENANT_POLICY, f"policy read failed: {type(exc).__name__}", scope_id=scope_id)
        return safe_defaults

    with _lock:
        _cache[scope_id] = (now, policy)
    return dict(policy)


def invalidate_cache(scope_id: str = "") -> None:
    """Drop cached policy for a scope (or all scopes). Test-support / admin use."""
    with _lock:
        if scope_id:
            _cache.pop(scope_id, None)
        else:
            _cache.clear()
