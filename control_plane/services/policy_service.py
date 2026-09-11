"""Security policy read/write against the TENANTS_TABLE, keyed by scope_id.

TENANTS_TABLE keeps its existing (env-var-backed) name for compatibility with
the Tier 2 / Tier 3 handlers, but every record is partitioned by scope_id. The
policy fields mirror vardoger/tier2/handler.py DEFAULT_TENANT_POLICY and the
Tier 3 policy so the control plane and the handlers agree.
"""
from __future__ import annotations

import logging
import time
from decimal import Decimal
from typing import Any

from control_plane import config
from control_plane.schemas.management import SecurityPolicy
from vardoger import aws
from vardoger.health import TENANT_POLICY, report_degraded

logger = logging.getLogger(__name__)

_ALLOWED_MODES = {"off", "shadow", "enforce"}


class PolicyWriteError(RuntimeError):
    """The policy could not be persisted.

    Raised instead of letting a boto exception escape as an unhandled 500.
    A failed policy write must NOT be reported as success: this policy governs
    whether the async tiers may terminate live sessions, so an operator who
    believes they switched to enforce (or back to shadow) when the write never
    landed is operating on a false picture. The router turns this into a 503
    with an actionable message.
    """



def _dynamodb():
    return aws.resource("dynamodb", region=config.AWS_REGION)


def _to_float(value: Any, default: float) -> float:
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int) -> int:
    if isinstance(value, Decimal):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    if value is None:
        return default
    return bool(value)


def _mode(value: Any, default: str) -> str:
    mode = str(value or default or "shadow").lower()
    return mode if mode in _ALLOWED_MODES else "shadow"


def _policy_from_item(item: dict[str, Any] | None) -> SecurityPolicy:
    item = item or {}
    return SecurityPolicy(
        tier2_mode=_mode(item.get("tier2_mode"), "shadow"),
        tier2_default_kill_threshold=_to_float(item.get("tier2_default_kill_threshold"), 0.97),
        tier2_high_risk_threshold=_to_float(item.get("tier2_high_risk_threshold"), 0.85),
        tier2_require_repeated_malicious=_to_bool(item.get("tier2_require_repeated_malicious"), True),
        tier2_min_malicious_verdicts_for_kill=_to_int(item.get("tier2_min_malicious_verdicts_for_kill"), 2),
        tier2_allow_single_verdict_kill_threshold=_to_float(
            item.get("tier2_allow_single_verdict_kill_threshold"), 0.99
        ),
        tier3_mode=_mode(item.get("tier3_mode"), "shadow"),
        tier3_min_sessions_for_kill=_to_int(item.get("tier3_min_sessions_for_kill"), 3),
        tier3_similarity_threshold=_to_float(item.get("tier3_similarity_threshold"), 0.90),
        tier3_kill_threshold=_to_float(item.get("tier3_kill_threshold"), 0.95),
        policy_version=_to_int(item.get("policy_version"), 1),
        updated_by=str(item.get("updated_by") or ""),
        updated_at=_to_int(item.get("updated_at"), 0),
    )


def get_policy() -> SecurityPolicy:
    """Read the scope's Tier 2/Tier 3 policy, defaulting to safe shadow mode."""
    try:
        response = _dynamodb().Table(config.TENANTS_TABLE).get_item(
            Key={"scope_id": config.scope_id()}
        )
        return _policy_from_item(response.get("Item") or {})
    except Exception:
        logger.exception("Failed to read policy for scope=%s; using defaults", config.scope_id())
        return SecurityPolicy()


def put_policy(policy: SecurityPolicy, updated_by: str = "") -> SecurityPolicy:
    """Persist the scope's policy to TENANTS_TABLE keyed by scope_id.

    ``policy_version`` is SERVER-OWNED: we read the currently stored version and
    increment it, ignoring whatever the client sent. This prevents a client from
    forcing an arbitrary version and keeps the counter monotonic.
    """
    scope = config.scope_id()
    now = int(time.time())
    current_version = int(get_policy().policy_version)
    item: dict[str, Any] = {
        "scope_id": scope,
        "tier2_mode": _mode(policy.tier2_mode, "shadow"),
        "tier2_default_kill_threshold": Decimal(str(policy.tier2_default_kill_threshold)),
        "tier2_high_risk_threshold": Decimal(str(policy.tier2_high_risk_threshold)),
        "tier2_require_repeated_malicious": bool(policy.tier2_require_repeated_malicious),
        "tier2_min_malicious_verdicts_for_kill": int(policy.tier2_min_malicious_verdicts_for_kill),
        "tier2_allow_single_verdict_kill_threshold": Decimal(str(policy.tier2_allow_single_verdict_kill_threshold)),
        "tier3_mode": _mode(policy.tier3_mode, "shadow"),
        "tier3_min_sessions_for_kill": int(policy.tier3_min_sessions_for_kill),
        "tier3_similarity_threshold": Decimal(str(policy.tier3_similarity_threshold)),
        "tier3_kill_threshold": Decimal(str(policy.tier3_kill_threshold)),
        "policy_version": current_version + 1,
        "updated_by": updated_by,
        "updated_at": now,
    }
    try:
        _dynamodb().Table(config.TENANTS_TABLE).put_item(Item=item)
    except Exception as exc:
        logger.exception("Failed to write policy for scope=%s", scope)
        report_degraded(TENANT_POLICY, f"policy write failed: {type(exc).__name__}", scope_id=scope)
        raise PolicyWriteError(
            f"Policy could not be saved ({type(exc).__name__}). "
            "The scope configuration table may be unavailable; the previous policy is still in effect."
        ) from exc
    return _policy_from_item(item)
