"""Settings and configuration endpoints."""
from __future__ import annotations

import logging
import os
import time

from fastapi import APIRouter, Depends

from control_plane import config
from control_plane.dependencies import Principal, require_role
from control_plane.schemas.management import ManagedUpgradeInfo
from vardoger import aws

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["settings"])

# Informational handoff text for switching to the managed offering. This is a
# concept-level intake URL (env-driven, empty default — never hardcode a SaaS
# URL). The upgrade is informational: we record intent, we do NOT migrate data.
_MANAGED_HANDOFF_TEXT = (
    "The managed offering runs the same detection tiers for you and aggregates "
    "across sources. Switching is a handoff: your scope_id moves from 'local' "
    "to an assigned managed scope. No data is migrated automatically from here."
)
_MANAGED_INSTRUCTIONS = (
    "1) Record your intent below. 2) Complete the managed intake form. "
    "3) A managed scope_id is provisioned. 4) Re-point telemetry to the managed "
    "endpoint. This endpoint only records intent; it performs no migration."
)


def _managed_intake_url() -> str:
    return os.environ.get("VARDOGER_MANAGED_INTAKE_URL", "").strip()


def _telemetry_mode() -> str:
    return os.environ.get("VARDOGER_TELEMETRY_MODE", "").strip()


@router.get("/status", dependencies=[Depends(require_role("viewer"))])
def status() -> dict[str, str | bool]:
    """Return current deployment mode and feature flags."""
    return {
        "deployment_mode": config.DEPLOYMENT_MODE,
        "auth_mode": config.AUTH_MODE,
        "scope_id": config.scope_id(),
        "ml_endpoint_configured": bool(os.environ.get("VARDOGER_ML_ENDPOINT", "")),
        "tier3_enabled": os.environ.get("TIER3_ENABLED", "true").lower() == "true",
        "global_kill_enabled": os.environ.get("VARDOGER_GLOBAL_KILL_ENABLED", "false").lower() == "true",
        "signature_feed_configured": bool(os.environ.get("VARDOGER_SIGNATURE_FEED_URL", "")),
        "managed_intake_configured": bool(_managed_intake_url()),
    }


@router.get("/managed-upgrade", dependencies=[Depends(require_role("viewer"))])
def managed_upgrade_info() -> ManagedUpgradeInfo:
    """Return informational handoff text and current telemetry mode (viewer)."""
    return ManagedUpgradeInfo(
        telemetry_mode=_telemetry_mode(),
        handoff_text=_MANAGED_HANDOFF_TEXT,
        intake_url=_managed_intake_url(),
        intent_recorded=False,
        instructions=_MANAGED_INSTRUCTIONS,
    )


@router.post("/managed-upgrade")
def managed_upgrade_intent(
    principal: Principal = Depends(require_role("admin")),
) -> ManagedUpgradeInfo:
    """Record managed-upgrade intent and return switch instructions (admin).

    Informational only — this sets an intent flag on the scope record and
    returns instructions. It does NOT migrate any data.
    """
    intent_recorded = False
    try:
        aws.table(config.TENANTS_TABLE, region=config.AWS_REGION).update_item(
            Key={"scope_id": config.scope_id()},
            UpdateExpression=(
                "SET managed_upgrade_intent = :v, managed_upgrade_intent_at = :t, "
                "managed_upgrade_intent_by = :b"
            ),
            ExpressionAttributeValues={
                ":v": True,
                ":t": int(time.time()),
                ":b": principal.subject,
            },
        )
        intent_recorded = True
    except Exception:
        logger.exception("Failed to record managed-upgrade intent for scope=%s", config.scope_id())

    return ManagedUpgradeInfo(
        telemetry_mode=_telemetry_mode(),
        handoff_text=_MANAGED_HANDOFF_TEXT,
        intake_url=_managed_intake_url(),
        intent_recorded=intent_recorded,
        instructions=_MANAGED_INSTRUCTIONS,
    )
