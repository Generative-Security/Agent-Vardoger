"""Security policy endpoints.

GET  /api/policy — read the scope's Tier 2/Tier 3 policy (viewer).
PUT  /api/policy — write it (admin). Enforcement policy is admin-only.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from control_plane.dependencies import Principal, require_role
from control_plane.schemas.management import SecurityPolicy
from control_plane.services import policy_service

router = APIRouter(prefix="/api/policy", tags=["policy"])


@router.get("", dependencies=[Depends(require_role("viewer"))])
def get_policy() -> SecurityPolicy:
    """Read the scope's Tier 2/Tier 3 security policy."""
    return policy_service.get_policy()


@router.put("")
def put_policy(
    policy: SecurityPolicy,
    principal: Principal = Depends(require_role("admin")),
) -> SecurityPolicy:
    """Write the scope's Tier 2/Tier 3 security policy (admin only).

    A failed write returns 503 rather than a generic 500, so the dashboard can
    tell the operator the policy did NOT change and the previous one still
    applies. Reporting a failed enforcement-policy write as success would be
    actively dangerous.
    """
    try:
        return policy_service.put_policy(policy, updated_by=principal.subject)
    except policy_service.PolicyWriteError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
