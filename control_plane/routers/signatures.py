"""Signature endpoints.

GET  /api/signatures         — community metadata + premium status (viewer).
POST /api/signatures/custom  — author a custom signature (admin).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from control_plane.dependencies import Principal, require_role
from control_plane.schemas.management import (
    CustomSignatureRequest,
    CustomSignatureResponse,
    SignaturesResponse,
)
from control_plane.services import signatures_service

router = APIRouter(prefix="/api/signatures", tags=["signatures"])


@router.get("", dependencies=[Depends(require_role("viewer"))])
def get_signatures() -> SignaturesResponse:
    """Return community signature metadata plus premium status."""
    return signatures_service.get_signatures()


@router.post("/custom")
def add_custom_signature(
    req: CustomSignatureRequest,
    principal: Principal = Depends(require_role("admin")),
) -> CustomSignatureResponse:
    """Author a custom signature for the scope (admin only).

    - 400 when the pattern is invalid or fails the ReDoS screen (client error).
    - 503 when the pattern was accepted but could not be stored (dependency
      failure). A 200 therefore means the signature really was persisted.
    """
    try:
        result = signatures_service.add_custom_signature(req, author=principal.subject)
    except signatures_service.SignatureWriteError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    if result.error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.error)
    return result
