"""Sources listing endpoint.

A source is "<aws_account_id>/<agent>" — the segmentation dimension within the
scope. This lists the distinct source values seen across the scope's tables.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from control_plane import config
from control_plane.dependencies import require_role
from control_plane.schemas.management import SourcesResponse
from control_plane.services import session_query

router = APIRouter(
    prefix="/api/sources",
    tags=["sources"],
    dependencies=[Depends(require_role("viewer"))],
)


@router.get("")
def list_sources() -> SourcesResponse:
    """List distinct source values seen within the scope."""
    sources = session_query.get_distinct_sources()
    return SourcesResponse(scope_id=config.scope_id(), sources=sources, count=len(sources))
