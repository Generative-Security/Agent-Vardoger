"""Prompt history search endpoint (viewer role)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from control_plane.dependencies import require_role
from control_plane.schemas.prompt_history import PromptHistoryResponse
from control_plane.services import prompt_history_service

router = APIRouter(
    prefix="/api/prompt-history",
    tags=["prompt-history"],
    dependencies=[Depends(require_role("viewer"))],
)


@router.get("/search")
def search(
    source: str = "",
    session_id: str = "",
    decision: str = Query("", pattern="^(|allow|block)$"),
    keyword: str = "",
    min_risk: int = Query(0, ge=0),
    hours: int = Query(24, ge=1, le=2160),
    limit: int = Query(100, ge=1, le=500),
) -> PromptHistoryResponse:
    """Search prompt history with filters, scoped by scope_id.

    Provide ``?source=<account>/<agent>`` to filter within the scope; omit it
    for the rollup across all sources.
    """
    return prompt_history_service.search_prompt_history(
        source=source.strip(),
        session_id=session_id.strip(),
        decision=decision.strip(),
        keyword=keyword.strip(),
        min_risk=min_risk,
        hours=hours,
        limit=limit,
    )
