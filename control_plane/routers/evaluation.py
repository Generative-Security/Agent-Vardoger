"""Evaluation endpoints.

GET  /api/evaluation      — outcome-ledger TP/TN/FP/FN summary (viewer).
POST /api/evaluation/run  — trigger an evaluation run (admin) — stub.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends

from control_plane.dependencies import require_role
from control_plane.schemas.management import EvaluationRunResponse, EvaluationSummary
from control_plane.services import evaluation_service

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])


@router.get("", dependencies=[Depends(require_role("viewer"))])
def get_evaluation(source: str = "") -> EvaluationSummary:
    """Return outcome-ledger summary counts (TP/TN/FP/FN) for the scope."""
    return evaluation_service.get_evaluation_summary(source=source.strip())


@router.post("/run", dependencies=[Depends(require_role("admin"))])
def run_evaluation() -> EvaluationRunResponse:
    """Trigger an evaluation run (admin only).

    Stub: no backing batch job is wired up yet. Returns accepted with a run id
    so the UI can poll later.
    """
    run_id = f"eval-{int(time.time())}"
    return EvaluationRunResponse(
        status="accepted",
        run_id=run_id,
        detail="Evaluation run accepted (stub — no batch job wired up yet).",
    )
