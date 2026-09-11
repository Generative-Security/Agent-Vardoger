"""Health check endpoint."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/api/health")
def health() -> dict[str, str]:
    """Simple health check."""
    return {"status": "ok", "service": "agent-vardoger"}
