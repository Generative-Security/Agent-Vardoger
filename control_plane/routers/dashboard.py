"""Dashboard API endpoints.

Monitoring / read endpoints — require the ``viewer`` role. Every endpoint is
scoped by scope_id and accepts an optional ``?source=<account>/<agent>`` filter.
When source is omitted, results are the rollup across all sources in the scope.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from control_plane.dependencies import require_role
from control_plane.schemas.dashboard import (
    CategoryBreakdown,
    DashboardSummary,
    DetectionEvent,
    SessionSummary,
    SignatureHit,
    Tier3Finding,
    TimelinePoint,
)
from control_plane.services import session_query

router = APIRouter(
    prefix="/api/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_role("viewer"))],
)


@router.get("/sessions")
def sessions(source: str = "") -> SessionSummary:
    """Return active and terminated session counts with details."""
    return session_query.get_sessions(source=source.strip())


@router.get("/detections")
def detections(hours: int = 24, source: str = "") -> list[DetectionEvent]:
    """Return recent detection events."""
    return session_query.get_detection_events(hours, source=source.strip())


@router.get("/detections/timeline")
def detection_timeline(
    hours: int = 24,
    interval: str = Query("1h", pattern="^(5m|15m|1h|6h)$"),
    source: str = "",
) -> list[TimelinePoint]:
    """Return detection counts bucketed by time interval."""
    return session_query.get_detection_timeline(hours, interval, source=source.strip())


@router.get("/detections/by-category")
def detections_by_category(hours: int = 24, source: str = "") -> list[CategoryBreakdown]:
    """Return blocked detections grouped by category."""
    return session_query.get_detections_by_category(hours, source=source.strip())


@router.get("/detections/by-signature")
def detections_by_signature(hours: int = 24, source: str = "") -> list[SignatureHit]:
    """Return signature hit counts ranked by frequency."""
    return session_query.get_detections_by_signature(hours, source=source.strip())


@router.get("/tier3/findings")
def tier3_findings(hours: int = 24, source: str = "") -> list[Tier3Finding]:
    """Return Tier 3 cross-session findings."""
    return session_query.get_tier3_findings(hours, source=source.strip())


@router.get("/summary")
def summary(
    hours: int = 24,
    interval: str = Query("1h", pattern="^(5m|15m|1h|6h)$"),
    source: str = "",
) -> DashboardSummary:
    """Return every dashboard panel in one response.

    Preferred over polling the individual endpoints: it derives all six views
    from a single DetectionEvents read. The standalone endpoints above remain
    available and unchanged for scripted callers.
    """
    return session_query.get_dashboard_summary(hours, interval, source=source.strip())
