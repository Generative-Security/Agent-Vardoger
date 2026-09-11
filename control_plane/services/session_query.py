"""Session and detection event queries from DynamoDB.

Every query is ALWAYS scoped by scope_id first (the partition/isolation key,
"local" in self-hosted deployments), then optionally filtered by source
("<aws_account_id>/<agent>") within that scope. When source is omitted the
result is the rollup across all sources in the scope.

Scan amplification
------------------
The dashboard renders six views over the same underlying data, and each used to
issue its own full ``Scan`` of ``DetectionEvents``: the timeline, category
breakdown, and signature breakdown each called ``get_detection_events``
independently, and Tier 3 findings scanned the table a fifth time with a
``provenance`` filter. With the SPA polling every 30s, a single open dashboard
produced five full table scans per poll, and every extra viewer multiplied it.

Two changes fix that without altering any endpoint's response:

1. The raw scan is memoized for ``_CACHE_TTL_SECONDS`` per
   (scope, source, window), so the derived views share one read.
2. Tier 3 findings are filtered from that same result in memory rather than
   re-scanning — a ``FilterExpression`` does not reduce scanned capacity anyway,
   so this is strictly cheaper and returns identical rows.

The cache is per-process (warm Lambda container), holds only rows the caller's
role is already authorized to read, and is keyed by scope AND source so a
source-filtered view can never be served another source's rows. TTL is well
under the poll interval, so freshness is unchanged in practice.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime

from boto3.dynamodb.conditions import Attr

from control_plane import config
from control_plane.schemas.dashboard import (
    CategoryBreakdown,
    DashboardSummary,
    DetectionEvent,
    SessionInfo,
    SessionSummary,
    SignatureHit,
    Tier3Finding,
    TimelinePoint,
)
from vardoger import aws
from vardoger.health import DASHBOARD_QUERY, report_degraded

logger = logging.getLogger(__name__)


def _dynamodb():
    return aws.resource("dynamodb", region=config.AWS_REGION)


def _scope_filter(source: str = ""):
    """Build the base filter for a query: scope_id first, then optional source.

    Records are partitioned by scope_id. In self-hosted deployments that is
    always "local". When ``source`` is provided we additionally filter to the
    matching source attribute (segmentation within the scope).
    """
    condition = Attr("scope_id").eq(config.scope_id())
    if source:
        condition = condition & Attr("source").eq(source)
    return condition


# --- Short-TTL memo for the DetectionEvents scan -------------------------
# Keyed by (scope_id, source, hours). Bounded so a caller varying `hours` cannot
# grow it without limit.
_CACHE_TTL_SECONDS = 15.0
# A FAILED scan is cached too, for a shorter window. Without this, a failing
# table turned one dashboard poll back into five scans (each derived view
# retried independently) and emitted a degraded metric per retry — the most
# load at exactly the moment the table is least able to serve it.
_FAILURE_TTL_SECONDS = 5.0
_CACHE_MAX_ENTRIES = 32
# key -> (cached_at, items, ok)
_events_cache: dict[tuple[str, str, int], tuple[float, list[dict], bool]] = {}
_events_lock = threading.Lock()


def _recent_detection_items(hours: int, source: str = "") -> list[dict]:
    """Return raw DetectionEvents rows for the window, memoized briefly.

    Shared by the detections list, timeline, category/signature breakdowns, and
    Tier 3 findings so they cost ONE scan between them rather than five.

    Never raises: a failed scan yields an empty list, is reported once as a
    degraded component, and is itself cached briefly so the failure does not
    fan out into a retry storm across the derived views.
    """
    scope = config.scope_id()
    key = (scope, source, int(hours))
    now = time.time()

    cached = _events_cache.get(key)
    if cached:
        cached_at, items, ok = cached
        ttl = _CACHE_TTL_SECONDS if ok else _FAILURE_TTL_SECONDS
        if (now - cached_at) < ttl:
            return items

    cutoff = int(now) - hours * 3600
    try:
        table = _dynamodb().Table(config.DETECTION_EVENTS_TABLE)
        items = _scan_all(
            table,
            FilterExpression=_scope_filter(source) & Attr("event_ts").gte(cutoff),
        )
        ok = True
    except Exception as exc:
        logger.warning(
            "DetectionEvents scan failed (%s); serving empty results",
            type(exc).__name__,
            exc_info=True,
        )
        report_degraded(DASHBOARD_QUERY, f"detection events scan failed: {type(exc).__name__}")
        items, ok = [], False

    with _events_lock:
        if len(_events_cache) >= _CACHE_MAX_ENTRIES:
            _events_cache.clear()
        _events_cache[key] = (now, items, ok)
    return items


def invalidate_detection_cache() -> None:
    """Drop the memoized scan. Test-support only."""
    with _events_lock:
        _events_cache.clear()


def _scan_all(table, **kwargs) -> list[dict]:
    items: list[dict] = []
    while True:
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            return items
        kwargs["ExclusiveStartKey"] = last_key


def _to_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _to_float(value) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _to_timestamp(value: int) -> str:
    if not value:
        return ""
    return datetime.fromtimestamp(value, tz=UTC).isoformat()


def get_sessions(source: str = "") -> SessionSummary:
    """Return active and terminated session counts within the scope.

    When ``source`` is given, only sessions from that source are counted.
    """
    table = _dynamodb().Table(config.SESSION_TABLE)
    now = int(time.time())
    try:
        items = _scan_all(
            table,
            FilterExpression=_scope_filter(source) & Attr("ttl").gte(now),
        )
    except Exception as exc:
        logger.exception("Failed to query sessions")
        report_degraded(DASHBOARD_QUERY, f"sessions scan failed: {type(exc).__name__}")
        return SessionSummary(active_count=0, terminated_count=0)

    active = []
    terminated = []
    for item in items:
        info = SessionInfo(
            session_id=item.get("session_id", ""),
            created_at=_to_int(item.get("created_at")),
            scope_id=item.get("scope_id", config.scope_id()),
            source=item.get("source", ""),
            status=item.get("status", "active"),
            last_decision=item.get("last_decision", ""),
            last_risk_score=_to_int(item.get("last_risk_score")),
            last_matched_signatures=list(item.get("last_matched_signatures") or []),
            last_evaluated_at=_to_int(item.get("last_evaluated_at")),
        )
        if info.status == "terminated":
            terminated.append(info)
        else:
            active.append(info)

    return SessionSummary(
        active_count=len(active),
        terminated_count=len(terminated),
        active_sessions=sorted(active, key=lambda s: s.last_evaluated_at or s.created_at, reverse=True),
        terminated_sessions=sorted(terminated, key=lambda s: s.last_evaluated_at, reverse=True),
    )


def get_detection_events(hours: int = 24, source: str = "") -> list[DetectionEvent]:
    """Return recent detection events within the scope (optionally by source)."""
    return _events_from_items(_recent_detection_items(hours, source=source))


def _events_from_items(items: list[dict]) -> list[DetectionEvent]:
    """Map raw rows to DetectionEvent. Pure — no I/O."""
    events = [
        DetectionEvent(
            timestamp=_to_timestamp(_to_int(item.get("event_ts"))),
            session_id=item.get("session_id", ""),
            decision=item.get("decision", ""),
            matched_signatures=list(item.get("matched_signatures") or []),
            risk_score=_to_int(item.get("risk_score")),
            attack_intents=list(item.get("attack_intents") or []),
            matched_policy_rules=list(item.get("matched_policy_rules") or []),
        )
        for item in items
    ]
    return sorted(events, key=lambda e: e.timestamp, reverse=True)


def get_detection_timeline(
    hours: int = 24,
    interval: str = "1h",
    source: str = "",
    events: list[DetectionEvent] | None = None,
) -> list[TimelinePoint]:
    """Return detection counts bucketed by time interval.

    ``events`` lets a caller that already holds the event list (the summary
    endpoint) derive this view without another fetch.
    """
    seconds = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600}.get(interval, 3600)
    buckets: dict[int, dict[str, int]] = defaultdict(lambda: {"total": 0, "block": 0, "allow": 0})
    for event in (get_detection_events(hours, source=source) if events is None else events):
        if event.timestamp:
            ts = int(datetime.fromisoformat(event.timestamp).timestamp())
            bucket = ts - (ts % seconds)
            buckets[bucket]["total"] += 1
            if event.decision == "block":
                buckets[bucket]["block"] += 1
            else:
                buckets[bucket]["allow"] += 1
    return [
        TimelinePoint(
            timestamp=_to_timestamp(ts),
            detection_count=counts["total"],
            block_count=counts["block"],
            allow_count=counts["allow"],
        )
        for ts, counts in sorted(buckets.items())
    ]


def get_detections_by_category(
    hours: int = 24,
    source: str = "",
    events: list[DetectionEvent] | None = None,
) -> list[CategoryBreakdown]:
    """Return blocked detections grouped by category."""
    counts: Counter[str] = Counter()
    for event in (get_detection_events(hours, source=source) if events is None else events):
        if event.decision != "block":
            continue
        signals = event.matched_signatures or event.matched_policy_rules or ["policy"]
        for sig in signals:
            counts[sig] += 1
    total = sum(counts.values()) or 1
    return [
        CategoryBreakdown(category=cat, count=count, percentage=round(count / total * 100, 1))
        for cat, count in counts.most_common()
    ]


def get_detections_by_signature(
    hours: int = 24,
    source: str = "",
    events: list[DetectionEvent] | None = None,
) -> list[SignatureHit]:
    """Return signature hit counts ranked by frequency."""
    counts: Counter[str] = Counter()
    last_seen: dict[str, str] = {}
    for event in (get_detection_events(hours, source=source) if events is None else events):
        if event.decision != "block":
            continue
        sigs = event.matched_signatures or ["policy"]
        for sig in sigs:
            counts[sig] += 1
            last_seen[sig] = max(last_seen.get(sig, ""), event.timestamp)
    return [
        SignatureHit(signature_id=sig, hit_count=count, last_seen=last_seen.get(sig, ""))
        for sig, count in counts.most_common(50)
    ]


def get_tier3_findings(
    hours: int = 24,
    source: str = "",
    items: list[dict] | None = None,
) -> list[Tier3Finding]:
    """Return Tier 3 cross-session findings within the scope.

    Tier 3 findings are identified by ``provenance == "tier3"`` (the old meaning
    of "source" moved to the ``provenance`` attribute). This filters the shared
    DetectionEvents fetch in memory rather than issuing a second scan: a
    DynamoDB FilterExpression reduces returned rows but not scanned capacity, so
    the result is identical and strictly cheaper.
    """
    items = _recent_detection_items(hours, source=source) if items is None else items

    findings = []
    for item in items:
        if str(item.get("provenance", "")) != "tier3":
            continue
        findings.append(Tier3Finding(
            event_id=str(item.get("event_id", "")),
            timestamp=_to_timestamp(_to_int(item.get("event_ts"))),
            scope_id=str(item.get("scope_id", config.scope_id())),
            source=str(item.get("source", "")),
            provenance=str(item.get("provenance", "tier3")),
            affected_sources=list(item.get("affected_sources") or []),
            burst_id=str(item.get("burst_id", "")),
            category=str(item.get("category", "")),
            attack_style=str(item.get("attack_style", "")),
            confidence=_to_float(item.get("confidence")),
            affected_session_count=_to_int(item.get("affected_session_count")),
            affected_sessions=list(item.get("affected_sessions") or []),
            example_prompt_ids=list(item.get("example_prompt_ids") or []),
            similarity_method=str(item.get("similarity_method", "")),
            threshold_used=str(item.get("threshold_used", "")),
            action_taken=str(item.get("action_taken", "")),
            kill_triggered=bool(item.get("kill_triggered")),
            model_version=str(item.get("model_version", "")),
        ))
    return sorted(findings, key=lambda f: f.timestamp, reverse=True)


def get_dashboard_summary(
    hours: int = 24,
    interval: str = "1h",
    source: str = "",
) -> DashboardSummary:
    """Return every dashboard panel from a SINGLE DetectionEvents read.

    The raw rows are fetched once here and handed to each derived view, so the
    guarantee holds on the failure path too — not just when the cache happens
    to be warm. Each field is identical to the response of the corresponding
    standalone endpoint, which remains available.
    """
    items = _recent_detection_items(hours, source=source)
    events = _events_from_items(items)
    return DashboardSummary(
        sessions=get_sessions(source=source),
        detections=events,
        timeline=get_detection_timeline(hours, interval, source=source, events=events),
        categories=get_detections_by_category(hours, source=source, events=events),
        signatures=get_detections_by_signature(hours, source=source, events=events),
        tier3_findings=get_tier3_findings(hours, source=source, items=items),
    )


def get_distinct_sources() -> list[str]:
    """Return the distinct ``source`` values seen within the scope.

    Scans session, detection, and prompt-history tables (scoped by scope_id)
    and returns the deduplicated set of non-empty source attributes.
    """
    sources: set[str] = set()
    ddb = _dynamodb()
    for table_name in (
        config.SESSION_TABLE,
        config.DETECTION_EVENTS_TABLE,
        config.PROMPT_HISTORY_TABLE,
    ):
        try:
            items = _scan_all(
                ddb.Table(table_name),
                FilterExpression=Attr("scope_id").eq(config.scope_id()),
                ProjectionExpression="#s",
                ExpressionAttributeNames={"#s": "source"},
            )
        except Exception as exc:
            logger.exception("Failed to scan sources from %s", table_name)
            report_degraded(
                DASHBOARD_QUERY,
                f"source scan failed: {type(exc).__name__}",
                table=table_name,
            )
            continue
        for item in items:
            value = str(item.get("source") or "").strip()
            if value:
                sources.add(value)
    return sorted(sources)
