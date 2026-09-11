"""Prompt history search service."""
from __future__ import annotations

import logging
import time
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from control_plane import config
from control_plane.schemas.prompt_history import PromptHistoryRecord, PromptHistoryResponse
from vardoger import aws
from vardoger.health import DASHBOARD_QUERY, report_degraded

logger = logging.getLogger(__name__)


def _to_int(value: Any, default: int = 0) -> int:
    if isinstance(value, Decimal):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    return default


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, set):
        return [str(v) for v in value]
    return []


def _record_from_item(item: dict[str, Any]) -> PromptHistoryRecord:
    return PromptHistoryRecord(
        scope_id=str(item.get("scope_id", "")),
        source=str(item.get("source", "")),
        session_id=str(item.get("session_id", "")),
        prompt_id=str(item.get("prompt_id", "")),
        timestamp=str(item.get("timestamp", "")),
        prompt=str(item.get("prompt", "")),
        decision=str(item.get("decision", "")),
        risk_score=_to_int(item.get("risk_score")),
        matched_signatures=_string_list(item.get("matched_signatures")),
        attack_intents=_string_list(item.get("attack_intents")),
        matched_policy_rules=_string_list(item.get("matched_policy_rules")),
        prompt_length=_to_int(item.get("prompt_length")),
        agent_runtime_arn=str(item.get("agent_runtime_arn", "")),
        ingested_at=_to_int(item.get("ingested_at")),
        tier2_status=str(item.get("tier2_status", "")),
        tier2_label=str(item.get("tier2_label", "")),
        tier2_confidence=_to_float(item.get("tier2_confidence")),
        tier2_suspicious=_to_bool(item.get("tier2_suspicious")),
        tier2_risk_score=_to_float(item.get("tier2_risk_score")),
        tier2_prompt_score=_to_float(item.get("tier2_prompt_score")),
        tier2_session_score_after=_to_float(item.get("tier2_session_score_after")),
        tier2_category=str(item.get("tier2_category", "")),
        tier2_ml_verdict=str(item.get("tier2_ml_verdict", "")),
        tier2_action_taken=str(item.get("tier2_action_taken", "")),
        tier2_threshold_used=str(item.get("tier2_threshold_used", "")),
        tier2_kill_triggered=_to_bool(item.get("tier2_kill_triggered")),
        tier2_safe_intent_reason=str(item.get("tier2_safe_intent_reason", "")),
        tier2_error=str(item.get("tier2_error", "")),
    )


def search_prompt_history(
    *,
    scope_id: str = "",
    source: str = "",
    session_id: str = "",
    decision: str = "",
    keyword: str = "",
    min_risk: int = 0,
    hours: int = 24,
    limit: int = 100,
) -> PromptHistoryResponse:
    """Search prompt history with filters.

    The prompt-history table is partitioned by scope_id, so the query is always
    scoped by scope_id first (defaulting to the deployment scope, "local"
    self-hosted). When ``source`` is provided, records are additionally filtered
    to that source within the scope; when omitted, the result is the rollup
    across all sources in the scope.
    """
    limit = max(1, min(limit, 500))
    hours = max(1, min(hours, 24 * 90))
    since_epoch = int(time.time()) - (hours * 3600)
    scope_id = scope_id or config.scope_id()

    dynamodb = aws.resource("dynamodb", region=config.AWS_REGION)
    table = dynamodb.Table(config.PROMPT_HISTORY_TABLE)

    records: list[PromptHistoryRecord] = []
    scanned_count = 0
    last_key: dict[str, Any] | None = None

    try:
        while len(records) < limit and scanned_count < 2000:
            request_limit = min(250, max(limit * 2, 50))
            # Always scope by the partition key (scope_id).
            kwargs: dict[str, Any] = {
                "KeyConditionExpression": Key("scope_id").eq(scope_id),
                "ScanIndexForward": False,
                "Limit": request_limit,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            response = table.query(**kwargs)

            scanned_count += int(response.get("ScannedCount", 0))
            for item in response.get("Items", []):
                record = _record_from_item(item)
                # Apply filters — source-filter within the scope.
                if source and record.source != source:
                    continue
                if session_id and session_id.lower() not in record.session_id.lower():
                    continue
                if decision and record.decision.lower() != decision.lower():
                    continue
                if keyword and keyword.lower() not in record.prompt.lower():
                    continue
                if min_risk and record.risk_score < min_risk:
                    continue
                if record.ingested_at and record.ingested_at < since_epoch:
                    continue
                records.append(record)
                if len(records) >= limit:
                    break

            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ResourceNotFoundException":
            return PromptHistoryResponse(
                warning=f"{config.PROMPT_HISTORY_TABLE} is not deployed yet.",
            )
        logger.exception("Failed to search prompt history")
        report_degraded(DASHBOARD_QUERY, f"prompt history query failed: {code or type(exc).__name__}")
        return PromptHistoryResponse(warning=f"Prompt history is unavailable: {code or 'query failed'}.")
    except Exception as exc:
        # Not every boto failure is a ClientError — NoCredentialsError and the
        # other BotoCoreError subclasses are not. Letting those propagate made
        # this the ONLY read endpoint that 500s where the rest degrade to an
        # empty result, so a credential or connectivity problem broke the page
        # instead of showing it as empty-and-degraded.
        logger.exception("Failed to search prompt history")
        report_degraded(DASHBOARD_QUERY, f"prompt history query failed: {type(exc).__name__}")
        return PromptHistoryResponse(warning=f"Prompt history is unavailable: {type(exc).__name__}.")

    records.sort(key=lambda r: r.ingested_at or 0, reverse=True)
    return PromptHistoryResponse(
        records=records[:limit],
        count=len(records[:limit]),
        scanned_count=scanned_count,
    )
