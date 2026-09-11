"""Outcome ledger — TP/TN/FP/FN tracking for detection accuracy analysis.

Writes one row per Tier 1/2/3 decision for later evaluation. Rows are
partitioned by scope_id (``"local"`` self-hosted) and tagged with source
(account+agent). In self-hosted mode this shows local data only; in managed
mode the backend aggregates across scopes for benchmarking.

Ledger failures never interrupt the detection/enforcement path.
"""
from __future__ import annotations

import logging
import os
import time
from decimal import Decimal
from typing import Any

from vardoger import aws
from vardoger.health import OUTCOME_LEDGER, report_degraded

logger = logging.getLogger(__name__)

OUTCOME_TABLE = os.environ.get("VARDOGER_OUTCOME_TABLE", "VardogerOutcomeLedger")
RETENTION_DAYS = int(os.environ.get("VARDOGER_OUTCOME_RETENTION_DAYS", "180"))


def _table():
    return aws.table(OUTCOME_TABLE)


def _ddb_safe(value: Any) -> Any:
    """Convert Python floats recursively into DynamoDB-safe Decimals."""
    if isinstance(value, float):
        return Decimal(str(round(value, 6)))
    if isinstance(value, dict):
        return {key: _ddb_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_ddb_safe(item) for item in value]
    return value


def evaluate_result(expected_label: str, actual_action: str, predicted_outcome: str = "") -> str:
    """Map expected labels and actions into TP/TN/FP/FN buckets.

    Unknown labels stay unknown instead of pretending live unlabeled data
    is correct or incorrect.
    """
    expected = (expected_label or "unknown").lower()
    actual = (actual_action or "").lower()
    predicted = (predicted_outcome or "").lower()
    blocked = actual in {"blocked", "killed"} or predicted in {"block", "kill"}
    if expected == "benign":
        return "false_positive" if blocked else "true_negative"
    if expected == "attack":
        return "true_positive" if blocked else "false_negative"
    return "unknown"


def write_outcome(row: dict[str, Any]) -> None:
    """Best-effort write of a test/evaluation ledger row.

    Outcome-ledger failures intentionally do not interrupt Tier 2/Tier 3
    processing because the ledger is an analytics aid, not the enforcement path.
    """
    try:
        # scope_id is the isolation/partition key ("local" self-hosted). source
        # is the account+agent segmentation attribute. Accept legacy tenant_id
        # as a fallback for scope_id so older callers keep working.
        scope_id = str(row.get("scope_id") or row.get("tenant_id") or "local")
        source = str(row.get("source", ""))
        session_id = str(row.get("session_id", ""))
        prompt_id = str(row.get("prompt_id", ""))
        tier = str(row.get("tier", "unknown"))
        event_ts = int(row.get("event_ts") or time.time())
        run_id = str(row.get("run_id") or "production")
        actual_action = str(row.get("actual_action") or "allowed")
        predicted_outcome = str(row.get("predicted_outcome") or "pass")
        expected_label = str(row.get("expected_label") or "unknown")

        row = {key: value for key, value in row.items() if key != "tenant_id"}
        item = {
            **row,
            "scope_id": scope_id,
            "source": source,
            "run_id": run_id,
            "session_id": session_id,
            "prompt_id": prompt_id,
            "tier": tier,
            "event_ts": event_ts,
            "created_at": int(time.time()),
            "ttl": int(time.time()) + RETENTION_DAYS * 24 * 3600,
            "pk": scope_id,
            "sk": f"{event_ts}#{session_id}#{prompt_id}#{tier}",
            "gsi1_pk": run_id,
            "gsi1_sk": f"{event_ts}#{scope_id}#{session_id}#{prompt_id}#{tier}",
            "gsi2_pk": f"{scope_id}#{session_id}",
            "gsi2_sk": f"{event_ts}#{prompt_id}#{tier}",
            "gsi3_pk": f"{tier}#{predicted_outcome}",
            "gsi3_sk": f"{event_ts}#{scope_id}#{session_id}",
            "evaluation_result_actual": evaluate_result(expected_label, actual_action, predicted_outcome),
            "evaluation_result_would_have": evaluate_result(
                expected_label,
                "killed" if row.get("would_have_killed") else "allowed",
                predicted_outcome,
            ),
        }
        _table().put_item(Item=_ddb_safe(item))
    except Exception as exc:
        # Analytics, not enforcement — never interrupt detection. But a ledger
        # that silently stops writing makes the evaluation dashboard quietly
        # wrong, so surface it as a degraded component rather than a log line.
        logger.warning("Outcome ledger write failed", exc_info=True)
        report_degraded(OUTCOME_LEDGER, f"ledger write failed: {type(exc).__name__}")
