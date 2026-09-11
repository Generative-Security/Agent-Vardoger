"""Evaluation summary from the outcome ledger (OUTCOME_TABLE).

Rows are partitioned by scope_id (the ledger writes ``pk = scope_id``). Each row
carries ``evaluation_result_actual`` in {true_positive, true_negative,
false_positive, false_negative, unknown}. This service rolls those up into
counts for the scope.
"""
from __future__ import annotations

import logging

from boto3.dynamodb.conditions import Attr, Key

from control_plane import config
from control_plane.schemas.management import EvaluationSummary
from vardoger import aws

logger = logging.getLogger(__name__)

_RESULT_FIELD = "evaluation_result_actual"
_COUNT_KEYS = {
    "true_positive": "true_positive",
    "true_negative": "true_negative",
    "false_positive": "false_positive",
    "false_negative": "false_negative",
    "unknown": "unknown",
}


def _dynamodb():
    return aws.resource("dynamodb", region=config.AWS_REGION)


def get_evaluation_summary(source: str = "") -> EvaluationSummary:
    """Return TP/TN/FP/FN counts for the scope, optionally filtered by source."""
    scope = config.scope_id()
    table = _dynamodb().Table(config.OUTCOME_TABLE)
    counts = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0, "unknown": 0}

    items = []
    try:
        # The ledger partitions on pk = scope_id.
        kwargs = {"KeyConditionExpression": Key("pk").eq(scope)}
        if source:
            kwargs["FilterExpression"] = Attr("source").eq(source)
        while True:
            resp = table.query(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
    except Exception:
        logger.exception("Failed to read outcome ledger for scope=%s", scope)
        return EvaluationSummary(scope_id=scope)

    for item in items:
        result = str(item.get(_RESULT_FIELD, "")).lower()
        key = _COUNT_KEYS.get(result, "unknown")
        counts[key] += 1

    total = sum(counts.values())
    return EvaluationSummary(
        scope_id=scope,
        true_positive=counts["true_positive"],
        true_negative=counts["true_negative"],
        false_positive=counts["false_positive"],
        false_negative=counts["false_negative"],
        unknown=counts["unknown"],
        total=total,
    )
