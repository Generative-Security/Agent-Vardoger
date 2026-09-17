"""Tier 2 ML Lambda — prompt ingest plus per-prompt ML classification.

Triggered by SQS in production. For each prompt, it writes prompt history,
builds recent session context, invokes SageMaker, updates session risk,
writes dashboard/audit events, and optionally triggers enforcement when
the cumulative risk policy crosses a kill threshold.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, NamedTuple
from uuid import uuid4

from botocore.exceptions import ClientError

from vardoger import aws
from vardoger import policy as policy_module

# Shared coercion helpers, aliased to the names this module already uses at
# ~56 call sites. These previously existed here AND in Tier 3 AND in three
# control-plane services, and had drifted apart (see vardoger/coerce.py).
from vardoger.coerce import to_float as _to_float
from vardoger.coerce import to_int as _to_int
from vardoger.coerce import to_str_list as _list_field
from vardoger.health import ML_INFERENCE, report_degraded
from vardoger.outcome_ledger import write_outcome

from vardoger.logging_setup import configure_logging

logger = logging.getLogger(__name__)
# Applies VARDOGER_LOG_LEVEL. Without this the runtime's own root level
# applies and every INFO line is dropped, leaving the log group empty.
configure_logging()

# ---------------------------------------------------------------------------
# Environment configuration (all prefixed VARDOGER_)
# ---------------------------------------------------------------------------
# Empty means "no ML endpoint configured", which is the DEFAULT deployment and a
# supported state — not a missing value to paper over. The previous fallback
# ("vardoger-tier2-ml") named an endpoint nothing creates; it happens to be the
# Tier 2 *Lambda's* name, not a SageMaker endpoint. Defaulting to it made an
# unconfigured install look configured and turned every record into a
# ResourceNotFound from SageMaker. A tenant policy may still supply its own
# endpoint, which takes precedence over this (see _build_record_context).
SAGEMAKER_ENDPOINT = os.environ.get("VARDOGER_ML_ENDPOINT", "")
PROMPT_HISTORY_TABLE = os.environ.get("VARDOGER_PROMPT_HISTORY_TABLE", "VardogerPromptHistory")
SESSION_RISK_TABLE = os.environ.get("VARDOGER_SESSION_RISK_TABLE", "VardogerSessionRisk")
DETECTION_EVENTS_TABLE = os.environ.get("VARDOGER_DETECTION_EVENTS_TABLE", "VardogerDetectionEvents")
TENANTS_TABLE = os.environ.get("VARDOGER_TENANTS_TABLE", "VardogerTenants")
ENFORCEMENT_FUNCTION = os.environ.get("VARDOGER_ENFORCEMENT_FUNCTION", "")

PROMPT_HISTORY_RETENTION_DAYS = int(os.environ.get("VARDOGER_PROMPT_HISTORY_RETENTION_DAYS", "90"))
DETECTION_EVENT_RETENTION_DAYS = int(os.environ.get("VARDOGER_DETECTION_EVENT_RETENTION_DAYS", "90"))
SESSION_RISK_RETENTION_DAYS = int(os.environ.get("VARDOGER_SESSION_RISK_RETENTION_DAYS", "30"))
SESSION_CONTEXT_MIN = int(os.environ.get("VARDOGER_SESSION_CONTEXT_MIN", "5"))
SESSION_CONTEXT_MAX = int(os.environ.get("VARDOGER_SESSION_CONTEXT_MAX", "10"))
SESSION_CONTEXT_WINDOW = int(os.environ.get("VARDOGER_SESSION_CONTEXT_WINDOW", str(SESSION_CONTEXT_MAX)))
SESSION_CONTEXT_WINDOW = max(SESSION_CONTEXT_MIN, min(SESSION_CONTEXT_WINDOW, SESSION_CONTEXT_MAX))
SESSION_CONTEXT_TOKEN_BUDGET = int(os.environ.get("VARDOGER_SESSION_CONTEXT_TOKEN_BUDGET", "512"))
REVIEW_LAYER1_BLOCKED_PROMPTS = os.environ.get("VARDOGER_REVIEW_LAYER1_BLOCKED_PROMPTS", "false").lower() == "true"
ML_CONFIDENCE_THRESHOLD = float(os.environ.get("VARDOGER_ML_CONFIDENCE_THRESHOLD", "0.85"))
ML_SUSPICIOUS_THRESHOLD = float(os.environ.get("VARDOGER_ML_SUSPICIOUS_THRESHOLD", "0.55"))
ML_HIGH_RISK_KILL_THRESHOLD = int(os.environ.get("VARDOGER_ML_HIGH_RISK_KILL_THRESHOLD", "90"))
ML_CONDITIONAL_KILL_THRESHOLD = int(
    os.environ.get(
        "VARDOGER_ML_CONDITIONAL_KILL_THRESHOLD",
        str(int(float(os.environ.get("VARDOGER_ML_CUMULATIVE_RISK_THRESHOLD", "0.80")) * 100)),
    )
)
THRESHOLD_VERSION = os.environ.get("VARDOGER_THRESHOLD_VERSION", "02062026v1")
ML_KILL_ENABLED = os.environ.get("VARDOGER_ML_KILL_ENABLED", "false").lower() == "true"
GLOBAL_KILL_ENABLED = os.environ.get("VARDOGER_GLOBAL_KILL_ENABLED", "false").lower() == "true"
TIER2_KILL_ENABLED = os.environ.get("VARDOGER_TIER2_KILL_ENABLED", os.environ.get("VARDOGER_ML_KILL_ENABLED", "false")).lower() == "true"
DEFAULT_TIER2_MODE = os.environ.get("VARDOGER_DEFAULT_TIER2_MODE", "shadow").lower()
ML_KEEP_ALIVE_ENABLED = os.environ.get("VARDOGER_ML_KEEP_ALIVE_ENABLED", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Attack labels — all label strings that the ML model might return for attacks
# ---------------------------------------------------------------------------
ATTACK_LABELS = {
    "INJECTION",
    "LABEL_1",
    "ATTACK",
    "MALICIOUS",
    "1",
    "JAILBREAK",
    "PROMPT_INJECTION",
    "DATA_EXFILTRATION",
    "SOCIAL_ENGINEERING",
    "ACCOUNT_ABUSE",
    "ACCOUNT_TAKEOVER",
    "REFUND_MANIPULATION",
    "REFUND_FRAUD",
    "SLOW_ESCALATION",
}

CRITICAL_CATEGORIES = {
    "credential_theft",
    "data_exfiltration",
    "account_abuse",
    "account_takeover",
    "prompt_injection",
    "jailbreak",
    "system_prompt_extraction",
}

OBVIOUS_IMMEDIATE_KILL_CATEGORIES = {
    "prompt_injection",
    "jailbreak",
    "credential_theft",
    "system_prompt_extraction",
}

SUBTLE_REPEATED_EVIDENCE_CATEGORIES = {
    "inventory_probing",
    "refund_fraud",
    "refund_manipulation",
    "customer_data_mining",
    "employee_safety",
    "social_engineering",
    "shipping_info_abuse",
    "account_takeover",
    "policy_abuse",
    "data_exfiltration",
}

CATEGORY_KEYWORDS = (
    ("credential_theft", ("password", "secret", "token", "credential", "private key", "api key")),
    ("system_prompt_extraction", ("system prompt", "developer message", "hidden instruction", "startup instruction")),
    ("data_exfiltration", ("export", "download", "private details", "staffing", "roster", "hidden data")),
    ("customer_data_mining", ("customer list", "customer names", "customer emails", "private customer")),
    ("inventory_exfiltration", ("inventory export", "stock list", "supplier contacts", "bulk inventory")),
    ("employee_safety", ("employee names", "private schedule", "weak coverage", "late shift", "opening staff")),
    ("account_takeover", ("verification bypass", "recovery bypass", "reset their password", "take over")),
    ("account_abuse", ("account", "bank", "payment", "admin", "privilege")),
    ("refund_fraud", ("refund", "return", "fake receipt", "without proof", "proof missing", "manager approved")),
    ("prompt_injection", ("ignore previous", "override your rules", "disregard policy", "system prompt")),
    ("jailbreak", ("jailbreak", "developer mode", "do anything now", "dan mode")),
    ("social_engineering", ("urgent", "boss", "manager", "support", "approve for me")),
)

REGEX_SCORE_BY_SEVERITY = {
    "none": 0,
    "low": 10,
    "medium": 35,
    "high": 80,
    "critical": 95,
}

CATEGORY_SCORE = {
    "prompt_injection": 20,
    "jailbreak": 20,
    "credential_theft": 25,
    "system_prompt_extraction": 25,
    "data_exfiltration": 20,
    "account_takeover": 20,
    "employee_safety": 20,
    "inventory_exfiltration": 15,
    "customer_data_mining": 15,
    "refund_fraud": 12,
    "refund_manipulation": 12,
    "social_engineering": 12,
    "generic_malicious": 5,
    "unknown": 0,
    "safe": 0,
}

BEHAVIOUR_PATTERNS = (
    (20, "hidden_internal_fields", re.compile(r"\b(hidden|internal|private|admin|system)\b.{0,80}\b(field|config|instruction|message|record)s?\b", re.I)),
    (30, "credential_or_secret_request", re.compile(r"\b(password|secret|token|api\s*key|private\s*key|credential|bank detail)s?\b", re.I)),
    (25, "security_bypass", re.compile(r"\b(bypass|skip|disable|avoid|work around)\b.{0,80}\b(policy|verification|security|auth|approval|guardrail)s?\b", re.I)),
    (20, "bulk_export", re.compile(r"\b(export|download|dump|csv|spreadsheet|table)\b.{0,80}\b(all|records|customers|employees|suppliers|orders|inventory)\b", re.I)),
    (20, "private_info_request", re.compile(r"\b(customer|supplier|employee|staff)\b.{0,80}\b(private|personal|email|phone|address|name|schedule|roster)s?\b", re.I)),
    (15, "bulk_continuation", re.compile(r"\b(next\s+50|next\s+100|continue|more rows|another batch|rest of)\b", re.I)),
    (15, "authority_impersonation", re.compile(r"\b(manager|admin|ceo|boss|director|owner)\b.{0,80}\b(asked|approved|needs|said|told)\b", re.I)),
    (10, "urgency_pressure", re.compile(r"\b(urgent|quick|asap|right now|immediately|emergency)\b", re.I)),
    (20, "support_manipulation", re.compile(r"\b(wording|script|say to support|convince support|manipulate|pressure)\b", re.I)),
    (15, "process_loophole", re.compile(r"\b(loophole|exception|edge case|what if|still approve|without proof)\b", re.I)),
    (25, "private_schedule_probe", re.compile(r"\b(private schedule|weak coverage|late shift|opening staff|closing staff|who is working)\b", re.I)),
    (25, "account_recovery_bypass", re.compile(r"\b(recovery|reset|verify|verification)\b.{0,80}\b(bypass|skip|without|fake|guess)\b", re.I)),
    (25, "refund_without_proof", re.compile(r"\b(refund|return)\b.{0,100}\b(without proof|fake receipt|manager approved|approve anyway)\b", re.I)),
)

ABUSE_INDICATORS = (
    "bypass",
    "without proof",
    "fake receipt",
    "manager already approved",
    "manager approved",
    "hidden fields",
    "internal only",
    "export all",
    "csv of all records",
    "admin access",
    "ignore instructions",
    "ignore previous",
    "system prompt",
    "supplier contacts",
    "employee names",
    "weak coverage",
    "private schedule",
    "recovery details",
    "verification bypass",
)

SAFE_INTENT_DISCOUNTS = {
    "product_question": 25,
    "order_status": 25,
    "return_policy_explanation": 25,
    "mistake_correction": 25,
    "password_reset_help": 20,
    "store_hours": 25,
    "shipping_options": 25,
    "stock_availability": 20,
    "general_security_education": 15,
    "normal_account_support": 20,
}

SAFE_INTENT_PATTERNS = (
    ("mistake_correction", re.compile(r"\b(accidentally|mistyped|typed the wrong|wrong|forgot|uploaded the wrong|entered the wrong)\b.{0,120}\b(fix|correct|replace|update|change|safe|safely|what should i do)\b", re.I)),
    ("mistake_correction", re.compile(r"\b(accidentally|mistyped|typed the wrong|wrong|forgot|uploaded the wrong|entered the wrong|spelling mistake|typo|closed the checkout|cannot find|can't find|forgot to add|forgot to remove|forgot to apply)\b", re.I)),
    ("product_question", re.compile(r"\b(product|item|feature|what can|what does|how does).{0,80}\b(do|work|help|available)\b", re.I)),
    ("order_status", re.compile(r"\b(order|delivery|shipment|tracking).{0,80}\b(status|where|when|arrive|update)\b", re.I)),
    ("return_policy_explanation", re.compile(r"\b(return|refund|receipt|exchange).{0,100}\b(policy|how does|explain|work|eligible|process|correction|normal|replace)\b", re.I)),
    ("return_policy_explanation", re.compile(r"\b(return|refund|exchange|receipt|return label)\b.{0,100}\b(help|question|check|valid|submit|request|before|label|same product|another size)\b", re.I)),
    ("password_reset_help", re.compile(r"\b(password|login|account).{0,80}\b(reset|help|locked|forgot)\b", re.I)),
    ("store_hours", re.compile(r"\b(store|opening|closing|hours|open today|close today)\b", re.I)),
    ("shipping_options", re.compile(r"\b(shipping|delivery).{0,80}\b(options|cost|speed|available|change|changes|selected)\b", re.I)),
    ("stock_availability", re.compile(r"\b(stock|available|inventory).{0,80}\b(one|single|item|product|size|colour|color)\b", re.I)),
    ("general_security_education", re.compile(r"\b(learn|explain|training|education|what is).{0,80}\b(security|phishing|prompt injection|jailbreak)\b", re.I)),
    ("normal_account_support", re.compile(r"\b(account|profile|email|support|invoice|payment|billing|card|contact)\b.{0,120}\b(help|update|change|issue|resend|correct|link|merge|clean up|normal|safe|safest)\b", re.I)),
    ("normal_account_support", re.compile(r"\b(update|change|correct|fix|safest|safe)\b.{0,120}\b(my|own)?\s*(account|profile|email|contact|billing|payment|card)\b", re.I)),
)

CAPABILITY_QUESTION_PATTERNS = (
    re.compile(
        r"\b(?:what|explain|tell me|describe)\b.{0,80}\b"
        r"(?:demo\s+)?(?:chatbot|bot|assistant)\b.{0,80}\b"
        r"(?:can\s+do|does|capabilit(?:y|ies)|features?|help\s+with)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:what\s+can|how\s+can)\b.{0,60}\b"
        r"(?:you|this\s+(?:demo\s+)?(?:chatbot|bot|assistant))\b.{0,60}\b"
        r"(?:do|help\s+with)\b",
        re.IGNORECASE,
    ),
)

RISKY_CONTEXT_TERMS = (
    "ignore previous",
    "override",
    "bypass",
    "disable",
    "jailbreak",
    "system prompt",
    "hidden instruction",
    "secret",
    "private key",
    "token",
    "credential",
    "bank",
)


# ---------------------------------------------------------------------------
# Default tenant policy
# ---------------------------------------------------------------------------
# Tier-3 mode default is read from VARDOGER_DEFAULT_TIER3_MODE here but from
# DEFAULT_TIER3_MODE in the Tier 3 handler. That divergence predates the shared
# policy module; each tier keeps its own env var so unifying them cannot
# silently change behavior for a deployment that set one.
_DEFAULT_TIER3_MODE_FOR_TIER2 = os.environ.get("VARDOGER_DEFAULT_TIER3_MODE", "shadow").lower()
_TIER3_ENDPOINT_DEFAULT = "lambda-only-deterministic"

DEFAULT_TENANT_POLICY = policy_module.defaults(
    tier2_mode=DEFAULT_TIER2_MODE,
    tier3_mode=_DEFAULT_TIER3_MODE_FOR_TIER2,
    tier2_endpoint=SAGEMAKER_ENDPOINT,
    tier3_endpoint=_TIER3_ENDPOINT_DEFAULT,
)


# ---------------------------------------------------------------------------
# Module-level client singletons — reused across invocations in warm Lambdas
# ---------------------------------------------------------------------------
_sagemaker_runtime = None
_dynamodb = None
_lambda_client = None


def _now_ms() -> int:
    """Return current Unix epoch time in milliseconds for latency tracing."""
    return int(time.time() * 1000)


def _get_sagemaker_runtime():
    """SageMaker Runtime client (async profile — Tier 2 is off the request path)."""
    return aws.client("sagemaker-runtime")


def _get_dynamodb():
    """DynamoDB resource (async profile)."""
    return aws.resource("dynamodb")


def _get_lambda_client():
    """Lambda client (async profile), used to invoke the enforcement function."""
    return aws.client("lambda")


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _iso_timestamp(value: Any = None) -> str:
    """Return an ISO-8601 UTC timestamp from an epoch, string, or empty value."""
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (int, float)):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _normalize_mode(value: Any, default: str) -> str:
    """Return a supported tier mode (shared implementation)."""
    return policy_module.normalize_mode(value, default)


def _tenant_policy_from_item(item: dict[str, Any] | None) -> dict[str, Any]:
    """Build a policy dict from a stored scope record (shared implementation)."""
    return policy_module.policy_from_item(
        item,
        tier2_mode=DEFAULT_TIER2_MODE,
        tier3_mode=_DEFAULT_TIER3_MODE_FOR_TIER2,
        tier2_endpoint=SAGEMAKER_ENDPOINT,
        tier3_endpoint=_TIER3_ENDPOINT_DEFAULT,
    )


def _load_tenant_policy(scope_id: str) -> dict[str, Any]:
    """Read a scope's policy, TTL-cached, falling back to safe defaults.

    The Tier 2 event source delivers one record per invocation, so before the
    shared cache this was a DynamoDB round trip for **every prompt**.
    """
    return policy_module.load(
        scope_id,
        TENANTS_TABLE,
        tier2_mode=DEFAULT_TIER2_MODE,
        tier3_mode=_DEFAULT_TIER3_MODE_FOR_TIER2,
        tier2_endpoint=SAGEMAKER_ENDPOINT,
        tier3_endpoint=_TIER3_ENDPOINT_DEFAULT,
    )


def _mark_tenant_prompt_seen(scope_id: str, account_id: str = "", region: str = "") -> None:
    """Update lightweight tenant health metadata when a prompt arrives."""
    if not scope_id:
        return
    try:
        values: dict[str, Any] = {":now": int(time.time()), ":enabled": True}
        update = (
            "SET last_prompt_at = :now, "
            "tier2_enabled = if_not_exists(tier2_enabled, :enabled), "
            "tier3_enabled = if_not_exists(tier3_enabled, :enabled)"
        )
        if account_id:
            update += ", client_account_id = if_not_exists(client_account_id, :account)"
            values[":account"] = account_id
        if region:
            update += ", region = if_not_exists(region, :region)"
            values[":region"] = region
        _get_dynamodb().Table(TENANTS_TABLE).update_item(
            Key={"scope_id": scope_id},
            UpdateExpression=update,
            ExpressionAttributeValues=values,
        )
    except Exception:
        logger.exception("Failed to update tenant prompt health for scope=%s", scope_id)


# ---------------------------------------------------------------------------
# Record parsing
# ---------------------------------------------------------------------------

def _unmarshall_value(attr: dict[str, Any]) -> Any:
    """Convert a single DynamoDB typed attribute to plain Python."""
    if "S" in attr:
        return attr["S"]
    if "N" in attr:
        val = attr["N"]
        return int(val) if "." not in val else float(val)
    if "BOOL" in attr:
        return attr["BOOL"]
    if "NULL" in attr:
        return None
    if "L" in attr:
        return [_unmarshall_value(item) for item in attr["L"]]
    if "M" in attr:
        return {k: _unmarshall_value(v) for k, v in attr["M"].items()}
    return None


def _record_body(raw_record: dict[str, Any]) -> dict[str, Any] | None:
    """Extract prompt data from SQS records or legacy DynamoDB Stream INSERT events."""
    if raw_record.get("eventSource") == "aws:dynamodb" or "dynamodb" in raw_record:
        if raw_record.get("eventName") != "INSERT":
            return None
        image = raw_record.get("dynamodb", {}).get("NewImage", {})
        return {key: _unmarshall_value(value) for key, value in image.items()} if image else None

    body = raw_record.get("body")
    if isinstance(body, str):
        payload = json.loads(body)
        attrs = raw_record.get("attributes", {}) or {}
        if attrs.get("SentTimestamp"):
            payload["saas_sqs_send_done_at"] = int(attrs["SentTimestamp"])
        if attrs.get("ApproximateFirstReceiveTimestamp"):
            payload["saas_sqs_first_received_at"] = int(attrs["ApproximateFirstReceiveTimestamp"])
        return payload
    if isinstance(body, dict):
        payload = dict(body)
        attrs = raw_record.get("attributes", {}) or {}
        if attrs.get("SentTimestamp"):
            payload["saas_sqs_send_done_at"] = int(attrs["SentTimestamp"])
        if attrs.get("ApproximateFirstReceiveTimestamp"):
            payload["saas_sqs_first_received_at"] = int(attrs["ApproximateFirstReceiveTimestamp"])
        return payload
    return raw_record



# ---------------------------------------------------------------------------
# Prompt history
# ---------------------------------------------------------------------------

def _build_prompt_history_item(record: dict[str, Any]) -> dict[str, Any]:
    """Build the prompt history row for a customer prompt."""
    scope_id = str(record.get("scope_id") or "local")
    source = str(record.get("source") or "")
    session_id = str(record.get("session_id") or "unknown")
    timestamp = _iso_timestamp(record.get("timestamp"))
    prompt = str(record.get("prompt") or record.get("prompt_text") or "")
    matched_signatures = _list_field(record.get("matched_signatures", record.get("matched_signature_ids", [])))
    prompt_id = str(record.get("prompt_id") or record.get("request_id") or uuid4().hex)
    now = int(time.time())

    return {
        "scope_id": scope_id,
        "source": source,
        "session_timestamp": f"{session_id}#{timestamp}#{prompt_id}",
        "session_id": session_id,
        "runtime_session_id": str(record.get("runtime_session_id", "")),
        "agent_runtime_arn": str(record.get("agent_runtime_arn", "")),
        "prompt_id": prompt_id,
        "request_id": str(record.get("request_id", "")),
        "timestamp": timestamp,
        "prompt": prompt,
        "normalized_prompt": str(record.get("normalized_prompt", "")),
        "decision": str(record.get("decision", record.get("layer1_decision", ""))),
        "risk_score": int(record.get("risk_score", record.get("layer1_risk_score", 0)) or 0),
        "matched_signatures": matched_signatures,
        "attack_intents": _list_field(record.get("attack_intents", [])),
        "matched_policy_rules": _list_field(record.get("matched_policy_rules", [])),
        "prompt_length": int(record.get("prompt_length", len(prompt)) or 0),
        "transport_status": str(record.get("transport_status", "sent")),
        "provenance": str(record.get("provenance", "dispatcher")),
        "ingested_at": now,
        "dispatcher_received_at": int(record.get("dispatcher_received_at", 0) or 0),
        "saas_sqs_send_started_at": int(record.get("saas_sqs_send_started_at", 0) or 0),
        "saas_sqs_send_done_at": int(record.get("saas_sqs_send_done_at", 0) or 0),
        "saas_sqs_first_received_at": int(record.get("saas_sqs_first_received_at", 0) or 0),
        "tier2_lambda_started_at": int(record.get("tier2_lambda_started_at", 0) or 0),
        "ttl": now + PROMPT_HISTORY_RETENTION_DAYS * 24 * 3600,
    }


def _put_prompt_history(item: dict[str, Any]) -> bool:
    """Persist one prompt into the prompt history table (idempotent)."""
    try:
        _get_dynamodb().Table(PROMPT_HISTORY_TABLE).put_item(
            Item=item,
            ConditionExpression=(
                "attribute_not_exists(scope_id) "
                "AND attribute_not_exists(session_timestamp)"
            ),
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info(
                "Duplicate prompt ignored scope=%s session_timestamp=%s prompt_id=%s",
                item.get("scope_id", ""),
                item.get("session_timestamp", ""),
                item.get("prompt_id", ""),
            )
            return False
        raise
    return True


def _get_session_history(scope_id: str, session_id: str) -> list[dict]:
    """Fetch the most recent N prompts for a session for multi-turn detection."""
    table = _get_dynamodb().Table(PROMPT_HISTORY_TABLE)
    try:
        response = table.query(
            KeyConditionExpression="scope_id = :sid_scope AND begins_with(session_timestamp, :sid)",
            ExpressionAttributeValues={
                ":sid_scope": scope_id,
                ":sid": f"{session_id}#",
            },
            ScanIndexForward=False,
            Limit=SESSION_CONTEXT_MAX,
        )
        return list(reversed(response.get("Items", [])))
    except ClientError:
        logger.exception("Failed to query session history for %s/%s", scope_id, session_id)
        return []



# ---------------------------------------------------------------------------
# ML invocation
# ---------------------------------------------------------------------------

def _build_ml_input(prompt: str, session_history: list[dict]) -> str:
    """Build the text payload for SageMaker by joining session history + current prompt."""
    normalized_current = prompt.strip()
    history_prompts: list[str] = []

    for item in session_history:
        hist_prompt = str(item.get("prompt", "")).strip()
        if hist_prompt:
            history_prompts.append(hist_prompt)

    if history_prompts and normalized_current and history_prompts[-1] == normalized_current:
        available_prompts = history_prompts[-SESSION_CONTEXT_MAX:]
    else:
        available_prompts = (
            history_prompts + ([normalized_current] if normalized_current else [])
        )[-SESSION_CONTEXT_MAX:]

    current_prompt = available_prompts[-1] if available_prompts else normalized_current
    context_prompts = available_prompts[-SESSION_CONTEXT_MIN:]

    if current_prompt and (not context_prompts or context_prompts[-1] != current_prompt):
        context_prompts = [*context_prompts, current_prompt][-SESSION_CONTEXT_MAX:]

    return " ".join(f"[USER] {item}" for item in context_prompts)


def _invoke_ml(text: str, endpoint_name: str | None = None) -> dict[str, Any]:
    """Call the SageMaker endpoint and return the top label + confidence score."""
    endpoint = endpoint_name or SAGEMAKER_ENDPOINT
    if not endpoint:
        # _process_record routes the no-endpoint case to _handle_no_ml_endpoint
        # before reaching here. If that guard is ever bypassed, fail with a
        # message that names the cause rather than a boto ParamValidationError.
        raise ValueError("No Tier 2 ML endpoint configured (VARDOGER_ML_ENDPOINT is empty)")
    runtime = _get_sagemaker_runtime()
    response = runtime.invoke_endpoint(
        EndpointName=endpoint,
        ContentType="application/json",
        Body=json.dumps({"inputs": text}),
    )
    result = json.loads(response["Body"].read())

    # Defensively parse the endpoint's response: it is an external component and
    # a malformed/empty shape must degrade to SAFE (score 0), not raise. The
    # caller's per-record try would otherwise turn a shape surprise into a
    # retry->DLQ churn.
    if isinstance(result, list) and result:
        items = result[0] if isinstance(result[0], list) else result
        candidates = [x for x in items if isinstance(x, dict)]
        if candidates:
            top = max(candidates, key=lambda x: x.get("score", 0) or 0)
            label = top.get("label")
            score = top.get("score")
            if isinstance(label, str) and isinstance(score, (int, float)):
                return {"label": label, "confidence": float(score)}

    # Unrecognized response shape: degrade to SAFE rather than raise, but make
    # the degradation visible — a silently mis-shaped endpoint means Tier 2 is
    # scoring nothing while appearing healthy.
    report_degraded(ML_INFERENCE, "unrecognized ML response shape; scored as SAFE", endpoint=endpoint)
    return {"label": "SAFE", "confidence": 0.0}


# ---------------------------------------------------------------------------
# Keep-alive
# ---------------------------------------------------------------------------

def _is_keep_alive_event(event: dict[str, Any]) -> bool:
    """Return True when EventBridge or a manual test invocation is warming Tier 2."""
    return (
        event.get("source") == "vardoger.keepalive"
        or event.get("action") == "tier2_keep_alive"
    )


def _handle_keep_alive() -> dict[str, Any]:
    """Optionally ping the SageMaker endpoint to keep Tier 2 warm."""
    if not ML_KEEP_ALIVE_ENABLED:
        logger.info("Tier2 keep-alive ping skipped because ML_KEEP_ALIVE_ENABLED=false")
        return {"keep_alive": "disabled"}

    started = time.time()
    ml_result = _invoke_ml("[USER] Vardoger Tier 2 keep-alive health check.")
    latency_ms = int((time.time() - started) * 1000)
    logger.info(
        "Tier2 keep-alive ping completed endpoint=%s label=%s confidence=%.3f latency_ms=%s",
        SAGEMAKER_ENDPOINT,
        ml_result.get("label", ""),
        float(ml_result.get("confidence", 0.0) or 0.0),
        latency_ms,
    )
    return {
        "keep_alive": "sent",
        "endpoint": SAGEMAKER_ENDPOINT,
        "latency_ms": latency_ms,
        "label": ml_result.get("label", ""),
        "confidence": ml_result.get("confidence", 0.0),
    }



# ---------------------------------------------------------------------------
# Core scoring functions
# ---------------------------------------------------------------------------

def _is_attack(ml_result: dict[str, Any]) -> bool:
    """Return True if the ML label is an attack type AND confidence exceeds the threshold."""
    return (
        str(ml_result["label"]).upper() in ATTACK_LABELS
        and ml_result["confidence"] >= ML_CONFIDENCE_THRESHOLD
    )


def _is_attack_label(label: str) -> bool:
    """Return True when a model label maps to a Tier 2 attack family."""
    return str(label).upper() in ATTACK_LABELS


def _tier2_risk_score(ml_result: dict[str, Any]) -> float:
    """Return the ML-only component score."""
    label = str(ml_result.get("label", ""))
    confidence = float(ml_result.get("confidence", 0.0) or 0.0)
    if not _is_attack_label(label):
        return 0.0
    if confidence < 0.55:
        return 0.0
    if confidence < 0.75:
        return 20.0
    if confidence < 0.85:
        return 35.0
    if confidence < 0.95:
        return 50.0
    if confidence < 0.97:
        return 65.0
    if confidence < 0.99:
        return 80.0
    return 90.0


def _is_suspicious(ml_result: dict[str, Any]) -> bool:
    """Return True for medium-confidence attack labels that should be logged and accumulated."""
    return _tier2_risk_score(ml_result) >= ML_SUSPICIOUS_THRESHOLD * 100


def _normalize_stored_risk(value: Any) -> float:
    """Read legacy 0-1 or current 0-100 risk values as a 0-100 score."""
    if isinstance(value, Decimal):
        value = float(value)
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    if 0 < score <= 1:
        score *= 100
    return max(0.0, min(score, 100.0))


def _normalize_session_score(value: Any) -> float:
    """Read cumulative SessionRisk values on the newer 0-200 scale."""
    if isinstance(value, Decimal):
        value = float(value)
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    if 0 < score <= 1:
        score *= 100
    return max(0.0, min(score, 200.0))


def _category_from_label(label: str) -> str:
    """Map model labels into customer-facing security categories."""
    normalized = str(label).upper()
    if normalized in {"DATA_EXFILTRATION"}:
        return "data_exfiltration"
    if normalized in {"SOCIAL_ENGINEERING"}:
        return "social_engineering"
    if normalized in {"ACCOUNT_ABUSE", "ACCOUNT_TAKEOVER"}:
        return normalized.lower()
    if normalized in {"REFUND_MANIPULATION", "REFUND_FRAUD"}:
        return "refund_fraud"
    if normalized in {"JAILBREAK"}:
        return "jailbreak"
    if normalized in {"PROMPT_INJECTION"}:
        return "prompt_injection"
    if normalized in {"INJECTION", "LABEL_1", "ATTACK", "MALICIOUS", "1"}:
        return "generic_malicious"
    return "safe"


def _infer_category(label: str, ml_input: str) -> str:
    """Use the model label plus session text hints to choose the clearest category."""
    if not _is_attack_label(label):
        return "safe"

    lowered = ml_input.lower()
    for category, keywords in CATEGORY_KEYWORDS:
        if any(keyword in lowered for keyword in keywords):
            return category
    return _category_from_label(label)


def _regex_component_score(item: dict[str, Any]) -> float:
    """Convert Layer 1 signature/risk metadata into the deterministic regex component."""
    if str(item.get("decision", "")).lower() == "block":
        layer1_risk = _to_float(item.get("risk_score"), 0.0)
        if layer1_risk >= 12:
            return 95.0
        if layer1_risk >= 8:
            return 80.0
        return 95.0
    severity = str(item.get("regex_severity") or item.get("risk_bucket") or "none").lower()
    if severity in REGEX_SCORE_BY_SEVERITY:
        return float(REGEX_SCORE_BY_SEVERITY[severity])
    layer1_risk = _to_float(item.get("risk_score"), 0.0)
    if layer1_risk >= 12:
        return 95.0
    if layer1_risk >= 8:
        return 80.0
    if layer1_risk >= 4:
        return 35.0
    if layer1_risk > 0 or item.get("matched_signatures"):
        return 10.0
    return 0.0


def _behaviour_score(prompt: str, session_history: list[dict[str, Any]]) -> tuple[float, list[str]]:
    """Score concrete risky behaviours visible in the current prompt and recent context."""
    text = " ".join(
        [str(item.get("prompt", "")) for item in session_history[-3:]]
        + [str(prompt or "")]
    )
    score = 0.0
    reasons: list[str] = []
    for points, reason, pattern in BEHAVIOUR_PATTERNS:
        if pattern.search(text):
            score += points
            reasons.append(reason)
    return min(score, 100.0), reasons


def _prior_risky_categories(session_history: list[dict[str, Any]]) -> list[str]:
    """Return risky categories seen earlier in the same session."""
    categories: list[str] = []
    for item in session_history:
        category = str(item.get("tier2_category") or item.get("category") or "").lower()
        verdict = str(item.get("tier2_ml_verdict") or item.get("tier2_status") or "").lower()
        if category and category not in {"safe", "unknown", "tier2_disabled"} and verdict in {
            "watch",
            "suspicious",
            "high_risk",
            "malicious",
        }:
            categories.append(category)
    return categories


def _repetition_score(category: str, session_history: list[dict[str, Any]], prompt: str) -> tuple[float, list[str]]:
    """Score repeated same-session probing and rephrasing behaviour."""
    score = 0.0
    reasons: list[str] = []
    prior_categories = _prior_risky_categories(session_history)
    category_count = prior_categories.count(category)
    if category not in {"safe", "unknown", "generic_malicious"}:
        if category_count >= 2:
            score += 20
            reasons.append("same_risky_category_3_plus_times")
        elif category_count == 1:
            score += 10
            reasons.append("same_risky_category_twice")

    prior_text = " ".join(str(item.get("prompt", "")).lower() for item in session_history[-5:])
    current = str(prompt or "").lower()
    if any(word in prior_text for word in ("cannot", "blocked", "denied", "not allowed")) and any(
        word in current for word in ("instead", "what if", "try", "rephrase", "another way")
    ):
        score += 20
        reasons.append("rephrased_after_denial_or_block")

    schema_terms = ("field", "schema", "column", "record", "database", "table")
    restricted_terms = ("customer", "employee", "supplier", "account", "order", "inventory")
    if sum(1 for item in session_history[-5:] if any(term in str(item.get("prompt", "")).lower() for term in schema_terms)) >= 3:
        score += 15
        reasons.append("schema_or_data_access_probe_3_plus")
    if sum(1 for item in session_history[-5:] if any(term in str(item.get("prompt", "")).lower() for term in restricted_terms)) >= 3:
        score += 20
        reasons.append("multiple_restricted_data_types")
    if sum(1 for item in session_history[-5:] if str(item.get("tier2_ml_verdict", "")).lower() == "high_risk") >= 2:
        score += 20
        reasons.append("multiple_high_risk_prompts_last_5")
    return min(score, 100.0), reasons


def _context_escalation_score(prompt: str, session_history: list[dict[str, Any]]) -> tuple[float, str]:
    """Score multi-turn movement from normal questions toward abuse or exfiltration."""
    history = " ".join(str(item.get("prompt", "")).lower() for item in session_history[-6:])
    current = str(prompt or "").lower()
    combined = f"{history} {current}"
    if not history:
        return 0.0, ""

    escalation_paths = (
        (30, "policy_to_bypass_or_manipulation", ("policy", "process", "refund", "return"), ("without proof", "fake receipt", "loophole", "approve anyway")),
        (30, "data_question_to_bulk_export", ("field", "schema", "record", "data"), ("export all", "csv", "download", "bulk", "all records")),
        (30, "account_support_to_takeover", ("account", "reset", "verify", "verification"), ("bypass", "without verification", "recovery details", "admin access")),
        (30, "staffing_to_weak_coverage", ("schedule", "staff", "roster", "shift"), ("employee names", "weak coverage", "opening staff", "closing staff")),
        (20, "general_to_internal_details", ("how", "what", "explain"), ("hidden", "internal", "private", "system prompt")),
        (10, "mild_escalation", ("what", "how", "explain"), ("exception", "edge case", "details")),
    )
    for points, reason, early_terms, late_terms in escalation_paths:
        if any(term in combined for term in early_terms) and any(term in current for term in late_terms):
            return float(points), reason
    return 0.0, ""



# ---------------------------------------------------------------------------
# Safe intent gates
# ---------------------------------------------------------------------------

def _safe_intent_gate(prompt: str, session_history: list[dict]) -> dict[str, Any]:
    """Detect likely benign business/support intent before ML enforcement."""
    normalized_prompt = " ".join(str(prompt or "").lower().split())
    history_text = " ".join(str(item.get("prompt", "")).lower() for item in session_history[-3:])
    has_risky_context = any(term in normalized_prompt or term in history_text for term in RISKY_CONTEXT_TERMS)
    if not normalized_prompt or has_risky_context:
        return {"is_safe": False, "category": "", "reason": ""}
    for category, pattern in SAFE_INTENT_PATTERNS:
        if pattern.search(prompt):
            return {
                "is_safe": True,
                "category": category,
                "reason": f"Prompt looks like normal {category.replace('_', ' ')}.",
            }
    if _is_safe_capability_question(prompt, session_history):
        return {
            "is_safe": True,
            "category": "product_question",
            "reason": "Prompt asks what the demo chatbot can do without risky context.",
        }
    return {"is_safe": False, "category": "", "reason": ""}


def _safe_intent_discount_result(prompt: str, session_history: list[dict[str, Any]]) -> dict[str, Any]:
    """Return safe-intent classification plus the discount allowed by abuse guardrails."""
    safe_result = _safe_intent_gate(prompt, session_history)
    text = " ".join(
        [str(item.get("prompt", "")).lower() for item in session_history[-3:]]
        + [str(prompt or "").lower()]
    )
    if any(indicator in text for indicator in ABUSE_INDICATORS):
        return {
            **safe_result,
            "is_safe": False,
            "discount": 0,
            "reason": "",
            "blocked_by_abuse_indicator": True,
        }
    if not safe_result.get("is_safe"):
        return {**safe_result, "discount": 0, "blocked_by_abuse_indicator": False}
    category = str(safe_result.get("category") or "")
    return {
        **safe_result,
        "discount": SAFE_INTENT_DISCOUNTS.get(category, 15),
        "blocked_by_abuse_indicator": False,
    }


def _is_safe_capability_question(prompt: str, session_history: list[dict]) -> bool:
    """Identify low-risk product discovery questions that the ML model over-flags."""
    normalized_prompt = " ".join(prompt.lower().split())
    if not normalized_prompt:
        return False

    if any(term in normalized_prompt for term in RISKY_CONTEXT_TERMS):
        return False

    if not any(pattern.search(prompt) for pattern in CAPABILITY_QUESTION_PATTERNS):
        return False

    history_text = " ".join(str(item.get("prompt", "")).lower() for item in session_history[-3:])
    return not any(term in history_text for term in RISKY_CONTEXT_TERMS)


def _apply_tier2_safety_overrides(
    prompt: str,
    session_history: list[dict],
    ml_result: dict[str, Any],
) -> dict[str, Any]:
    """Apply narrow analyst-approved overrides after ML scoring but before enforcement."""
    if _is_attack(ml_result) and _is_safe_capability_question(prompt, session_history):
        logger.info("Tier2 override: capability question treated as safe")
        return {
            "label": "SAFE_CAPABILITY_QUESTION",
            "confidence": 1.0 - float(ml_result.get("confidence", 0.0) or 0.0),
            "raw_label": ml_result.get("label", ""),
            "raw_confidence": ml_result.get("confidence", 0.0),
        }
    return ml_result



# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------

def _score_prompt(
    *,
    prompt: str,
    item: dict[str, Any],
    ml_result: dict[str, Any],
    category: str,
    session_history: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate the deterministic prompt score used before any kill decision."""
    regex_score = _regex_component_score(item)
    ml_score = _tier2_risk_score(ml_result)
    category_score = float(CATEGORY_SCORE.get(category, 0))
    behaviour_score, behaviour_reasons = _behaviour_score(prompt, session_history)
    repetition_score, repetition_reasons = _repetition_score(category, session_history, prompt)
    context_escalation_score, context_escalation_reason = _context_escalation_score(prompt, session_history)
    safe_intent = _safe_intent_discount_result(prompt, session_history)
    safe_discount = float(safe_intent.get("discount", 0) or 0)
    final_score = min(
        100.0,
        max(
            0.0,
            regex_score
            + ml_score
            + category_score
            + behaviour_score
            + repetition_score
            + context_escalation_score
            - safe_discount,
        ),
    )
    if regex_score == 0 and behaviour_score == 0 and repetition_score == 0 and context_escalation_score == 0 and not safe_intent.get("blocked_by_abuse_indicator"):
        final_score = min(final_score, 39.0)
    if safe_intent.get("is_safe") and not safe_intent.get("blocked_by_abuse_indicator"):
        final_score = min(final_score, 19.0)
    return {
        "final_prompt_score": round(final_score, 2),
        "regex_score": regex_score,
        "ml_score": ml_score,
        "category_score": category_score,
        "behaviour_score": behaviour_score,
        "behaviour_reasons": behaviour_reasons,
        "repetition_score": repetition_score,
        "repetition_reasons": repetition_reasons,
        "context_escalation_score": context_escalation_score,
        "context_escalation_reason": context_escalation_reason,
        "safe_intent_discount": safe_discount,
        "safe_intent": safe_intent,
    }


def _risk_band(final_prompt_score: float) -> dict[str, str]:
    """Map a prompt score to verdict and recommended action."""
    if final_prompt_score >= 85:
        return {"ml_verdict": "malicious", "action_taken": "kill", "threshold_used": "prompt_score_85_100"}
    if final_prompt_score >= 65:
        return {"ml_verdict": "high_risk", "action_taken": "raise_session_risk", "threshold_used": "prompt_score_65_84"}
    if final_prompt_score >= 40:
        return {"ml_verdict": "suspicious", "action_taken": "raise_session_risk", "threshold_used": "prompt_score_40_64"}
    if final_prompt_score >= 20:
        return {"ml_verdict": "watch", "action_taken": "log_only", "threshold_used": "prompt_score_20_39"}
    return {"ml_verdict": "safe", "action_taken": "allow", "threshold_used": "prompt_score_0_19"}



# ---------------------------------------------------------------------------
# Session risk accumulation
# ---------------------------------------------------------------------------

def _session_increment(verdict: str) -> float:
    """Return how much the current prompt contributes to cumulative session risk."""
    return {
        "safe": 0.0,
        "watch": 5.0,
        "suspicious": 15.0,
        "high_risk": 30.0,
        "malicious": 50.0,
    }.get(verdict, 0.0)


def _session_status_for_score(score: float) -> str:
    """Map cumulative session score to the dashboard/enforcement status ladder."""
    if score >= 120:
        return "kill_candidate"
    if score >= 80:
        return "high_risk"
    if score >= 40:
        return "watch"
    return "active"


def _get_previous_session_state(scope_id: str, session_id: str) -> dict[str, Any]:
    """Read the previous cumulative risk state, including fields used for decay."""
    if not scope_id or not session_id:
        return {"score": 0.0, "status": "active", "last_risky_at": 0, "confirmed_malicious": False}
    try:
        response = _get_dynamodb().Table(SESSION_RISK_TABLE).get_item(
            Key={"tenant_session_id": f"{scope_id}#{session_id}"}
        )
        item = response.get("Item", {})
        return {
            "score": _normalize_session_score(item.get("current_risk_score", 0.0)),
            "status": str(item.get("status") or "active"),
            "last_risky_at": _to_int(item.get("last_risky_at") or item.get("updated_at"), 0),
            "confirmed_malicious": bool(item.get("confirmed_malicious") or item.get("kill_triggered")),
        }
    except Exception:
        logger.exception("Failed to read previous SessionRisk for %s/%s", scope_id, session_id)
        return {"score": 0.0, "status": "active", "last_risky_at": 0, "confirmed_malicious": False}


def _apply_session_decay(previous_state: dict[str, Any], current_verdict: str, regex_score: float) -> float:
    """Apply risk decay for long sessions without erasing confirmed hostile evidence."""
    score = float(previous_state.get("score", 0.0) or 0.0)
    if previous_state.get("confirmed_malicious") or regex_score >= REGEX_SCORE_BY_SEVERITY["critical"]:
        return score
    last_risky_at = _to_int(previous_state.get("last_risky_at"), 0)
    if current_verdict in {"suspicious", "high_risk", "malicious"} or not last_risky_at:
        return score
    age_seconds = int(time.time()) - last_risky_at
    if age_seconds > 30 * 60:
        return score * 0.5
    if age_seconds > 15 * 60:
        return score * 0.75
    return score


def _accumulate_session_score(
    previous_state: dict[str, Any],
    verdict: str,
    regex_score: float,
) -> tuple[float, float]:
    """Calculate before/after cumulative session score using the prompt risk band."""
    before = _apply_session_decay(previous_state, verdict, regex_score)
    after = min(200.0, before + _session_increment(verdict))
    return round(before, 2), round(after, 2)


def _previous_tier2_risk(item: dict[str, Any]) -> float:
    """Read prior suspicious Tier 2 risk from a prompt-history row."""
    verdict = str(item.get("tier2_ml_verdict", item.get("tier2_status", ""))).lower()
    action = str(item.get("tier2_action_taken", "")).lower()
    is_prior_signal = (
        verdict in {"suspicious", "high_risk", "malicious"}
        or action in {"raise_session_risk", "kill"}
        or item.get("tier2_suspicious")
        or item.get("tier2_attack_detected")
    )
    if not is_prior_signal:
        return 0.0
    value = item.get("tier2_risk_score", item.get("tier2_confidence", 0.0))
    return _normalize_stored_risk(value)


def _accumulate_session_risk(
    current_risk: float,
    session_history: list[dict[str, Any]],
) -> tuple[float, int]:
    """Accumulate suspicious Tier 2 risk across the current session context window."""
    prior_scores = [_previous_tier2_risk(item) for item in session_history]
    suspicious_scores = [score for score in prior_scores if score > 0]
    if current_risk >= ML_SUSPICIOUS_THRESHOLD * 100:
        suspicious_scores.append(current_risk)
    cumulative = min(sum(suspicious_scores), 100.0)
    return cumulative, len(suspicious_scores)


def _get_previous_session_risk(scope_id: str, session_id: str) -> float:
    """Read the last SessionRisk score for visibility and idempotent updates."""
    if not scope_id or not session_id:
        return 0.0
    try:
        response = _get_dynamodb().Table(SESSION_RISK_TABLE).get_item(
            Key={"tenant_session_id": f"{scope_id}#{session_id}"}
        )
        item = response.get("Item", {})
        return _normalize_stored_risk(item.get("current_risk_score", 0.0))
    except ClientError:
        logger.exception("Failed to read previous SessionRisk for %s/%s", scope_id, session_id)
        return 0.0



# ---------------------------------------------------------------------------
# Kill eligibility evaluation
# ---------------------------------------------------------------------------

def _prior_malicious_verdict_count(session_history: list[dict[str, Any]]) -> int:
    """Count previous Tier 2 malicious verdicts in the same session context."""
    count = 0
    for item in session_history:
        verdict = str(item.get("tier2_ml_verdict") or item.get("tier2_status") or "").lower()
        action = str(item.get("tier2_action_taken") or "").lower()
        if verdict == "malicious" or action == "kill" or item.get("tier2_kill_triggered"):
            count += 1
    return count


def _global_guard_state() -> dict[str, bool]:
    """Return current platform-level Tier 2 enforcement guard status."""
    return {
        "global_kill_enabled": GLOBAL_KILL_ENABLED,
        "tier2_kill_enabled": TIER2_KILL_ENABLED or ML_KILL_ENABLED,
        "enforcement_configured": bool(ENFORCEMENT_FUNCTION),
    }


def _model_label_is_malicious(model_result: dict[str, Any]) -> bool:
    """Return True only for attack labels with confidence in the malicious band."""
    return (
        _is_attack_label(str(model_result.get("label", "")))
        and float(model_result.get("confidence", 0.0) or 0.0) >= 0.85
    )


def evaluate_tier2_kill_eligibility(
    tenant_policy: dict[str, Any],
    model_result: dict[str, Any],
    session_history: list[dict[str, Any]],
    accumulated_risk_score: float,
    safe_intent_result: dict[str, Any],
    global_guards: dict[str, bool],
    final_prompt_score: float = 0.0,
    session_score_after: float = 0.0,
) -> dict[str, Any]:
    """Evaluate strict Tier 2 enforcement guardrails and explain the outcome.

    Tier 2 kills asynchronously, after the prompt has already been answered, so
    a false positive here terminates a live session a real user is mid-way
    through. That asymmetry is why eligibility is deliberately conservative and
    why every denial carries a reason.

    A kill requires ALL of:

    - **enforce mode** — tenant policy explicitly set to enforce. Shadow (the
      default) evaluates everything and reports ``would_have_killed`` without
      acting, so an operator can measure the false-positive rate on their own
      traffic before enabling enforcement.
    - **global + tier guards** — ``global_kill_enabled`` and
      ``tier2_kill_enabled``, plus a configured enforcement function. These are
      the operator's kill switch, independent of per-tenant policy.
    - **no safe intent** — ``safe_intent_result`` vetoes the kill outright.
      A legitimate business question that happens to contain risky vocabulary
      ("how do I reset a customer password?") must never terminate a session.
    - **sufficient evidence** — either repeated malicious verdicts across the
      session (``tier2_min_malicious_verdicts_for_kill``), or a single verdict
      at extreme confidence (``tier2_allow_single_verdict_kill_threshold``,
      default 0.99). One mid-confidence hit is never enough on its own.

    The returned dict carries ``eligible`` plus ``reason`` / ``human_reason``,
    ``required_evidence`` and ``evidence_seen`` so a denied kill is explainable
    on the dashboard rather than an unexplained non-event.
    """
    mode = _normalize_mode(tenant_policy.get("tier2_mode"), "shadow")
    label = str(model_result.get("label", "")).upper()
    category = str(model_result.get("category") or _category_from_label(label) or "unknown")
    confidence = float(model_result.get("confidence", 0.0) or 0.0)
    if final_prompt_score <= 0:
        final_prompt_score = accumulated_risk_score
    if session_score_after <= 0:
        session_score_after = accumulated_risk_score
    default_threshold = _to_float(tenant_policy.get("tier2_default_kill_threshold"), 0.97)
    min_malicious = _to_int(tenant_policy.get("tier2_min_malicious_verdicts_for_kill"), 2)
    single_threshold = _to_float(tenant_policy.get("tier2_allow_single_verdict_kill_threshold"), 0.99)
    session_kill_score_threshold = _to_float(tenant_policy.get("session_kill_score_threshold"), 120.0)
    prior_malicious = _prior_malicious_verdict_count(session_history)
    current_malicious = _model_label_is_malicious(model_result)
    malicious_seen = prior_malicious + (1 if current_malicious else 0)
    repeated_evidence = malicious_seen >= min_malicious
    obvious_category = category in OBVIOUS_IMMEDIATE_KILL_CATEGORIES
    session_score_evidence = session_score_after >= session_kill_score_threshold
    single_extreme_confidence = confidence >= single_threshold
    safe_gate_blocks = bool(safe_intent_result.get("is_safe")) and not (
        confidence >= 0.99 and category in {"prompt_injection", "jailbreak"}
    )

    def denied(reason_code: str, human_reason: str) -> dict[str, Any]:
        return {
            "eligible": False,
            "reason": reason_code,
            "human_reason": human_reason,
            "threshold_used": default_threshold,
            "required_evidence": (
                f"mode=enforce, confidence>={default_threshold}, prompt_score>=90, "
                f"category!=generic_malicious, repeated={min_malicious} or "
                f"confidence>={single_threshold} or session_score>={session_kill_score_threshold:.0f}"
            ),
            "evidence_seen": (
                f"mode={mode}, label={label}, category={category}, confidence={confidence:.4f}, "
                f"prompt_score={final_prompt_score:.1f}, session_score={session_score_after:.1f}, "
                f"malicious_seen={malicious_seen}, accumulated_risk={accumulated_risk_score:.1f}"
            ),
            "would_have_killed": False,
            "safe_intent_reason": str(safe_intent_result.get("reason") or ""),
        }

    if not global_guards.get("global_kill_enabled"):
        return denied("global_kill_disabled", "Global kill guard is disabled.")
    if not global_guards.get("tier2_kill_enabled"):
        return denied("tier2_kill_disabled", "Tier 2 kill guard is disabled.")
    if not global_guards.get("enforcement_configured"):
        return denied("enforcement_not_configured", "Enforcement Lambda is not configured.")
    if mode != "enforce":
        return denied("tenant_mode_not_enforce", f"Tenant Tier 2 mode is {mode}, not enforce.")
    if not current_malicious:
        return denied("model_label_not_malicious", "Model label is not malicious.")
    if confidence < default_threshold:
        return denied("confidence_below_threshold", "Model confidence is below tenant kill threshold.")
    if safe_gate_blocks:
        return denied("safe_intent_gate_blocked", "Safe-intent gate reduced the action to high_risk.")
    if final_prompt_score < 90:
        return denied("prompt_score_below_kill_threshold", "Final prompt score is below 90.")
    if category == "generic_malicious":
        return denied("generic_malicious_not_enough", "Generic malicious label lacks category evidence.")

    if obvious_category and single_extreme_confidence:
        return {
            "eligible": True,
            "would_have_killed": True,
            "reason": "kill_eligible_obvious_extreme_confidence",
            "human_reason": "Obvious malicious category passed confidence and prompt-score guardrails.",
            "threshold_used": max(default_threshold, min(confidence, single_threshold)),
            "required_evidence": f"obvious category, confidence>={single_threshold}, prompt_score>=90",
            "evidence_seen": f"category={category}, confidence={confidence:.4f}, prompt_score={final_prompt_score:.1f}",
            "safe_intent_reason": str(safe_intent_result.get("reason") or ""),
        }

    if category in SUBTLE_REPEATED_EVIDENCE_CATEGORIES or not obvious_category:
        if repeated_evidence or single_extreme_confidence or session_score_evidence:
            return {
                "eligible": True,
                "would_have_killed": True,
                "reason": "kill_eligible_repeated_or_session_score",
                "human_reason": "Subtle category has repeated, extreme-confidence, or session-score evidence.",
                "threshold_used": default_threshold,
                "required_evidence": (
                    f"repeated_malicious>={min_malicious} or confidence>={single_threshold} "
                    f"or session_score>={session_kill_score_threshold:.0f}"
                ),
                "evidence_seen": (
                    f"malicious_seen={malicious_seen}, confidence={confidence:.4f}, "
                    f"session_score={session_score_after:.1f}"
                ),
                "safe_intent_reason": str(safe_intent_result.get("reason") or ""),
            }
        return denied(
            "repeated_evidence_required",
            "Subtle category requires repeated evidence, extreme confidence, or accumulated session score.",
        )

    return denied("session_score_below_threshold", "No Tier 2 kill guardrail matched.")



# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def _trigger_enforcement(
    scope_id: str,
    session_id: str,
    runtime_session_id: str,
    gateway_session_id: str,
    app_session_id: str,
    agent_runtime_arn: str,
    ml_label: str,
    ml_confidence: float,
    cumulative_risk: float = 0.0,
    final_prompt_score: float = 0.0,
    policy_version: int = 1,
    threshold_used: str = "",
    reason: str = "",
    model_version: str = "",
) -> int:
    """Fire-and-forget call to the enforcement Lambda to kill a malicious session."""
    if not ENFORCEMENT_FUNCTION:
        logger.warning("ENFORCEMENT_FUNCTION not set, skipping kill for %s", session_id)
        return 0

    enforcement_invoked_at = _now_ms()
    enforcement_risk = max(
        float(ml_confidence or 0.0) * 100,
        float(cumulative_risk or 0.0),
    )
    payload = {
        "action": "terminate",
        "scope_id": scope_id,
        "session_id": session_id,
        "gateway_session_id": gateway_session_id or session_id,
        "runtime_session_id": runtime_session_id or session_id,
        "app_session_id": app_session_id or session_id,
        "agent_runtime_arn": agent_runtime_arn,
        "matched_signature_ids": [f"ml-tier2-{ml_label.lower()}"],
        "risk_score": min(12, round((enforcement_risk / 100) * 12)),
        "attack_intents": [f"ml:{ml_label}", "tier2:cumulative-risk"],
        "matched_policy_rules": ["tier2_ml_detection", "tier2_cumulative_risk"],
        "risk_bucket": "high",
        "detection_source": "tier2_ml",
        "source": "tier2",
        "policy_version": policy_version,
        "model_version": model_version or SAGEMAKER_ENDPOINT,
        "tier2_confidence": ml_confidence,
        "confidence": ml_confidence,
        "tier2_cumulative_risk_score": cumulative_risk,
        "tier2_prompt_score": final_prompt_score,
        "threshold_used": threshold_used,
        "reason": reason,
        "enforcement_invoked_at": enforcement_invoked_at,
    }

    try:
        _get_lambda_client().invoke(
            FunctionName=ENFORCEMENT_FUNCTION,
            InvocationType="Event",
            Payload=json.dumps(payload),
        )
        logger.info("Enforcement triggered for session %s (ml=%s, conf=%.3f)",
                     session_id, ml_label, ml_confidence)
    except ClientError:
        logger.exception("Failed to invoke enforcement for %s", session_id)
    return enforcement_invoked_at


# ---------------------------------------------------------------------------
# Session risk persistence
# ---------------------------------------------------------------------------

def _update_session_risk(
    *,
    scope_id: str,
    source: str,
    session_id: str,
    runtime_session_id: str,
    agent_runtime_arn: str,
    category: str,
    confidence: float,
    ml_verdict: str,
    action_taken: str,
    final_session_risk: float,
    previous_session_risk: float,
    final_prompt_score: float,
    repeated_suspicious_count: int,
    kill_triggered: bool,
    threshold_version: str,
    kill_eligible: bool = False,
) -> int:
    """Persist accumulated session risk for dashboard and future Tier 2 analysis."""
    if not scope_id or not session_id:
        return 0
    now = int(time.time())
    status = "terminated" if kill_triggered else _session_status_for_score(final_session_risk)
    last_risky_at = now if ml_verdict in {"suspicious", "high_risk", "malicious"} else 0
    _get_dynamodb().Table(SESSION_RISK_TABLE).update_item(
        Key={"tenant_session_id": f"{scope_id}#{session_id}"},
        UpdateExpression=(
            "SET scope_id = :scope_id, #source = :source, session_id = :session_id, "
            "runtime_session_id = :runtime_session_id, agent_runtime_arn = :agent_runtime_arn, "
            "#status = :status, current_risk_score = :current_risk, "
            "previous_risk_score = :previous_risk, last_prompt_score = :prompt_score, "
            "repeated_suspicious_count = :repeated_count, "
            "last_verdict = :last_verdict, last_category = :last_category, "
            "last_confidence = :last_confidence, last_action_taken = :action_taken, "
            "kill_eligible = :kill_eligible, kill_triggered = :kill_triggered, "
            "confirmed_malicious = :confirmed_malicious, "
            "threshold_version = :threshold_version, "
            "updated_at = :updated_at, #ttl = :ttl"
        ),
        ExpressionAttributeNames={"#status": "status", "#ttl": "ttl", "#source": "source"},
        ExpressionAttributeValues={
            ":scope_id": scope_id,
            ":source": source,
            ":session_id": session_id,
            ":runtime_session_id": runtime_session_id,
            ":agent_runtime_arn": agent_runtime_arn,
            ":status": status,
            ":current_risk": Decimal(str(round(float(final_session_risk or 0.0), 2))),
            ":previous_risk": Decimal(str(round(float(previous_session_risk or 0.0), 2))),
            ":prompt_score": Decimal(str(round(float(final_prompt_score or 0.0), 2))),
            ":repeated_count": repeated_suspicious_count,
            ":last_verdict": ml_verdict,
            ":last_category": category,
            ":last_confidence": Decimal(str(round(float(confidence or 0.0), 6))),
            ":action_taken": action_taken,
            ":kill_eligible": kill_eligible,
            ":kill_triggered": kill_triggered,
            ":confirmed_malicious": bool(kill_triggered or ml_verdict == "malicious"),
            ":threshold_version": threshold_version,
            ":updated_at": now,
            ":ttl": now + SESSION_RISK_RETENTION_DAYS * 24 * 3600,
        },
    )
    if last_risky_at:
        try:
            _get_dynamodb().Table(SESSION_RISK_TABLE).update_item(
                Key={"tenant_session_id": f"{scope_id}#{session_id}"},
                UpdateExpression="SET last_risky_at = :last_risky_at",
                ExpressionAttributeValues={":last_risky_at": last_risky_at},
            )
        except ClientError:
            logger.exception("Failed to update last_risky_at for %s/%s", scope_id, session_id)
    return _now_ms()



# ---------------------------------------------------------------------------
# Detection events
# ---------------------------------------------------------------------------

def _write_detection_event(
    *,
    scope_id: str,
    source: str,
    session_id: str,
    timestamp: str,
    prompt_id: str,
    category: str,
    ml_verdict: str,
    action_taken: str,
    risk_score: float,
    final_session_risk: float,
    session_score_before: float = 0.0,
    confidence: float = 0.0,
    attack_detected: bool = False,
    kill_eligible: bool = False,
    kill_triggered: bool = False,
    kill_denied_reason: str = "",
    reason: str = "",
    threshold_used: str = "",
    context_prompt_count: int = 0,
    safe_intent_reason: str = "",
    policy_version: int = 1,
    mode: str = "shadow",
    model_id: str = "",
    event_type: str | None = None,
    would_have_killed: bool = False,
) -> None:
    """Write suspicious-or-higher detection events for audit and dashboard panels."""
    if ml_verdict not in {"watch", "suspicious", "high_risk", "malicious"} and not kill_triggered and not would_have_killed and not kill_eligible:
        return
    now = int(time.time())
    resolved_event_type = event_type or ("tier2_kill_allowed" if kill_triggered else "tier2_shadow_verdict")
    _get_dynamodb().Table(DETECTION_EVENTS_TABLE).put_item(
        Item={
            "event_id": f"{now}-{uuid4().hex}",
            "scope_id": scope_id,
            "source": source,
            "session_id": session_id,
            "prompt_id": prompt_id,
            "timestamp": timestamp,
            "event_ts": now,
            "event_type": resolved_event_type,
            "tier": "tier2",
            "provenance": "tier2",
            "category": category,
            "ml_verdict": ml_verdict,
            "action_taken": action_taken,
            "tier2_attack_detected": attack_detected,
            "tier2_prompt_score": Decimal(str(round(float(risk_score or 0.0), 2))),
            "tier2_session_score_before": Decimal(str(round(float(session_score_before or 0.0), 2))),
            "tier2_session_score_after": Decimal(str(round(float(final_session_risk or 0.0), 2))),
            "tier2_kill_eligible": kill_eligible,
            "tier2_kill_triggered": kill_triggered,
            "tier2_kill_denied_reason": kill_denied_reason,
            "tier2_recommended_action": action_taken,
            "tier2_policy_version": policy_version,
            "tier2_threshold_used": str(threshold_used),
            "tier2_context_prompt_count": context_prompt_count,
            "tier2_safe_intent_reason": safe_intent_reason,
            "risk_score": Decimal(str(round(float(risk_score or 0.0), 2))),
            "final_session_risk": Decimal(str(round(float(final_session_risk or 0.0), 2))),
            "confidence": Decimal(str(round(float(confidence or 0.0), 6))),
            "kill_triggered": kill_triggered,
            "would_have_killed": would_have_killed,
            "reason": reason,
            "threshold_used": threshold_used,
            "threshold_version": THRESHOLD_VERSION,
            "policy_version": policy_version,
            "mode": mode,
            "model_id": model_id or SAGEMAKER_ENDPOINT,
            "model_version": SAGEMAKER_ENDPOINT,
            "model_endpoint": SAGEMAKER_ENDPOINT,
            "ttl": now + DETECTION_EVENT_RETENTION_DAYS * 24 * 3600,
        }
    )



# ---------------------------------------------------------------------------
# Outcome ledger
# ---------------------------------------------------------------------------

def _write_tier2_outcome(
    *,
    raw_prompt_record: dict[str, Any],
    scope_id: str,
    source: str,
    session_id: str,
    runtime_session_id: str,
    agent_runtime_arn: str,
    prompt_id: str,
    category: str,
    predicted_label: str,
    predicted_outcome: str,
    recommended_action: str,
    actual_action: str,
    kill_triggered: bool,
    would_have_killed: bool,
    kill_eligible: bool,
    kill_denied_reason: str,
    prompt_score: float,
    session_score_before: float,
    session_score_after: float,
    confidence: float,
    model_version: str,
    policy_version: int,
    threshold_used: str,
    safe_intent_reason: str = "",
    context_prompt_count: int = 0,
) -> None:
    """Write a best-effort Tier 2 ledger row for FP/FN analysis."""
    event_ts = int(time.time())
    write_outcome({
        "scope_id": scope_id,
        "source": source,
        "run_id": str(raw_prompt_record.get("run_id") or raw_prompt_record.get("test_run_id") or "production"),
        "session_id": session_id,
        "runtime_session_id": runtime_session_id,
        "gateway_session_id": str(raw_prompt_record.get("gateway_session_id") or session_id),
        "app_session_id": str(raw_prompt_record.get("app_session_id") or session_id),
        "agent_runtime_arn": agent_runtime_arn,
        "prompt_id": prompt_id,
        "tier": "tier2",
        "event_ts": event_ts,
        "created_at": event_ts,
        "prompt_hash": str(raw_prompt_record.get("prompt_hash") or ""),
        "prompt_simhash": str(raw_prompt_record.get("prompt_simhash") or ""),
        "context_prompt_count": context_prompt_count,
        "session_turn_index": raw_prompt_record.get("message_count") or raw_prompt_record.get("session_turn_index") or 0,
        "provenance": str(raw_prompt_record.get("provenance") or "production_shadow"),
        "test_cohort": str(raw_prompt_record.get("test_cohort") or "unknown"),
        "test_scenario": str(raw_prompt_record.get("test_scenario") or ""),
        "scenario_family": str(raw_prompt_record.get("scenario_family") or ""),
        "predicted_label": predicted_label,
        "predicted_outcome": predicted_outcome,
        "recommended_action": recommended_action,
        "actual_action": actual_action,
        "block_or_pass": "block" if actual_action in {"blocked", "killed"} else "pass",
        "kill_triggered": kill_triggered,
        "would_have_killed": would_have_killed,
        "kill_eligible": kill_eligible,
        "kill_denied_reason": kill_denied_reason,
        "prompt_score": prompt_score,
        "session_score_before": session_score_before,
        "session_score_after": session_score_after,
        "confidence": confidence,
        "category": category,
        "model_id": SAGEMAKER_ENDPOINT,
        "model_version": model_version,
        "threshold_version": THRESHOLD_VERSION,
        "policy_version": policy_version,
        "threshold_used": threshold_used,
        "safe_intent_reason": safe_intent_reason,
        "expected_label": str(raw_prompt_record.get("expected_label") or "unknown"),
        "expected_outcome": str(raw_prompt_record.get("expected_outcome") or "unknown"),
        "ground_truth_source": str(raw_prompt_record.get("ground_truth_source") or "unknown"),
        "ground_truth_category": str(raw_prompt_record.get("ground_truth_category") or ""),
        "ground_truth_notes": str(raw_prompt_record.get("ground_truth_notes") or ""),
    })



# ---------------------------------------------------------------------------
# Logging and result persistence
# ---------------------------------------------------------------------------

def _log_prediction(
    scope_id: str,
    session_id: str,
    ml_label: str,
    ml_confidence: float,
    risk_score: float,
    final_session_risk: float,
    category: str,
    ml_verdict: str,
    action_taken: str,
    kill_triggered: bool,
    threshold_used: str,
) -> None:
    """Emit a structured log line for CloudWatch dashboards and alerting."""
    logger.info(
        "ML Tier2: scope=%s session=%s label=%s confidence=%.3f "
        "risk=%.2f final_session_risk=%.2f category=%s verdict=%s action=%s "
        "kill_triggered=%s threshold=%s kill_enabled=%s",
        scope_id, session_id, ml_label, ml_confidence,
        risk_score, final_session_risk, category, ml_verdict, action_taken,
        kill_triggered, threshold_used, ML_KILL_ENABLED,
    )


def _record_tier2_result(
    *,
    scope_id: str,
    session_timestamp: str,
    session_id: str,
    timestamp: str,
    ml_label: str,
    ml_confidence: float,
    risk_score: float,
    final_session_risk: float,
    session_score_before: float = 0.0,
    category: str = "unknown",
    ml_verdict: str = "safe",
    action_taken: str = "allow",
    attack_detected: bool = False,
    kill_eligible: bool = False,
    kill_triggered: bool = False,
    kill_denied_reason: str = "",
    threshold_used: str = "",
    threshold_version: str = "",
    reason: str = "",
    repeated_suspicious_count: int = 0,
    context_prompt_count: int = 0,
    timings: dict[str, int] | None = None,
    error: str = "",
    tier2_mode: str = "shadow",
    policy_version: int = 1,
    would_have_killed: bool = False,
    kill_eligibility_reason: str = "",
    required_evidence: str = "",
    evidence_seen: str = "",
    safe_intent_reason: str = "",
    score_components: dict[str, Any] | None = None,
) -> None:
    """Persist the Tier 2 ML result onto the prompt-history row for dashboards."""
    if not scope_id:
        logger.warning("Tier2 result not persisted because scope_id is empty")
        return

    key_session_timestamp = session_timestamp or (
        f"{session_id}#{timestamp}" if session_id and timestamp else ""
    )
    if not key_session_timestamp:
        logger.warning("Tier2 result not persisted because session_timestamp is empty")
        return

    status = "error" if error else ml_verdict
    confidence = Decimal(str(round(float(ml_confidence or 0.0), 6)))
    risk = Decimal(str(round(float(risk_score or 0.0), 2)))
    final_risk = Decimal(str(round(float(final_session_risk or 0.0), 2)))
    evaluated_at = int(time.time())
    timings = timings or {}
    score_components = score_components or {}
    table = _get_dynamodb().Table(PROMPT_HISTORY_TABLE)

    try:
        table.update_item(
            Key={
                "scope_id": scope_id,
                "session_timestamp": key_session_timestamp,
            },
            UpdateExpression=(
                "SET tier2_status = :status, "
                "tier2_label = :label, "
                "tier2_confidence = :confidence, "
                "tier2_suspicious = :suspicious, "
                "tier2_risk_score = :risk, "
                "tier2_cumulative_risk_score = :cumulative_risk, "
                "tier2_final_session_risk = :final_risk, "
                "tier2_risk_window = :risk_window, "
                "tier2_risk_reason = :risk_reason, "
                "tier2_prompt_score = :prompt_score, "
                "tier2_session_score_before = :session_score_before, "
                "tier2_session_score_after = :session_score_after, "
                "tier2_category = :category, "
                "tier2_ml_verdict = :ml_verdict, "
                "tier2_action_taken = :action_taken, "
                "tier2_recommended_action = :recommended_action, "
                "tier2_threshold_used = :threshold_used, "
                "tier2_threshold_version = :threshold_version, "
                "tier2_reason = :reason, "
                "tier2_repeated_suspicious_count = :repeated_count, "
                "tier2_attack_detected = :attack, "
                "tier2_kill_eligible = :kill_eligible, "
                "tier2_kill_triggered = :kill, "
                "tier2_kill_denied_reason = :kill_denied_reason, "
                "tier2_model_endpoint = :endpoint, "
                "tier2_context_window = :window, "
                "tier2_context_prompts = :context_count, "
                "tier2_mode = :tier2_mode, "
                "tier2_policy_version = :policy_version, "
                "tier2_would_have_killed = :would_have_killed, "
                "tier2_kill_eligibility_reason = :kill_eligibility_reason, "
                "tier2_required_evidence = :required_evidence, "
                "tier2_evidence_seen = :evidence_seen, "
                "tier2_safe_intent_reason = :safe_intent_reason, "
                "tier2_regex_score = :regex_score, "
                "tier2_ml_score = :ml_score, "
                "tier2_category_score = :category_score, "
                "tier2_behaviour_score = :behaviour_score, "
                "tier2_repetition_score = :repetition_score, "
                "tier2_context_escalation_score = :context_escalation_score, "
                "tier2_safe_intent_discount = :safe_intent_discount, "
                "tier2_evaluated_at = :evaluated_at, "
                "tier2_lambda_started_at = :tier2_lambda_started_at, "
                "prompt_history_written_at = :prompt_history_written_at, "
                "session_history_loaded_at = :session_history_loaded_at, "
                "sagemaker_invoke_started_at = :sagemaker_invoke_started_at, "
                "sagemaker_invoke_done_at = :sagemaker_invoke_done_at, "
                "session_risk_written_at = :session_risk_written_at, "
                "enforcement_invoked_at = :enforcement_invoked_at, "
                "tier2_error = :error"
            ),
            ExpressionAttributeValues={
                ":status": status,
                ":label": ml_label,
                ":confidence": confidence,
                ":suspicious": ml_verdict in {"suspicious", "high_risk", "malicious"},
                ":risk": risk,
                ":cumulative_risk": final_risk,
                ":final_risk": final_risk,
                ":prompt_score": risk,
                ":session_score_before": Decimal(str(round(float(session_score_before or 0.0), 2))),
                ":session_score_after": final_risk,
                ":risk_window": repeated_suspicious_count,
                ":risk_reason": reason,
                ":category": category,
                ":ml_verdict": ml_verdict,
                ":action_taken": action_taken,
                ":recommended_action": action_taken,
                ":threshold_used": threshold_used,
                ":threshold_version": threshold_version,
                ":reason": reason,
                ":repeated_count": repeated_suspicious_count,
                ":attack": attack_detected,
                ":kill_eligible": kill_eligible,
                ":kill": kill_triggered,
                ":kill_denied_reason": kill_denied_reason,
                ":endpoint": SAGEMAKER_ENDPOINT,
                ":window": SESSION_CONTEXT_WINDOW,
                ":context_count": context_prompt_count,
                ":tier2_mode": tier2_mode,
                ":policy_version": policy_version,
                ":would_have_killed": would_have_killed,
                ":kill_eligibility_reason": kill_eligibility_reason,
                ":required_evidence": required_evidence,
                ":evidence_seen": evidence_seen,
                ":safe_intent_reason": safe_intent_reason,
                ":regex_score": Decimal(str(round(float(score_components.get("regex_score", 0.0) or 0.0), 2))),
                ":ml_score": Decimal(str(round(float(score_components.get("ml_score", 0.0) or 0.0), 2))),
                ":category_score": Decimal(str(round(float(score_components.get("category_score", 0.0) or 0.0), 2))),
                ":behaviour_score": Decimal(str(round(float(score_components.get("behaviour_score", 0.0) or 0.0), 2))),
                ":repetition_score": Decimal(str(round(float(score_components.get("repetition_score", 0.0) or 0.0), 2))),
                ":context_escalation_score": Decimal(str(round(float(score_components.get("context_escalation_score", 0.0) or 0.0), 2))),
                ":safe_intent_discount": Decimal(str(round(float(score_components.get("safe_intent_discount", 0.0) or 0.0), 2))),
                ":evaluated_at": evaluated_at,
                ":tier2_lambda_started_at": int(timings.get("tier2_lambda_started_at", 0) or 0),
                ":prompt_history_written_at": int(timings.get("prompt_history_written_at", 0) or 0),
                ":session_history_loaded_at": int(timings.get("session_history_loaded_at", 0) or 0),
                ":sagemaker_invoke_started_at": int(timings.get("sagemaker_invoke_started_at", 0) or 0),
                ":sagemaker_invoke_done_at": int(timings.get("sagemaker_invoke_done_at", 0) or 0),
                ":session_risk_written_at": int(timings.get("session_risk_written_at", 0) or 0),
                ":enforcement_invoked_at": int(timings.get("enforcement_invoked_at", 0) or 0),
                ":error": error,
            },
        )
    except ClientError:
        logger.exception("Failed to persist Tier2 result for %s/%s", scope_id, session_id)



# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Per-record pipeline
#
# A Tier 2 record takes exactly one of three paths, and each path ends by
# recording a result and an outcome-ledger row:
#
#   1. _handle_layer1_blocked — Tier 1 already blocked this prompt. Stored for
#      audit and used to raise session risk, but no ML review (it would score a
#      prompt the user never got an answer to).
#   2. _handle_tier2_off      — tenant policy disables Tier 2. Logged only.
#   3. _handle_no_ml_endpoint — no SageMaker endpoint is configured. Logged only.
#      This is the DEFAULT self-hosted deployment: the function still runs, so
#      the prompt reaches PromptHistory (which Prompt History and Tier 3 read),
#      but there is nothing to classify with. Without this branch the record
#      would fall through to _handle_scored and die in _invoke_ml on an empty
#      EndpointName — turning the zero-config default into a DLQ of retries.
#   4. _handle_scored         — the full path: ML classification, deterministic
#      scoring, guarded kill eligibility, and enforcement.
#
# These were previously inlined in one very long function with five separate
# _record_tier2_result call sites at different nesting depths, which made it easy
# for a path to drift out of contract with the enforcement handler unnoticed.
# Splitting them keeps each path's full argument list visible in one screen and
# makes the dispatch loop auditable.
# ---------------------------------------------------------------------------


@dataclass
class _RecordContext:
    """Everything the three paths share, resolved once per record."""

    raw_prompt_record: dict[str, Any]
    item: dict[str, Any]
    prompt: str
    decision: str
    scope_id: str
    source: str
    session_id: str
    timestamp: str
    session_timestamp: str
    agent_runtime_arn: str
    runtime_session_id: str
    prompt_id: str
    tenant_policy: dict[str, Any]
    tier2_mode: str
    tier2_model_endpoint: str
    policy_version: int
    lambda_started_at: int
    prompt_history_written_at: int


class _RecordOutcome(NamedTuple):
    """Tally contribution for one record.

    ``killed`` is tracked separately from ``status`` because an enforced kill
    counts toward BOTH ``blocked`` and ``processed`` in the handler's return
    value — preserved from the original accounting.
    """

    status: str  # "processed" | "skipped" | "error"
    killed: bool = False


def _build_record_context(record: dict[str, Any], lambda_started_at: int) -> _RecordContext | None:
    """Parse one SQS record into a context, or None when it cannot be processed.

    Returns None (caller counts it as skipped) when the body is unreadable, the
    prompt-history write fails, or the record lacks a prompt/session id.
    """
    raw_prompt_record = _record_body(record)
    if not raw_prompt_record:
        return None
    raw_prompt_record["tier2_lambda_started_at"] = lambda_started_at

    item = _build_prompt_history_item(raw_prompt_record)
    if not _put_prompt_history(item):
        return None
    prompt_history_written_at = _now_ms()

    scope_id = str(item.get("scope_id") or "local")
    _mark_tenant_prompt_seen(scope_id)
    tenant_policy = _load_tenant_policy(scope_id)

    ctx = _RecordContext(
        raw_prompt_record=raw_prompt_record,
        item=item,
        prompt=str(item.get("prompt", "")),
        decision=str(item.get("decision", "")),
        scope_id=scope_id,
        source=str(item.get("source") or ""),
        session_id=str(item.get("session_id", "")),
        timestamp=str(item.get("timestamp", "")),
        session_timestamp=str(item.get("session_timestamp", "")),
        agent_runtime_arn=str(item.get("agent_runtime_arn", "")),
        runtime_session_id=str(item.get("runtime_session_id", "")),
        prompt_id=str(item.get("prompt_id", "")),
        tenant_policy=tenant_policy,
        tier2_mode=_normalize_mode(tenant_policy.get("tier2_mode"), "shadow"),
        tier2_model_endpoint=str(tenant_policy.get("tier2_model_endpoint") or SAGEMAKER_ENDPOINT),
        policy_version=_to_int(tenant_policy.get("policy_version"), 1),
        lambda_started_at=lambda_started_at,
        prompt_history_written_at=prompt_history_written_at,
    )
    if not ctx.prompt or not ctx.session_id:
        return None
    return ctx


def _handle_layer1_blocked(ctx: _RecordContext) -> _RecordOutcome:
    """Tier 1 already blocked this prompt; record it and raise session risk.

    ML review is skipped by policy: the prompt never reached the agent, so
    classifying it adds cost without changing the outcome. The session's risk is
    still raised so a sequence of Tier-1 blocks escalates.
    """
    layer1_score = _regex_component_score(ctx.item)
    previous_state = _get_previous_session_state(ctx.scope_id, ctx.session_id)
    session_score_before, session_score_after = _accumulate_session_score(
        previous_state,
        "malicious",
        layer1_score,
    )
    session_risk_written_at = _update_session_risk(
        scope_id=ctx.scope_id,
        source=ctx.source,
        session_id=ctx.session_id,
        runtime_session_id=ctx.runtime_session_id,
        agent_runtime_arn=ctx.agent_runtime_arn,
        category="layer1_block",
        confidence=1.0,
        ml_verdict="malicious",
        action_taken="raise_session_risk",
        final_session_risk=session_score_after,
        previous_session_risk=session_score_before,
        final_prompt_score=layer1_score,
        repeated_suspicious_count=1,
        kill_triggered=False,
        threshold_version=f"{THRESHOLD_VERSION}:policy{ctx.policy_version}",
        kill_eligible=False,
    )
    _write_detection_event(
        scope_id=ctx.scope_id,
        source=ctx.source,
        session_id=ctx.session_id,
        timestamp=ctx.timestamp,
        prompt_id=ctx.prompt_id,
        category="layer1_block",
        ml_verdict="malicious",
        action_taken="raise_session_risk",
        risk_score=layer1_score,
        final_session_risk=session_score_after,
        session_score_before=session_score_before,
        confidence=1.0,
        attack_detected=True,
        kill_eligible=False,
        kill_triggered=False,
        kill_denied_reason="layer1_already_blocked",
        reason="Layer 1 regex/signature blocked this prompt before Tier 2.",
        threshold_used="layer1_critical_block",
        context_prompt_count=1,
        policy_version=ctx.policy_version,
        mode=ctx.tier2_mode,
        event_type="layer1_block",
    )
    _record_tier2_result(
        scope_id=ctx.scope_id,
        session_timestamp=ctx.session_timestamp,
        session_id=ctx.session_id,
        timestamp=ctx.timestamp,
        ml_label="SKIPPED_LAYER1_BLOCK",
        ml_confidence=0.0,
        risk_score=layer1_score,
        final_session_risk=session_score_after,
        session_score_before=session_score_before,
        category="layer1_block",
        ml_verdict="malicious",
        action_taken="raise_session_risk",
        attack_detected=True,
        kill_eligible=False,
        kill_triggered=False,
        kill_denied_reason="layer1_already_blocked",
        threshold_used="layer1_critical_block",
        threshold_version=THRESHOLD_VERSION,
        reason="Layer 1 blocked this prompt; Tier 2 ML review was skipped by policy.",
        repeated_suspicious_count=1,
        context_prompt_count=1,
        timings={
            "tier2_lambda_started_at": ctx.lambda_started_at,
            "prompt_history_written_at": ctx.prompt_history_written_at,
            "session_risk_written_at": session_risk_written_at,
        },
        tier2_mode=ctx.tier2_mode,
        policy_version=ctx.policy_version,
        score_components={"regex_score": layer1_score},
    )
    _write_tier2_outcome(
        raw_prompt_record=ctx.raw_prompt_record,
        scope_id=ctx.scope_id,
        source=ctx.source,
        session_id=ctx.session_id,
        runtime_session_id=ctx.runtime_session_id,
        agent_runtime_arn=ctx.agent_runtime_arn,
        prompt_id=ctx.prompt_id,
        category="layer1_block",
        predicted_label="malicious",
        predicted_outcome="block",
        recommended_action="raise_session_risk",
        actual_action="blocked",
        kill_triggered=False,
        would_have_killed=False,
        kill_eligible=False,
        kill_denied_reason="layer1_already_blocked",
        prompt_score=layer1_score,
        session_score_before=session_score_before,
        session_score_after=session_score_after,
        confidence=1.0,
        model_version=ctx.tier2_model_endpoint,
        policy_version=ctx.policy_version,
        threshold_used="layer1_critical_block",
        context_prompt_count=1,
    )
    return _RecordOutcome("skipped")


def _handle_tier2_skipped(
    ctx: _RecordContext,
    *,
    category: str,
    verdict: str,
    threshold_used: str,
    reason: str,
    kill_denied_reason: str,
) -> _RecordOutcome:
    """Record a Tier 2 skip: no inference, no enforcement, full audit trail.

    Shared by the two non-scoring paths so they cannot drift apart in the shape
    they write. Only the labels differ, and they differ deliberately: an
    operator reading the outcome ledger must be able to tell "my policy turned
    this off" apart from "no model was ever configured", because the fix is
    different in each case. Both still write the result and ledger rows, so a
    skipped prompt is never invisible.
    """
    skipped_at = _now_ms()
    _record_tier2_result(
        scope_id=ctx.scope_id,
        session_timestamp=ctx.session_timestamp,
        session_id=ctx.session_id,
        timestamp=ctx.timestamp,
        ml_label="SKIPPED",
        ml_confidence=0.0,
        risk_score=0.0,
        final_session_risk=0.0,
        category=category,
        ml_verdict=verdict,
        action_taken="log_only",
        kill_triggered=False,
        threshold_used=threshold_used,
        threshold_version=THRESHOLD_VERSION,
        reason=reason,
        repeated_suspicious_count=0,
        context_prompt_count=0,
        timings={
            "tier2_lambda_started_at": ctx.lambda_started_at,
            "prompt_history_written_at": ctx.prompt_history_written_at,
            "session_history_loaded_at": 0,
            "sagemaker_invoke_started_at": 0,
            "sagemaker_invoke_done_at": 0,
            "session_risk_written_at": skipped_at,
            "enforcement_invoked_at": 0,
        },
        tier2_mode=ctx.tier2_mode,
        policy_version=ctx.policy_version,
    )
    _write_tier2_outcome(
        raw_prompt_record=ctx.raw_prompt_record,
        scope_id=ctx.scope_id,
        source=ctx.source,
        session_id=ctx.session_id,
        runtime_session_id=ctx.runtime_session_id,
        agent_runtime_arn=ctx.agent_runtime_arn,
        prompt_id=ctx.prompt_id,
        category=category,
        predicted_label=verdict,
        predicted_outcome="pass",
        recommended_action="log_only",
        actual_action="skipped",
        kill_triggered=False,
        would_have_killed=False,
        kill_eligible=False,
        kill_denied_reason=kill_denied_reason,
        prompt_score=0.0,
        session_score_before=0.0,
        session_score_after=0.0,
        confidence=0.0,
        model_version=ctx.tier2_model_endpoint or "none",
        policy_version=ctx.policy_version,
        threshold_used=threshold_used,
    )
    return _RecordOutcome("skipped")


def _handle_tier2_off(ctx: _RecordContext) -> _RecordOutcome:
    """Tenant policy has Tier 2 off: record the skip, run no inference."""
    return _handle_tier2_skipped(
        ctx,
        category="tier2_disabled",
        verdict="skipped_by_policy",
        threshold_used="tenant_tier2_off",
        reason="Tenant policy set Tier 2 mode to off.",
        kill_denied_reason="tenant_mode_not_enforce",
    )


def _handle_no_ml_endpoint(ctx: _RecordContext) -> _RecordOutcome:
    """No ML endpoint configured: record the prompt, run no inference.

    The default self-hosted deployment. Tier 1 still blocks inline and the
    prompt is already in PromptHistory by the time we get here (see
    _build_record_context), so Prompt History and Tier 3 both work — only the
    ML verdict is absent. Attach a Tier 2 endpoint to light this path up.

    Deliberately NOT an error: a missing optional component is a configuration
    state, and counting it as one would bury real failures in the error tally
    and retry every prompt to the dead-letter queue.
    """
    return _handle_tier2_skipped(
        ctx,
        category="tier2_no_endpoint",
        verdict="skipped_no_endpoint",
        threshold_used="no_ml_endpoint",
        reason="No Tier 2 ML endpoint is configured; prompt recorded without classification.",
        kill_denied_reason="no_ml_endpoint",
    )


def _handle_scored(ctx: _RecordContext) -> _RecordOutcome:
    """Full Tier 2 path: classify, score, evaluate kill eligibility, enforce.

    The kill decision is deliberately two-stage. ``eligibility`` answers "may we
    kill given this tenant's mode and the global guards?", while
    ``hypothetical_eligibility`` re-runs the same evaluation with every guard
    forced on to answer "would this have killed in enforce mode?". The second
    answer drives shadow-mode reporting (``would_have_killed``) so an operator
    can see what enforce mode WOULD have done before turning it on — that is the
    whole point of shadow being the default.
    """
    # Step 1: Pull recent session context for multi-turn detection
    session_history = _get_session_history(ctx.scope_id, ctx.session_id)
    session_history_loaded_at = _now_ms()
    ml_input = _build_ml_input(ctx.prompt, session_history)

    # Step 2: Score via SageMaker, then apply deterministic scoring on top. The
    # model's label alone never decides a kill; _score_prompt layers safe-intent
    # gating, behaviour patterns, repetition and escalation over it.
    sagemaker_invoke_started_at = _now_ms()
    ml_result = _invoke_ml(ml_input, ctx.tier2_model_endpoint)
    sagemaker_invoke_done_at = _now_ms()
    ml_result = _apply_tier2_safety_overrides(ctx.prompt, session_history, ml_result)
    category = _infer_category(str(ml_result["label"]), ml_input)
    ml_result["category"] = category
    score_result = _score_prompt(
        prompt=ctx.prompt,
        item=ctx.item,
        ml_result=ml_result,
        category=category,
        session_history=session_history,
    )
    risk_score = float(score_result["final_prompt_score"])
    risk_band_result = _risk_band(risk_score)
    previous_state = _get_previous_session_state(ctx.scope_id, ctx.session_id)
    session_score_before, final_session_risk = _accumulate_session_score(
        previous_state,
        risk_band_result["ml_verdict"],
        float(score_result.get("regex_score", 0.0) or 0.0),
    )
    repeated_suspicious_count = len([
        h
        for h in session_history
        if str(h.get("tier2_ml_verdict") or "").lower() in {"suspicious", "high_risk", "malicious"}
    ]) + (1 if risk_band_result["ml_verdict"] in {"suspicious", "high_risk", "malicious"} else 0)
    safe_intent_result = score_result["safe_intent"]
    global_guards = _global_guard_state()
    eligibility = evaluate_tier2_kill_eligibility(
        ctx.tenant_policy,
        ml_result,
        session_history,
        final_session_risk,
        safe_intent_result,
        global_guards,
        final_prompt_score=risk_score,
        session_score_after=final_session_risk,
    )
    # Hypothetical eligibility (would this have killed in enforce mode?). Every
    # guard is forced on so the answer reflects the evidence rules alone.
    hypothetical_policy = dict(ctx.tenant_policy)
    hypothetical_policy["tier2_mode"] = "enforce"
    policy_guards = dict(global_guards)
    policy_guards["global_kill_enabled"] = True
    policy_guards["tier2_kill_enabled"] = True
    policy_guards["enforcement_configured"] = True
    hypothetical_eligibility = evaluate_tier2_kill_eligibility(
        hypothetical_policy,
        ml_result,
        session_history,
        final_session_risk,
        safe_intent_result,
        policy_guards,
        final_prompt_score=risk_score,
        session_score_after=final_session_risk,
    )
    would_have_killed = bool(hypothetical_eligibility.get("eligible"))
    kill_eligible = bool(eligibility.get("eligible"))
    kill_denied_reason = "" if kill_eligible else str(eligibility.get("reason") or "")
    current_risk_decision = {
        "ml_verdict": risk_band_result["ml_verdict"],
        "action_taken": risk_band_result["action_taken"],
        "kill_triggered": False,
        "threshold_used": risk_band_result["threshold_used"],
        "reason": (
            f"Prompt score {risk_score:.1f}; session score moved "
            f"{session_score_before:.1f}->{final_session_risk:.1f}."
        ),
    }

    kill_triggered = False
    enforcement_invoked_at = 0

    # The score says kill but the guards say no: downgrade to raising session
    # risk. The prompt still flows; only the kill is withheld.
    if current_risk_decision["action_taken"] == "kill" and not kill_eligible:
        current_risk_decision = {
            **current_risk_decision,
            "action_taken": "raise_session_risk",
            "threshold_used": f"kill_denied:{eligibility.get('threshold_used', '')}",
            "reason": str(eligibility.get("human_reason") or eligibility.get("reason") or ""),
        }

    # Step 3: Only kill when tenant/global guards and evidence rules all pass.
    if current_risk_decision["action_taken"] == "kill" and kill_eligible:
        enforcement_invoked_at = _trigger_enforcement(
            scope_id=ctx.scope_id,
            session_id=ctx.session_id,
            runtime_session_id=ctx.runtime_session_id,
            gateway_session_id=str(ctx.raw_prompt_record.get("gateway_session_id") or ctx.session_id),
            app_session_id=str(ctx.raw_prompt_record.get("app_session_id") or ctx.session_id),
            agent_runtime_arn=ctx.agent_runtime_arn,
            ml_label=ml_result["label"],
            ml_confidence=ml_result["confidence"],
            cumulative_risk=final_session_risk,
            final_prompt_score=risk_score,
            policy_version=ctx.policy_version,
            threshold_used=str(eligibility.get("threshold_used") or current_risk_decision["threshold_used"]),
            reason=str(eligibility.get("human_reason") or eligibility.get("reason") or ""),
            model_version=ctx.tier2_model_endpoint,
        )
        if enforcement_invoked_at:
            kill_triggered = True
        else:
            # The enforcement invoke failed. Record that honestly rather than
            # reporting a kill that never happened.
            kill_denied_reason = "enforcement_invoke_failed"
            current_risk_decision = {
                **current_risk_decision,
                "action_taken": "raise_session_risk",
                "reason": "Enforcement invocation failed; session risk was still updated.",
            }

    session_risk_written_at = _update_session_risk(
        scope_id=ctx.scope_id,
        source=ctx.source,
        session_id=ctx.session_id,
        runtime_session_id=ctx.runtime_session_id,
        agent_runtime_arn=ctx.agent_runtime_arn,
        category=category,
        confidence=ml_result["confidence"],
        ml_verdict=current_risk_decision["ml_verdict"],
        action_taken=current_risk_decision["action_taken"],
        final_session_risk=final_session_risk,
        previous_session_risk=session_score_before,
        final_prompt_score=risk_score,
        repeated_suspicious_count=repeated_suspicious_count,
        kill_triggered=kill_triggered,
        threshold_version=f"{THRESHOLD_VERSION}:policy{ctx.policy_version}",
        kill_eligible=kill_eligible,
    )

    attack_detected = current_risk_decision["ml_verdict"] in {"watch", "suspicious", "high_risk", "malicious"}
    context_prompt_count = ml_input.count("[USER]")

    _write_detection_event(
        scope_id=ctx.scope_id,
        source=ctx.source,
        session_id=ctx.session_id,
        timestamp=ctx.timestamp,
        prompt_id=ctx.prompt_id,
        category=category,
        ml_verdict=current_risk_decision["ml_verdict"],
        action_taken=current_risk_decision["action_taken"],
        risk_score=risk_score,
        final_session_risk=final_session_risk,
        session_score_before=session_score_before,
        confidence=ml_result["confidence"],
        attack_detected=attack_detected,
        kill_eligible=kill_eligible,
        kill_triggered=kill_triggered,
        kill_denied_reason=kill_denied_reason,
        reason=current_risk_decision["reason"],
        threshold_used=current_risk_decision["threshold_used"],
        context_prompt_count=context_prompt_count,
        safe_intent_reason=str(safe_intent_result.get("reason") or ""),
        policy_version=ctx.policy_version,
        mode=ctx.tier2_mode,
        # Event type is ordered most-specific first: an actual kill, then a
        # shadow-mode "would have killed", then a safe-intent save, then a
        # denied kill, then the verdict band, then a plain detection.
        event_type=(
            "tier2_kill_allowed" if kill_triggered
            else "tier2_shadow_verdict" if ctx.tier2_mode == "shadow" and would_have_killed
            else "enforcement_skipped_safe_intent" if safe_intent_result.get("is_safe") and hypothetical_eligibility.get("eligible")
            else "tier2_kill_denied" if risk_band_result["ml_verdict"] == "malicious" and not kill_triggered
            else f"tier2_{current_risk_decision['ml_verdict']}" if attack_detected
            else "tier2_detection"
        ),
        would_have_killed=would_have_killed,
    )

    _record_tier2_result(
        scope_id=ctx.scope_id,
        session_timestamp=ctx.session_timestamp,
        session_id=ctx.session_id,
        timestamp=ctx.timestamp,
        ml_label=ml_result["label"],
        ml_confidence=ml_result["confidence"],
        risk_score=risk_score,
        final_session_risk=final_session_risk,
        session_score_before=session_score_before,
        category=category,
        ml_verdict=current_risk_decision["ml_verdict"],
        action_taken=current_risk_decision["action_taken"],
        attack_detected=attack_detected,
        kill_eligible=kill_eligible,
        kill_triggered=kill_triggered,
        kill_denied_reason=kill_denied_reason,
        threshold_used=current_risk_decision["threshold_used"],
        threshold_version=THRESHOLD_VERSION,
        reason=current_risk_decision["reason"],
        repeated_suspicious_count=repeated_suspicious_count,
        context_prompt_count=context_prompt_count,
        timings={
            "tier2_lambda_started_at": ctx.lambda_started_at,
            "prompt_history_written_at": ctx.prompt_history_written_at,
            "session_history_loaded_at": session_history_loaded_at,
            "sagemaker_invoke_started_at": sagemaker_invoke_started_at,
            "sagemaker_invoke_done_at": sagemaker_invoke_done_at,
            "session_risk_written_at": session_risk_written_at,
            "enforcement_invoked_at": enforcement_invoked_at,
        },
        tier2_mode=ctx.tier2_mode,
        policy_version=ctx.policy_version,
        would_have_killed=would_have_killed,
        kill_eligibility_reason=str(eligibility.get("reason") or hypothetical_eligibility.get("reason") or ""),
        required_evidence=str(eligibility.get("required_evidence") or ""),
        evidence_seen=str(eligibility.get("evidence_seen") or ""),
        safe_intent_reason=str(safe_intent_result.get("reason") or ""),
        score_components=score_result,
    )
    _write_tier2_outcome(
        raw_prompt_record=ctx.raw_prompt_record,
        scope_id=ctx.scope_id,
        source=ctx.source,
        session_id=ctx.session_id,
        runtime_session_id=ctx.runtime_session_id,
        agent_runtime_arn=ctx.agent_runtime_arn,
        prompt_id=ctx.prompt_id,
        category=category,
        predicted_label=current_risk_decision["ml_verdict"],
        predicted_outcome=(
            "kill" if kill_triggered else
            "would_kill" if would_have_killed and ctx.tier2_mode == "shadow" else
            "raise_risk" if current_risk_decision["action_taken"] == "raise_session_risk" else
            "pass"
        ),
        recommended_action=current_risk_decision["action_taken"],
        actual_action="killed" if kill_triggered else "not_enforced" if would_have_killed else "allowed",
        kill_triggered=kill_triggered,
        would_have_killed=would_have_killed,
        kill_eligible=kill_eligible,
        kill_denied_reason=kill_denied_reason,
        prompt_score=risk_score,
        session_score_before=session_score_before,
        session_score_after=final_session_risk,
        confidence=ml_result["confidence"],
        model_version=ctx.tier2_model_endpoint,
        policy_version=ctx.policy_version,
        threshold_used=current_risk_decision["threshold_used"],
        safe_intent_reason=str(safe_intent_result.get("reason") or ""),
        context_prompt_count=context_prompt_count,
    )

    _log_prediction(
        scope_id=ctx.scope_id,
        session_id=ctx.session_id,
        ml_label=ml_result["label"],
        ml_confidence=ml_result["confidence"],
        risk_score=risk_score,
        final_session_risk=final_session_risk,
        category=category,
        ml_verdict=current_risk_decision["ml_verdict"],
        action_taken=current_risk_decision["action_taken"],
        kill_triggered=kill_triggered,
        threshold_used=current_risk_decision["threshold_used"],
    )
    return _RecordOutcome("processed", killed=kill_triggered)


def _handle_record_error(record: dict[str, Any], exc: Exception) -> _RecordOutcome:
    """Record a Tier 2 failure so a dropped prompt is visible, not silent."""
    logger.exception("ML inference failed")
    report_degraded(ML_INFERENCE, f"tier 2 record failed: {type(exc).__name__}")
    try:
        failed_record = _build_prompt_history_item(_record_body(record) or {})
    except Exception:
        failed_record = {}
    _record_tier2_result(
        scope_id=str(failed_record.get("scope_id") or "local"),
        session_timestamp=str(failed_record.get("session_timestamp", "")),
        session_id=str(failed_record.get("session_id", "")),
        timestamp=str(failed_record.get("timestamp", "")),
        ml_label="ERROR",
        ml_confidence=0.0,
        risk_score=0.0,
        final_session_risk=0.0,
        category="error",
        ml_verdict="safe",
        action_taken="log_only",
        kill_triggered=False,
        threshold_used="error",
        threshold_version=THRESHOLD_VERSION,
        reason="Tier 2 inference failed before a verdict could be produced.",
        repeated_suspicious_count=0,
        context_prompt_count=0,
        timings={
            "tier2_lambda_started_at": int(failed_record.get("tier2_lambda_started_at", 0) or 0),
            "prompt_history_written_at": int(failed_record.get("prompt_history_written_at", 0) or 0),
        },
        error=str(exc)[:500],
    )
    return _RecordOutcome("error")


def _process_record(record: dict[str, Any]) -> _RecordOutcome:
    """Route one record down exactly one of the four Tier 2 paths."""
    ctx = _build_record_context(record, _now_ms())
    if ctx is None:
        return _RecordOutcome("skipped")
    if ctx.decision == "block" and not REVIEW_LAYER1_BLOCKED_PROMPTS:
        return _handle_layer1_blocked(ctx)
    if ctx.tier2_mode == "off":
        return _handle_tier2_off(ctx)
    # Checked AFTER the policy check: an operator who explicitly turned Tier 2
    # off should see that reason in the ledger, not "no endpoint".
    if not ctx.tier2_model_endpoint:
        return _handle_no_ml_endpoint(ctx)
    return _handle_scored(ctx)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda entry point: ingest prompts, classify with ML, and optionally kill sessions."""
    if _is_keep_alive_event(event):
        return _handle_keep_alive()

    records = event.get("Records", [])
    if not records:
        return {"processed": 0}

    tally = {"processed": 0, "blocked": 0, "skipped": 0, "errors": 0}
    for record in records:
        try:
            outcome = _process_record(record)
        except Exception as exc:
            outcome = _handle_record_error(record, exc)

        if outcome.status == "error":
            tally["errors"] += 1
        elif outcome.status == "skipped":
            tally["skipped"] += 1
        else:
            tally["processed"] += 1
        # An enforced kill counts toward BOTH blocked and processed.
        if outcome.killed:
            tally["blocked"] += 1

    return tally
