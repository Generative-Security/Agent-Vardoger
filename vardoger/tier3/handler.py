"""Tier 3 cross-session detection Lambda.

Triggered by EventBridge on a schedule. Tier 3 reads recent prompt history,
detects repeated/near-duplicate/category-burst attack waves across sessions,
writes grouped findings to DetectionEvents, and optionally invokes the existing
customer enforcement path when conservative kill rules are met.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, replace
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from vardoger import aws
from vardoger import policy as policy_module

# Shared coercion helpers under this module's existing names — see
# vardoger/coerce.py for why these no longer live per-handler.
from vardoger.coerce import to_float as _to_float
from vardoger.coerce import to_int as _to_int
from vardoger.coerce import to_str_tuple as _string_list
from vardoger.logging_setup import configure_logging
from vardoger.outcome_ledger import write_outcome
from vardoger.tier3.embedding import get_embedder
from vardoger.tier3.similarity import (
    cosine_similarity,
    hamming_distance,
    normalize_prompt,
    prompt_hash,
    simhash,
    stable_hash,
)

logger = logging.getLogger(__name__)
# Applies VARDOGER_LOG_LEVEL. Without this the runtime's own root level
# applies and every INFO line is dropped, leaving the log group empty.
configure_logging()

PROMPT_HISTORY_TABLE = os.environ.get("VARDOGER_PROMPT_HISTORY_TABLE", "VardogerPromptHistory")
SESSION_RISK_TABLE = os.environ.get("VARDOGER_SESSION_RISK_TABLE", "VardogerSessionRisk")
DETECTION_EVENTS_TABLE = os.environ.get("VARDOGER_DETECTION_EVENTS_TABLE", "VardogerDetectionEvents")
TENANTS_TABLE = os.environ.get("VARDOGER_TENANTS_TABLE", "VardogerTenants")
ENFORCEMENT_FUNCTION = os.environ.get("VARDOGER_ENFORCEMENT_FUNCTION", "")

TIER3_ENABLED = os.environ.get("TIER3_ENABLED", "true").lower() == "true"
# The template sets VARDOGER_GLOBAL_KILL_ENABLED (as Tier 2 reads it). Reading
# only the bare name meant this gate was never satisfiable: Tier 3
# enforcement stayed off no matter how the stack was configured. The
# unprefixed name is still accepted so an existing override keeps working.
GLOBAL_KILL_ENABLED = os.environ.get(
    "VARDOGER_GLOBAL_KILL_ENABLED",
    os.environ.get("GLOBAL_KILL_ENABLED", "false"),
).lower() == "true"
TIER3_KILL_ENABLED = os.environ.get("TIER3_KILL_ENABLED", "false").lower() == "true"
DEFAULT_TIER3_MODE = os.environ.get("DEFAULT_TIER3_MODE", "shadow").lower()
TIME_WINDOW_MINUTES = int(os.environ.get("TIER3_TIME_WINDOW_MINUTES", "5"))
MIN_SESSIONS = int(os.environ.get("TIER3_MIN_SESSIONS", "3"))
SIMHASH_DISTANCE_THRESHOLD = int(os.environ.get("TIER3_SIMHASH_DISTANCE_THRESHOLD", "3"))
CATEGORY_BURST_MIN_SESSIONS = int(os.environ.get("TIER3_CATEGORY_BURST_MIN_SESSIONS", "5"))
PATTERN_BURST_MIN_SESSIONS = int(os.environ.get("TIER3_PATTERN_BURST_MIN_SESSIONS", "3"))
SESSION_RISK_BURST_MIN_SESSIONS = int(os.environ.get("TIER3_SESSION_RISK_BURST_MIN_SESSIONS", "5"))
SESSION_RISK_BURST_THRESHOLD = float(os.environ.get("TIER3_SESSION_RISK_BURST_THRESHOLD", "65"))
EMBEDDING_SIMILARITY_THRESHOLD = float(os.environ.get("TIER3_EMBEDDING_SIMILARITY_THRESHOLD", "0.82"))
BURST_COOLDOWN_MINUTES = int(os.environ.get("TIER3_BURST_COOLDOWN_MINUTES", "30"))
MAX_PROMPTS_PER_RUN = int(os.environ.get("TIER3_MAX_PROMPTS_PER_RUN", "2000"))
# Reads the VARDOGER_-prefixed name, matching Tier 2 and every other var in
# the project. It previously read the bare "DETECTION_EVENT_RETENTION_DAYS",
# which nothing sets — so the value was unconfigurable in practice.
FINDING_RETENTION_DAYS = int(os.environ.get("VARDOGER_DETECTION_EVENT_RETENTION_DAYS", "90"))
MODEL_VERSION = os.environ.get("TIER3_MODEL_VERSION", "tier3-rules-v1-shadow")
DEFAULT_TENANT_POLICY = policy_module.defaults(
    tier3_mode=DEFAULT_TIER3_MODE,
    tier3_endpoint=MODEL_VERSION,
)

CRITICAL_CATEGORIES = {
    "system_prompt_extraction",
    "credential_theft",
    "customer_data_exfiltration",
    "data_exfiltration",
    "security_bypass",
    "account_takeover",
    "refund_fraud",
    "refund_manipulation",
    "high_value_order_abuse",
}

CRITICAL_SIGNATURE_HINTS = ("critical", "credential", "secret", "exfil", "sig-r-zd", "system_prompt")
RISKY_SESSION_STATUSES = {"watch", "suspicious", "high_risk", "terminated", "malicious"}

URL_RE = re.compile(r"https?://\S+|www\.\S+")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.IGNORECASE)
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
QUOTED_RE = re.compile(r"(['\"])(?:(?=(\\?))\2.)*?\1")

_dynamodb = None
_lambda_client = None


@dataclass(frozen=True)
class PromptRecord:
    """Minimal prompt record used by Tier 3 analysis."""

    scope_id: str
    source: str
    session_id: str
    prompt_id: str
    timestamp: str
    ingested_at: int
    prompt: str
    category: str
    risk_score: float
    final_session_risk: float
    repeated_suspicious_count: int
    matched_signatures: tuple[str, ...]
    agent_runtime_arn: str
    prompt_hash: str
    simhash_value: int
    runtime_session_id: str = ""
    gateway_session_id: str = ""
    app_session_id: str = ""


@dataclass(frozen=True)
class Finding:
    """A grouped Tier 3 finding before persistence."""

    scope_id: str
    burst_id: str
    category: str
    attack_style: str
    confidence: float
    similarity_score: float
    final_group_score: float
    affected_sessions: tuple[str, ...]
    affected_sources: tuple[str, ...]
    example_prompt_ids: tuple[str, ...]
    example_prompt_hashes: tuple[str, ...]
    similarity_method: str
    threshold_used: str
    action_taken: str
    kill_triggered: bool
    would_have_killed: bool
    kill_denied_reason: str
    policy_version: int
    mode: str
    model_version: str
    window_start: int
    session_cluster_key: str
    records: tuple[PromptRecord, ...]


def _get_dynamodb():
    """DynamoDB resource (async profile — Tier 3 runs on a schedule)."""
    return aws.resource("dynamodb")


def _get_lambda_client():
    """Lambda client (async profile), used to invoke the enforcement function."""
    return aws.client("lambda")


def _window_start(epoch: int, window_minutes: int = TIME_WINDOW_MINUTES) -> int:
    """Return the start epoch for the configured analysis window."""
    window_seconds = max(60, window_minutes * 60)
    return epoch - (epoch % window_seconds)


def _category(item: dict[str, Any]) -> str:
    """Return the strongest available category label for a prompt."""
    category = str(item.get("tier2_category") or item.get("category") or "").strip().lower()
    if category and category != "safe":
        return category
    signatures = _string_list(item.get("matched_signatures"))
    if any("credential" in sig or "secret" in sig for sig in signatures):
        return "credential_theft"
    if any("exfil" in sig for sig in signatures):
        return "customer_data_exfiltration"
    if any("jailbreak" in sig or "prompt" in sig for sig in signatures):
        return "system_prompt_extraction"
    return "unknown"


def _record_from_item(item: dict[str, Any]) -> PromptRecord | None:
    """Convert a prompt history item into a Tier 3 prompt record."""
    scope_id = str(item.get("scope_id") or "local")
    source = str(item.get("source") or "")
    session_id = str(item.get("session_id") or "")
    prompt = str(item.get("prompt") or "")
    if not scope_id or not session_id or not prompt:
        return None
    ingested_at = _to_int(item.get("ingested_at") or item.get("tier2_evaluated_at"))
    prompt_id = str(item.get("prompt_id") or item.get("request_id") or stable_hash([session_id, prompt])[:16])
    matched_signatures = _string_list(item.get("matched_signatures"))
    return PromptRecord(
        scope_id=scope_id,
        source=source,
        session_id=session_id,
        prompt_id=prompt_id,
        timestamp=str(item.get("timestamp") or ""),
        ingested_at=ingested_at,
        prompt=prompt,
        category=_category(item),
        risk_score=max(_to_float(item.get("risk_score")), _to_float(item.get("tier2_risk_score"))),
        final_session_risk=_to_float(item.get("tier2_final_session_risk") or item.get("tier2_cumulative_risk_score")),
        repeated_suspicious_count=_to_int(item.get("tier2_repeated_suspicious_count") or item.get("tier2_risk_window")),
        matched_signatures=matched_signatures,
        agent_runtime_arn=str(item.get("agent_runtime_arn") or ""),
        runtime_session_id=str(item.get("runtime_session_id") or session_id),
        gateway_session_id=str(item.get("gateway_session_id") or session_id),
        app_session_id=str(item.get("app_session_id") or session_id),
        prompt_hash=str(item.get("prompt_hash") or prompt_hash(prompt)),
        simhash_value=_to_int(item.get("prompt_simhash") or simhash(prompt)),
    )


def _scan_recent_prompts(cutoff: int, scope_id: str = "") -> list[PromptRecord]:
    """Read recent prompt history rows for one scope or all scopes."""
    table = _get_dynamodb().Table(PROMPT_HISTORY_TABLE)
    items: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {
        "Limit": min(MAX_PROMPTS_PER_RUN, 500),
        "FilterExpression": Attr("ingested_at").gte(cutoff),
    }
    if scope_id:
        kwargs["FilterExpression"] = kwargs["FilterExpression"] & Attr("scope_id").eq(scope_id)
    while len(items) < MAX_PROMPTS_PER_RUN:
        response = table.scan(**kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    records = [_record_from_item(item) for item in items[:MAX_PROMPTS_PER_RUN]]
    return [record for record in records if record is not None]


def _scan_session_risks(scope_id: str) -> dict[str, dict[str, Any]]:
    """Read current SessionRisk rows for one scope."""
    table = _get_dynamodb().Table(SESSION_RISK_TABLE)
    response = table.scan(FilterExpression=Attr("scope_id").eq(scope_id), Limit=1000)
    items = response.get("Items", [])
    while response.get("LastEvaluatedKey"):
        response = table.scan(
            FilterExpression=Attr("scope_id").eq(scope_id),
            ExclusiveStartKey=response["LastEvaluatedKey"],
            Limit=1000,
        )
        items.extend(response.get("Items", []))
    return {str(item.get("session_id", "")): item for item in items if item.get("session_id")}


def _load_scope_ids(event: dict[str, Any], records: list[PromptRecord]) -> list[str]:
    """Load scope IDs from event override, or default to the single self-hosted scope.

    Accepts either ``scope_id`` (new) or ``tenant_id`` (legacy) as the event
    override key. Self-hosted deployments have exactly one scope, ``"local"``,
    so when no override is provided we return ``["local"]``.
    """
    override = event.get("scope_id") or event.get("tenant_id")
    if override:
        return [str(override)]
    return ["local"]


def _normalize_mode(value: Any, default: str) -> str:
    """Return a supported tier mode (shared implementation)."""
    return policy_module.normalize_mode(value, default)


def _tenant_policy_from_item(item: dict[str, Any] | None) -> dict[str, Any]:
    """Build a policy dict from a stored scope record (shared implementation).

    Tier 2 and Tier 3 read the SAME record, so they must parse it identically.
    They previously did not — see vardoger/policy.py for the drift this fixes.
    """
    return policy_module.policy_from_item(
        item,
        tier3_mode=DEFAULT_TIER3_MODE,
        tier3_endpoint=MODEL_VERSION,
    )


def _load_tenant_policy(scope_id: str) -> dict[str, Any]:
    """Read a scope's policy, TTL-cached, falling back to safe defaults."""
    return policy_module.load(
        scope_id,
        TENANTS_TABLE,
        tier3_mode=DEFAULT_TIER3_MODE,
        tier3_endpoint=MODEL_VERSION,
    )

def _tenant_tier3_enabled(scope_id: str) -> bool:
    """Return whether Tier 3 is enabled for a scope."""
    return _load_tenant_policy(scope_id).get("tier3_mode") != "off"


def _is_critical(records: list[PromptRecord], category: str) -> bool:
    """Return True when a group is critical enough to qualify for enforcement."""
    if category in CRITICAL_CATEGORIES:
        return True
    return any(
        any(hint in signature.lower() for hint in CRITICAL_SIGNATURE_HINTS)
        for record in records
        for signature in record.matched_signatures
    )


def _prompt_matched_critical_signature(records: list[PromptRecord]) -> bool:
    """Return True when any prompt in a group had a critical/high-risk signature hint."""
    return any(
        any(hint in signature.lower() for hint in CRITICAL_SIGNATURE_HINTS)
        for record in records
        for signature in record.matched_signatures
    )


def _has_known_category(records: list[PromptRecord]) -> bool:
    """Return True when a group has a meaningful non-unknown category."""
    return any(record.category and record.category not in {"unknown", "safe", "allow"} for record in records)


def _has_risk_support(records: list[PromptRecord], session_risks: dict[str, dict[str, Any]], threshold: float = SESSION_RISK_BURST_THRESHOLD) -> bool:
    """Return True when prompt or session risk supports a Tier 3 grouping."""
    average_risk, max_risk, repeated = _risk_stats(records, session_risks)
    return max_risk >= threshold or average_risk >= threshold or repeated >= 2


def _has_session_status_support(records: list[PromptRecord], session_risks: dict[str, dict[str, Any]]) -> bool:
    """Return True when SessionRisk status supports a prompt-pattern finding."""
    for record in records:
        risk_item = session_risks.get(record.session_id, {})
        status = str(risk_item.get("status") or risk_item.get("last_verdict") or "").lower()
        if status in RISKY_SESSION_STATUSES:
            return True
    return False


def _has_pattern_support(records: list[PromptRecord], session_risks: dict[str, dict[str, Any]], category: str) -> bool:
    """Return True when a normalized pattern has enough support to alert."""
    return (
        (category and category != "unknown")
        or _has_known_category(records)
        or _prompt_matched_critical_signature(records)
        or _has_risk_support(records, session_risks)
        or _has_session_status_support(records, session_risks)
    )


def _confidence(method: str, records: list[PromptRecord], session_risks: dict[str, dict[str, Any]], category: str) -> float:
    """Estimate confidence by combining independent and supporting signals."""
    has_category = (category and category not in {"unknown", "safe", "allow"}) or _has_known_category(records)
    has_risk = _has_risk_support(records, session_risks) or _has_session_status_support(records, session_risks)
    critical = _is_critical(records, category)
    if method == "exact_hash":
        return 0.95 if critical else 0.70
    if method == "simhash":
        if has_category:
            return 0.90
        return 0.86 if has_risk else 0.78
    if method == "normalized_pattern_burst":
        return 0.90 if has_risk else 0.76
    if method == "category_burst":
        if has_risk:
            return 0.90
        return min(0.94, 0.70 + (len({r.session_id for r in records}) * 0.03))
    if method == "session_risk_burst":
        return 0.90 if has_category else 0.82
    if method == "embedding":
        return 0.93 if has_category and has_risk else 0.91
    return 0.70


def _risk_stats(records: list[PromptRecord], session_risks: dict[str, dict[str, Any]]) -> tuple[float, float, int]:
    """Return average risk, max risk, and max repeated suspicious count for a group."""
    scores: list[float] = []
    repeated = 0
    for record in records:
        risk_item = session_risks.get(record.session_id, {})
        risk = max(record.final_session_risk, _to_float(risk_item.get("current_risk_score")))
        scores.append(risk)
        repeated = max(repeated, record.repeated_suspicious_count, _to_int(risk_item.get("repeated_suspicious_count")))
    if not scores:
        return 0.0, 0.0, repeated
    return sum(scores) / len(scores), max(scores), repeated


def _group_score(
    method: str,
    records: list[PromptRecord],
    category: str,
    confidence: float,
    session_risks: dict[str, dict[str, Any]],
) -> float:
    """Calculate a grouped Tier 3 risk score without using it as a direct kill command."""
    average_risk, max_risk, repeated = _risk_stats(records, session_risks)
    affected_count = len({record.session_id for record in records})
    critical_count = sum(1 for record in records if _is_critical([record], category))
    generic_pattern_score = {
        "exact_hash": 30,
        "simhash": 25,
        "normalized_pattern_burst": 18,
        "category_burst": 20,
        "session_risk_burst": 15,
        "embedding": 28,
    }.get(method, 10)
    benign_pattern_penalty = 20 if category in {"unknown", "safe", "allow", "session_risk"} and method in {
        "normalized_pattern_burst",
        "session_risk_burst",
    } else 0
    score = (
        (confidence * 45)
        + min(25, affected_count * 5)
        + min(15, critical_count * 5)
        + min(15, max(average_risk, max_risk) / 8)
        + min(10, repeated * 3)
        + generic_pattern_score
        - benign_pattern_penalty
    )
    return round(max(0.0, min(100.0, score)), 2)


def _kill_decision(
    method: str,
    records: list[PromptRecord],
    category: str,
    confidence: float,
    session_risks: dict[str, dict[str, Any]],
) -> tuple[bool, str]:
    """Apply conservative Tier 3 kill rules, per detection method.

    Tier 3 correlates ACROSS sessions, so a kill here can terminate sessions
    belonging to users who did nothing individually suspicious — the blast
    radius is wider than Tier 1 or Tier 2. The rules are therefore tightest
    where the evidence is weakest:

    - ``exact_hash`` — byte-identical prompts repeated across
      ``MIN_SESSIONS`` sessions. The strongest signal available (coordinated
      replay), so it may kill at >=0.90 confidence, but still only when the
      category is critical or a critical signature matched.
    - ``simhash`` / near-duplicate — allows for small mutations, so it demands
      correspondingly more corroboration before killing.
    - ``normalized_pattern`` / ``session_risk`` bursts — the weakest evidence
      (shape similarity or coincident risk, not identical content). These alert
      but are heavily restricted from killing; see
      ``_apply_tenant_policy_to_finding``, which blocks generic-pattern kills
      outright.

    Returns ``(should_kill, reason_code)``; the reason code is persisted on the
    finding so a non-kill is auditable.
    """
    sessions = {record.session_id for record in records}
    average_risk, max_risk, repeated = _risk_stats(records, session_risks)
    critical = _is_critical(records, category)
    critical_signature = _prompt_matched_critical_signature(records)

    if method == "exact_hash":
        if len(sessions) >= MIN_SESSIONS and confidence >= 0.90 and (critical or critical_signature):
            return True, "tier3_exact_critical_repeat"
        return False, "tier3_exact_grouped_alert"
    if method == "simhash":
        if (
            len(sessions) >= MIN_SESSIONS
            and critical
            and confidence >= 0.90
            and (average_risk >= 80 or max_risk >= 90)
        ):
            return True, "tier3_simhash_critical_burst"
        return False, "tier3_simhash_grouped_alert"
    if method == "embedding":
        if (
            len(sessions) >= MIN_SESSIONS
            and critical
            and confidence >= 0.90
            and average_risk >= 80
            and repeated >= 2
        ):
            return True, "tier3_embedding_critical_cluster"
        return False, "tier3_embedding_grouped_alert"
    if method == "normalized_pattern_burst":
        if (
            len(sessions) >= MIN_SESSIONS
            and confidence >= 0.90
            and (critical or critical_signature or max_risk >= 90)
        ):
            return True, "tier3_pattern_supported_critical_burst"
        return False, "tier3_pattern_grouped_alert"
    if method == "session_risk_burst":
        # SessionRisk burst is intentionally alert-only because it can amplify
        # Tier 2 false positives across a tenant.
        return False, "tier3_session_risk_grouped_alert"
    return False, "tier3_category_grouped_alert"


def _canonical_cluster_key(method: str, records: list[PromptRecord], category: str) -> str:
    """Return a stable cluster key for deterministic burst IDs."""
    if method == "exact_hash":
        return records[0].prompt_hash
    if method == "category_burst":
        return category
    if method in {"normalized_pattern_burst", "session_risk_burst"}:
        return stable_hash([method, category, ",".join(sorted({record.session_id for record in records}))])[:24]
    sessions = ",".join(sorted({record.session_id for record in records}))
    prompt_hashes = ",".join(sorted({record.prompt_hash for record in records})[:5])
    return stable_hash([sessions, prompt_hashes])[:24]


def _make_finding(
    *,
    scope_id: str,
    method: str,
    category: str,
    records: list[PromptRecord],
    session_risks: dict[str, dict[str, Any]],
    now: int,
    attack_style: str,
) -> Finding:
    """Create a deterministic Tier 3 finding object."""
    unique_by_session: dict[str, PromptRecord] = {}
    for record in sorted(records, key=lambda row: row.ingested_at):
        unique_by_session.setdefault(record.session_id, record)
    selected = list(unique_by_session.values())
    confidence = _confidence(method, selected, session_risks, category)
    kill_allowed, threshold_used = _kill_decision(method, selected, category, confidence, session_risks)
    final_group_score = _group_score(method, selected, category, confidence, session_risks)
    action = "grouped_alert_only"
    window = _window_start(min(record.ingested_at or now for record in selected) or now)
    canonical = _canonical_cluster_key(method, selected, category)
    burst_id = stable_hash([scope_id, str(window), method, category, canonical])
    affected_sessions = tuple(sorted(unique_by_session))
    # A scope groups across all its sources, so a finding may span multiple
    # sources (cross-account detection). Capture the distinct sources involved.
    affected_sources = tuple(sorted({record.source for record in records if record.source}))
    return Finding(
        scope_id=scope_id,
        burst_id=burst_id,
        category=category,
        attack_style=attack_style,
        confidence=confidence,
        similarity_score=confidence,
        final_group_score=final_group_score,
        affected_sessions=affected_sessions,
        affected_sources=affected_sources,
        example_prompt_ids=tuple(record.prompt_id for record in selected[:10]),
        example_prompt_hashes=tuple(record.prompt_hash for record in selected[:10]),
        similarity_method=method,
        threshold_used=threshold_used,
        action_taken=action,
        kill_triggered=False,
        would_have_killed=kill_allowed,
        kill_denied_reason="" if kill_allowed else threshold_used,
        policy_version=1,
        mode="shadow",
        model_version=MODEL_VERSION,
        window_start=window,
        session_cluster_key=stable_hash(affected_sessions),
        records=tuple(selected),
    )


def _exact_hash_findings(scope_id: str, records: list[PromptRecord], risks: dict[str, dict[str, Any]], now: int) -> list[Finding]:
    """Find exact repeated prompts across distinct sessions."""
    groups: dict[str, list[PromptRecord]] = defaultdict(list)
    for record in records:
        groups[record.prompt_hash].append(record)
    findings = []
    for group in groups.values():
        if len({record.session_id for record in group}) >= MIN_SESSIONS:
            categories = [record.category for record in group if record.category and record.category != "unknown"]
            category = max(set(categories), key=categories.count) if categories else "unknown"
            findings.append(_make_finding(
                scope_id=scope_id,
                method="exact_hash",
                category=category,
                records=group,
                session_risks=risks,
                now=now,
                attack_style="Exact repeated prompt across sessions",
            ))
    return findings


def _simhash_findings(scope_id: str, records: list[PromptRecord], risks: dict[str, dict[str, Any]], now: int) -> list[Finding]:
    """Find lightly modified near-duplicate prompts across distinct sessions."""
    findings: list[Finding] = []
    used: set[str] = set()
    candidates = [record for record in records if record.prompt_hash not in used]
    for base in candidates:
        group = [base]
        for other in records:
            if base.prompt_id == other.prompt_id:
                continue
            if hamming_distance(base.simhash_value, other.simhash_value) <= SIMHASH_DISTANCE_THRESHOLD:
                group.append(other)
        sessions = {record.session_id for record in group}
        if len(sessions) >= MIN_SESSIONS:
            key = stable_hash(sorted(record.prompt_id for record in group))
            if key in used:
                continue
            used.add(key)
            categories = [record.category for record in group if record.category and record.category != "unknown"]
            category = max(set(categories), key=categories.count) if categories else "unknown"
            findings.append(_make_finding(
                scope_id=scope_id,
                method="simhash",
                category=category,
                records=group,
                session_risks=risks,
                now=now,
                attack_style="Near-duplicate prompt variants across sessions",
            ))
    return findings


def _prompt_structure(prompt: str) -> str:
    """Return a normalized structure key for repeated pattern burst detection."""
    text = normalize_prompt(prompt)
    text = URL_RE.sub("<url>", text)
    text = EMAIL_RE.sub("<email>", text)
    text = UUID_RE.sub("<id>", text)
    text = HASH_RE.sub("<hash>", text)
    text = QUOTED_RE.sub("<quote>", text)
    text = NUMBER_RE.sub("<num>", text)
    tokens = re.findall(r"[a-z0-9_<>']+", text)
    collapsed: list[str] = []
    for token in tokens:
        if len(token) >= 24 and any(char.isdigit() for char in token):
            collapsed.append("<id>")
        else:
            collapsed.append(token)
    return " ".join(collapsed)


def _normalized_pattern_findings(scope_id: str, records: list[PromptRecord], risks: dict[str, dict[str, Any]], now: int) -> list[Finding]:
    """Find repeated normalized prompt structures across distinct sessions."""
    groups: dict[str, list[PromptRecord]] = defaultdict(list)
    for record in records:
        structure = _prompt_structure(record.prompt)
        if not structure:
            continue
        groups[structure].append(record)
    findings: list[Finding] = []
    for group in groups.values():
        if len({record.session_id for record in group}) >= PATTERN_BURST_MIN_SESSIONS:
            categories = [record.category for record in group if record.category and record.category != "unknown"]
            category = max(set(categories), key=categories.count) if categories else "unknown"
            if not _has_pattern_support(group, risks, category):
                continue
            findings.append(_make_finding(
                scope_id=scope_id,
                method="normalized_pattern_burst",
                category=category,
                records=group,
                session_risks=risks,
                now=now,
                attack_style="Repeated prompt structure across sessions",
            ))
    return findings


def _category_burst_findings(scope_id: str, records: list[PromptRecord], risks: dict[str, dict[str, Any]], now: int) -> list[Finding]:
    """Find bursts of the same high-risk category across sessions."""
    groups: dict[str, list[PromptRecord]] = defaultdict(list)
    for record in records:
        if record.category in CRITICAL_CATEGORIES:
            groups[record.category].append(record)
    findings = []
    for category, group in groups.items():
        if len({record.session_id for record in group}) >= CATEGORY_BURST_MIN_SESSIONS:
            findings.append(_make_finding(
                scope_id=scope_id,
                method="category_burst",
                category=category,
                records=group,
                session_risks=risks,
                now=now,
                attack_style="High-risk category burst across sessions",
            ))
    return findings


def _session_risk_findings(scope_id: str, records: list[PromptRecord], risks: dict[str, dict[str, Any]], now: int) -> list[Finding]:
    """Find scope-wide bursts of rising session risk."""
    records_by_session: dict[str, PromptRecord] = {}
    for record in sorted(records, key=lambda row: row.ingested_at, reverse=True):
        records_by_session.setdefault(record.session_id, record)
    risky_records: list[PromptRecord] = []
    for session_id, risk_item in risks.items():
        record = records_by_session.get(session_id)
        if not record:
            continue
        status = str(risk_item.get("status") or risk_item.get("last_verdict") or "").lower()
        current_risk = max(_to_float(risk_item.get("current_risk_score")), record.final_session_risk)
        if status in RISKY_SESSION_STATUSES or current_risk >= SESSION_RISK_BURST_THRESHOLD:
            risky_records.append(record)
    if len({record.session_id for record in risky_records}) < SESSION_RISK_BURST_MIN_SESSIONS:
        return []

    categories = [record.category for record in risky_records if record.category and record.category != "unknown"]
    category = max(set(categories), key=categories.count) if categories else "session_risk"
    return [_make_finding(
        scope_id=scope_id,
        method="session_risk_burst",
        category=category,
        records=risky_records,
        session_risks=risks,
        now=now,
        attack_style="Rising session risk across tenant",
    )]


def _embedding_findings(scope_id: str, records: list[PromptRecord], risks: dict[str, dict[str, Any]], now: int) -> list[Finding]:
    """Find semantic clusters when embedding mode is explicitly enabled."""
    embedder = get_embedder()
    if getattr(embedder, "model_version", "disabled") == "disabled" or len(records) < MIN_SESSIONS:
        return []
    try:
        vectors = embedder.embed([record.prompt for record in records])
    except Exception:
        logger.exception("Tier3 embedding provider failed; falling back to non-model logic")
        return []
    if len(vectors) != len(records):
        return []
    findings: list[Finding] = []
    used: set[str] = set()
    for idx, base in enumerate(records):
        group = [base]
        for jdx, other in enumerate(records):
            if idx == jdx or base.category != other.category:
                continue
            if cosine_similarity(vectors[idx], vectors[jdx]) >= EMBEDDING_SIMILARITY_THRESHOLD:
                group.append(other)
        if len({record.session_id for record in group}) >= MIN_SESSIONS:
            key = stable_hash(sorted(record.prompt_id for record in group))
            if key in used:
                continue
            used.add(key)
            findings.append(_make_finding(
                scope_id=scope_id,
                method="embedding",
                category=base.category,
                records=group,
                session_risks=risks,
                now=now,
                attack_style="Semantic prompt cluster across sessions",
            ))
    return findings


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Prefer stronger methods when multiple findings cover the same sessions."""
    rank = {
        "exact_hash": 0,
        "simhash": 1,
        "normalized_pattern_burst": 2,
        "category_burst": 3,
        "session_risk_burst": 4,
        "embedding": 5,
    }
    selected: dict[tuple[str, tuple[str, ...]], Finding] = {}
    for finding in sorted(findings, key=lambda item: rank.get(item.similarity_method, 99)):
        key = (finding.scope_id, finding.affected_sessions)
        selected.setdefault(key, finding)
    return list(selected.values())


def _apply_tenant_policy_to_finding(finding: Finding, tenant_policy: dict[str, Any]) -> Finding:
    """Apply tenant mode and global kill guards to a Tier 3 finding.

    The final gate before Tier 3 may terminate sessions. Every condition must
    hold: enforce mode, enough distinct affected sessions
    (``tier3_min_sessions_for_kill``), confidence above
    ``tier3_kill_threshold``, similarity above ``tier3_similarity_threshold``,
    and a high composite group score.

    ``generic_pattern_only`` is the most important guard: a burst detected only
    by normalized-pattern or session-risk similarity, in an uncategorized
    bucket, is exactly what legitimate traffic looks like when many users ask
    the same ordinary question at once (a product launch, an outage). Those may
    alert but must never kill, regardless of how confident the clustering is.
    """
    mode = _normalize_mode(tenant_policy.get("tier3_mode"), "shadow")
    min_sessions = _to_int(tenant_policy.get("tier3_min_sessions_for_kill")) or 3
    # `x or default` discards a legitimately stored 0.0 -- which is how an
    # operator disables a threshold -- and silently restores the default. Tier 2
    # already uses the value-preserving form; this is the same record read two
    # ways, which vardoger/policy.py exists to prevent.
    similarity_threshold = _to_float(tenant_policy.get("tier3_similarity_threshold"), 0.90)
    kill_threshold = _to_float(tenant_policy.get("tier3_kill_threshold"), 0.95)
    sessions_ok = len(finding.affected_sessions) >= min_sessions
    confidence_ok = finding.confidence >= kill_threshold
    similarity_ok = finding.similarity_score >= similarity_threshold
    group_score_ok = finding.final_group_score >= 90
    generic_pattern_only = (
        finding.similarity_method in {"normalized_pattern_burst", "session_risk_burst"}
        and finding.category in {"unknown", "session_risk", "safe", "allow"}
    )
    method_eligible = finding.similarity_method in {"exact_hash", "simhash", "category_burst", "embedding"} or (
        finding.similarity_method == "normalized_pattern_burst" and finding.category in CRITICAL_CATEGORIES
    )
    eligible = (
        mode == "enforce"
        and GLOBAL_KILL_ENABLED
        and TIER3_KILL_ENABLED
        and bool(ENFORCEMENT_FUNCTION)
        and finding.would_have_killed
        and group_score_ok
        and sessions_ok
        and confidence_ok
        and similarity_ok
        and not generic_pattern_only
        and method_eligible
    )
    denied_reason = ""
    if not eligible and finding.would_have_killed:
        if mode != "enforce":
            denied_reason = "tenant_mode_not_enforce"
        elif not GLOBAL_KILL_ENABLED:
            denied_reason = "global_kill_disabled"
        elif not TIER3_KILL_ENABLED:
            denied_reason = "tier3_kill_disabled"
        elif not ENFORCEMENT_FUNCTION:
            denied_reason = "enforcement_not_configured"
        elif not group_score_ok:
            denied_reason = "group_score_below_threshold"
        elif not sessions_ok:
            denied_reason = "affected_sessions_below_threshold"
        elif not confidence_ok:
            denied_reason = "confidence_below_threshold"
        elif not similarity_ok:
            denied_reason = "similarity_below_threshold"
        elif generic_pattern_only:
            denied_reason = "generic_pattern_alert_only"
        elif not method_eligible:
            denied_reason = "method_not_enforcement_eligible"
        else:
            denied_reason = "tier3_kill_guard_not_met"
    return replace(
        finding,
        mode=mode,
        model_version=str(tenant_policy.get("tier3_model_endpoint") or finding.model_version),
        policy_version=_to_int(tenant_policy.get("policy_version")) or 1,
        kill_triggered=eligible,
        action_taken="kill" if eligible else "grouped_alert_only",
        kill_denied_reason=denied_reason or finding.kill_denied_reason,
    )


def analyze_tenant(scope_id: str, records: list[PromptRecord], risks: dict[str, dict[str, Any]], now: int | None = None) -> list[Finding]:
    """Analyze one scope's recent cross-session activity."""
    now = now or int(time.time())
    scope_records = [record for record in records if record.scope_id == scope_id]
    findings: list[Finding] = []
    findings.extend(_exact_hash_findings(scope_id, scope_records, risks, now))
    findings.extend(_simhash_findings(scope_id, scope_records, risks, now))
    findings.extend(_normalized_pattern_findings(scope_id, scope_records, risks, now))
    findings.extend(_category_burst_findings(scope_id, scope_records, risks, now))
    findings.extend(_session_risk_findings(scope_id, scope_records, risks, now))
    findings.extend(_embedding_findings(scope_id, scope_records, risks, now))
    return _dedupe_findings(findings)


def _cooldown_exists(finding: Finding, now: int) -> bool:
    """Return True when an equivalent Tier 3 burst was already alerted recently."""
    cutoff = now - BURST_COOLDOWN_MINUTES * 60
    table = _get_dynamodb().Table(DETECTION_EVENTS_TABLE)
    response = table.scan(
        FilterExpression=(
            Attr("provenance").eq("tier3")
            & Attr("scope_id").eq(finding.scope_id)
            & Attr("category").eq(finding.category)
            & Attr("session_cluster_key").eq(finding.session_cluster_key)
            & Attr("event_ts").gte(cutoff)
        ),
        Limit=10,
    )
    return bool(response.get("Items"))


def _write_finding(finding: Finding, now: int) -> bool:
    """Write one Tier 3 finding to DetectionEvents without raw prompt text."""
    if _cooldown_exists(finding, now):
        logger.info("Tier3 cooldown suppressed burst_id=%s", finding.burst_id)
        return False
    event_id = f"tier3#{finding.scope_id}#{finding.burst_id}"
    table = _get_dynamodb().Table(DETECTION_EVENTS_TABLE)
    try:
        table.put_item(
            Item={
                "event_id": event_id,
                "scope_id": finding.scope_id,
                "provenance": "tier3",
                "burst_id": finding.burst_id,
                "category": finding.category,
                "attack_style": finding.attack_style,
                "confidence": Decimal(str(round(finding.confidence, 6))),
                "finding_confidence": Decimal(str(round(finding.confidence, 6))),
                "similarity_score": Decimal(str(round(finding.similarity_score, 6))),
                "final_group_score": Decimal(str(round(finding.final_group_score, 2))),
                "affected_session_count": len(finding.affected_sessions),
                "affected_sessions": list(finding.affected_sessions),
                "affected_sources": list(finding.affected_sources),
                "example_prompt_ids": list(finding.example_prompt_ids),
                "example_prompt_hashes": list(finding.example_prompt_hashes),
                "similarity_method": finding.similarity_method,
                "threshold_used": finding.threshold_used,
                "action_taken": finding.action_taken,
                "kill_triggered": finding.kill_triggered,
                "would_have_killed": finding.would_have_killed,
                "kill_denied_reason": finding.kill_denied_reason,
                "policy_version": finding.policy_version,
                "mode": finding.mode,
                "model_version": finding.model_version,
                "created_at": now,
                "event_ts": now,
                "event_type": "tier3_kill" if finding.kill_triggered else "tier3_grouped_finding",
                "decision": "grouped_kill_triggered" if finding.kill_triggered else (
                    "grouped_malicious" if finding.final_group_score >= 85 else
                    "grouped_high_risk" if finding.final_group_score >= 65 else
                    "grouped_watch"
                ),
                "risk_score": Decimal(str(round(finding.final_group_score, 2))),
                "matched_signatures": [f"tier3-{finding.similarity_method}"],
                "matched_policy_rules": ["tier3_cross_session_detection"],
                "attack_intents": [f"tier3:{finding.category}"],
                "session_id": finding.affected_sessions[0] if finding.affected_sessions else "",
                "session_cluster_key": finding.session_cluster_key,
                "window_start": finding.window_start,
                "ttl": now + FINDING_RETENTION_DAYS * 24 * 3600,
            },
            ConditionExpression="attribute_not_exists(event_id)",
        )
        _write_tier3_outcome(finding, now)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def _write_tier3_outcome(finding: Finding, now: int) -> None:
    """Write a grouped Tier 3 outcome row without raw prompt examples."""
    write_outcome({
        "scope_id": finding.scope_id,
        "affected_sources": list(finding.affected_sources),
        "run_id": os.environ.get("TIER3_TEST_RUN_ID", "production"),
        "session_id": finding.session_cluster_key,
        "prompt_id": finding.burst_id,
        "tier": "tier3",
        "event_ts": now,
        "prompt_hash": ",".join(finding.example_prompt_hashes[:5]),
        "context_prompt_count": len(finding.records),
        "provenance": "production_shadow" if finding.mode == "shadow" else "production_enforce",
        "test_cohort": "tier3_burst",
        "test_scenario": finding.attack_style,
        "scenario_family": finding.similarity_method,
        "predicted_label": "grouped_malicious" if finding.final_group_score >= 85 else "grouped_high_risk" if finding.final_group_score >= 65 else "grouped_watch",
        "predicted_outcome": "kill" if finding.kill_triggered else "would_kill" if finding.would_have_killed else "grouped_alert",
        "recommended_action": finding.action_taken,
        "actual_action": "killed" if finding.kill_triggered else "not_enforced",
        "block_or_pass": "block" if finding.kill_triggered else "pass",
        "kill_triggered": finding.kill_triggered,
        "would_have_killed": finding.would_have_killed,
        "kill_eligible": finding.kill_triggered or finding.would_have_killed,
        "kill_denied_reason": finding.kill_denied_reason,
        "final_group_score": finding.final_group_score,
        "finding_confidence": finding.confidence,
        "similarity_score": finding.similarity_score,
        "category": finding.category,
        "attack_style": finding.attack_style,
        "model_id": "tier3-rules",
        "model_version": finding.model_version,
        "threshold_version": finding.threshold_used,
        "policy_version": finding.policy_version,
        "threshold_used": finding.threshold_used,
        "expected_label": "unknown",
        "expected_outcome": "unknown",
        "ground_truth_source": "unknown",
    })


def _invoke_enforcement(finding: Finding) -> int:
    """Invoke existing customer enforcement once per affected session."""
    if not ENFORCEMENT_FUNCTION or not finding.kill_triggered:
        return 0
    invoked = 0
    by_session = {record.session_id: record for record in finding.records}
    for session_id in finding.affected_sessions:
        record = by_session.get(session_id)
        if not record:
            continue
        payload = {
            "action": "terminate",
            "scope_id": finding.scope_id,
            "source": record.source,
            "session_id": session_id,
            "gateway_session_id": record.gateway_session_id,
            "runtime_session_id": record.runtime_session_id,
            "app_session_id": record.app_session_id,
            "agent_runtime_arn": record.agent_runtime_arn,
            "matched_signature_ids": [f"tier3-{finding.similarity_method}", finding.threshold_used],
            "risk_score": 12,
            "attack_intents": [f"tier3:{finding.category}", finding.attack_style],
            "matched_policy_rules": ["tier3_cross_session_detection"],
            "risk_bucket": "high",
            "detection_source": "tier3",
            "provenance": "tier3",
            "policy_version": finding.policy_version,
            "model_version": finding.model_version,
            "confidence": finding.confidence,
            "threshold_used": finding.threshold_used,
            "reason": finding.kill_denied_reason or finding.attack_style,
            "tier3_burst_id": finding.burst_id,
        }
        try:
            _get_lambda_client().invoke(
                FunctionName=ENFORCEMENT_FUNCTION,
                InvocationType="Event",
                Payload=json.dumps(payload),
            )
            invoked += 1
        except ClientError:
            logger.exception("Tier3 failed to invoke enforcement for session=%s", session_id)
    return invoked


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Run scheduled Tier 3 cross-session detection."""
    if not TIER3_ENABLED:
        return {"enabled": False, "findings": 0}
    now = int(time.time())
    window_minutes = int(event.get("time_window_minutes") or TIME_WINDOW_MINUTES)
    cutoff = now - window_minutes * 60
    initial_records = _scan_recent_prompts(cutoff, str(event.get("scope_id") or event.get("tenant_id") or ""))
    scope_ids = _load_scope_ids(event, initial_records)
    findings_written = 0
    findings_seen = 0
    enforcement_invocations = 0
    scopes_skipped_by_policy = 0

    for scope_id in scope_ids:
        tenant_policy = _load_tenant_policy(scope_id)
        if _normalize_mode(tenant_policy.get("tier3_mode"), "shadow") == "off":
            scopes_skipped_by_policy += 1
            continue
        records = [record for record in initial_records if record.scope_id == scope_id]
        if len({record.session_id for record in records}) < MIN_SESSIONS:
            continue
        risks = _scan_session_risks(scope_id)
        findings = analyze_tenant(scope_id, records, risks, now)
        for finding in findings:
            finding = _apply_tenant_policy_to_finding(finding, tenant_policy)
            findings_seen += 1
            if _write_finding(finding, now):
                findings_written += 1
                enforcement_invocations += _invoke_enforcement(finding)

    return {
        "enabled": True,
        "scopes": len(scope_ids),
        "prompts_scanned": len(initial_records),
        "findings_seen": findings_seen,
        "findings_written": findings_written,
        "enforcement_invocations": enforcement_invocations,
        "scopes_skipped_by_policy": scopes_skipped_by_policy,
        "kill_enabled": TIER3_KILL_ENABLED,
    }
