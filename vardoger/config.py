"""Runtime configuration loaded from environment variables.

No hardcoded account IDs, secrets, or deployment-specific values.
All values have safe defaults for local development.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def _get(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _get_int(name: str, default: int) -> int:
    """Parse an int env var, falling back to the default on a bad value.

    A typo'd numeric env var must not crash every cold start; log and use the
    default instead.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid int for %s=%r; using default %s", name, raw, default)
        return default


def _get_float(name: str, default: float) -> float:
    """Parse a float env var, falling back to the default on a bad value."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid float for %s=%r; using default %s", name, raw, default)
        return default


# --- Platform identity (set at deploy time) ---
# The dispatcher serves exactly one AWS account + agent, so its source is fixed
# at deploy time. Tenant identity from the payload is never trusted.
AGENT_RUNTIME_ARN: str = _get("VARDOGER_AGENT_RUNTIME_ARN")
# Optional friendly agent alias used in the source key when set; otherwise the
# agent runtime ARN's last segment is used.
AGENT_ALIAS: str = _get("VARDOGER_AGENT_ALIAS")
# Isolation scope. Always "local" in self-hosted; managed injects a tenant id.
SCOPE_ID: str = _get("VARDOGER_SCOPE_ID", "local")

# --- Detection ---
SCANNER_REINIT_SECONDS: float = _get_float("VARDOGER_SCANNER_REINIT_SECONDS", 300.0)
SIGNATURE_MIN_PATTERNS: int = _get_int("VARDOGER_SIGNATURE_MIN_PATTERNS", 20)

# --- Session management ---
SESSION_TABLE_NAME: str = _get("VARDOGER_SESSION_TABLE", "VardogerSessionRegistry")
# Scope-config table (a.k.a. "tenants"): holds per-scope policy and
# operator-authored custom signatures. Kept the VARDOGER_TENANTS_TABLE env var
# name for compatibility with the control plane and tier handlers.
SCOPE_CONFIG_TABLE: str = _get("VARDOGER_TENANTS_TABLE", "VardogerTenants")
DETECTION_EVENTS_TABLE_NAME: str = _get("VARDOGER_DETECTION_EVENTS_TABLE", "VardogerDetectionEvents")
SESSION_TTL_MINUTES: int = _get_int("VARDOGER_SESSION_TTL_MINUTES", 30)
DETECTION_RETENTION_DAYS: int = _get_int("VARDOGER_DETECTION_RETENTION_DAYS", 90)

# --- Telemetry export ---
PROMPT_TELEMETRY_MODE: str = _get("VARDOGER_TELEMETRY_MODE", "local")  # local | managed | disabled
MANAGED_INTAKE_URL: str = _get("VARDOGER_MANAGED_INTAKE_URL")
# In "local" mode the dispatcher forwards prompts to a same-account SQS queue
# that fronts Tier 2 (and, downstream, PromptHistory). Without this, Tier 2/3
# and the Prompt History page never receive any data.
PROMPT_INTAKE_QUEUE_URL: str = _get("VARDOGER_PROMPT_INTAKE_QUEUE_URL")
TRANSPORT_FAILURE_POLICY: str = _get("VARDOGER_TRANSPORT_FAILURE_POLICY", "allow_and_mark_degraded")

# --- Enforcement ---
ENFORCEMENT_MODE: str = _get("VARDOGER_ENFORCEMENT_MODE", "inline")  # inline | async | disabled

# How Tier 1 responds to its own detection.
#
#   sidecar (default) — the prompt is passed through to the agent and the
#       SESSION is terminated. The agent may answer this one prompt; it will not
#       answer another. Chosen because a security sidecar should not be able to
#       take the agent down: a false positive costs one dead session, not a
#       refused request, and every tier converges on the same lever (kill the
#       session) rather than Tier 1 alone owning a second one (refuse the call).
#   gate            — the prompt is refused with HTTP 403 AND the session is
#       terminated. Strictest: a detected prompt never reaches the agent. Use
#       when a single successful malicious prompt is itself unacceptable —
#       one-shot exfiltration ("print every customer record") is answered before
#       the kill lands in sidecar mode.
#
# Both modes kill the session. The only difference is whether the triggering
# prompt is answered. Anything unrecognized falls back to the strict mode.
TIER1_MODE: str = _get("VARDOGER_TIER1_MODE", "sidecar").strip().lower()
if TIER1_MODE not in ("sidecar", "gate"):
    logger.warning("Invalid VARDOGER_TIER1_MODE=%r; using 'gate'", TIER1_MODE)
    TIER1_MODE = "gate"

# What to do when detection cannot run at all — the engine raised, or a
# dependency it needs is unavailable.
#
#   fail_open (default) — pass the prompt through, emit a degraded metric, and
#       alert. A monitoring component that is broken should not also break the
#       thing it monitors.
#   fail_closed         — refuse the prompt. Choose this when unmonitored
#       traffic is worse than no traffic.
#
# This governs FAILURE only. It does not apply to an oversized or unparseable
# body, or to a request with no source identity: those are attack-shaped inputs
# rather than infrastructure faults, and they are always refused.
DETECTION_FAILURE_POLICY: str = _get("VARDOGER_DETECTION_FAILURE_POLICY", "fail_open").strip().lower()
if DETECTION_FAILURE_POLICY not in ("fail_open", "fail_closed"):
    logger.warning(
        "Invalid VARDOGER_DETECTION_FAILURE_POLICY=%r; using 'fail_closed'", DETECTION_FAILURE_POLICY
    )
    DETECTION_FAILURE_POLICY = "fail_closed"

# --- Alerting ---
SNS_TOPIC_ARN: str = _get("VARDOGER_SNS_TOPIC_ARN")
ALERT_QUEUE_URL: str = _get("VARDOGER_ALERT_QUEUE_URL")

# --- Premium signatures (AWS Marketplace cross-account S3) ---
# Cross-account bucket holding the latest premium signatures. Empty unless the
# customer has subscribed via AWS Marketplace and been granted read access.
PREMIUM_SIGNATURE_BUCKET: str = _get("VARDOGER_PREMIUM_SIGNATURE_BUCKET")
PREMIUM_SIGNATURE_PREFIX: str = _get("VARDOGER_PREMIUM_SIGNATURE_PREFIX", "premium/")
# Optional cross-account role to assume before reading the bucket. When empty,
# the default credentials are used (bucket policy grants cross-account access).
PREMIUM_SIGNATURE_ROLE_ARN: str = _get("VARDOGER_PREMIUM_SIGNATURE_ROLE_ARN")

# --- ML (Tier 2, optional) ---
ML_ENDPOINT: str = _get("VARDOGER_ML_ENDPOINT")
ML_CONFIDENCE_THRESHOLD: float = _get_float("VARDOGER_ML_CONFIDENCE_THRESHOLD", 0.85)
ML_KILL_ENABLED: bool = _get("VARDOGER_ML_KILL_ENABLED", "false").lower() == "true"
GLOBAL_KILL_ENABLED: bool = _get("VARDOGER_GLOBAL_KILL_ENABLED", "false").lower() == "true"

# --- Encryption ---
KMS_KEY_ID: str = _get("VARDOGER_KMS_KEY_ID")
EVIDENCE_S3_BUCKET: str = _get("VARDOGER_EVIDENCE_S3_BUCKET")

# --- Logging ---
LOG_LEVEL: str = _get("VARDOGER_LOG_LEVEL", "INFO")
AWS_REGION: str = _get("AWS_REGION", _get("AWS_DEFAULT_REGION", "us-east-1"))
