"""Control plane configuration loaded from environment variables."""
from __future__ import annotations

import os

AWS_REGION: str = os.environ.get("AWS_REGION", "us-east-1")
PROMPT_HISTORY_TABLE: str = os.environ.get("VARDOGER_PROMPT_HISTORY_TABLE", "VardogerPromptHistory")
SESSION_RISK_TABLE: str = os.environ.get("VARDOGER_SESSION_RISK_TABLE", "VardogerSessionRisk")
DETECTION_EVENTS_TABLE: str = os.environ.get("VARDOGER_DETECTION_EVENTS_TABLE", "VardogerDetectionEvents")
SESSION_TABLE: str = os.environ.get("VARDOGER_SESSION_TABLE", "VardogerSessionRegistry")
# TENANTS_TABLE keeps its existing (env-var-backed) name, but every record in it
# is keyed by scope_id — the self-hosted default scope is always "local".
TENANTS_TABLE: str = os.environ.get("VARDOGER_TENANTS_TABLE", "VardogerTenants")
OUTCOME_TABLE: str = os.environ.get("VARDOGER_OUTCOME_TABLE", "VardogerOutcomeLedger")
CORS_ALLOW_ORIGINS: str = os.environ.get("VARDOGER_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")

# Auth mode. Allowed values:
#   "none"                     -> local dev, no auth, caller treated as admin
#   "cognito"                  -> API Gateway Cognito authorizer verifies the JWT;
#                                 we read claims (role) from the request
#   "cognito+identity-center"  -> same as cognito, plus AWS Identity Center groups
AUTH_MODE: str = os.environ.get("VARDOGER_AUTH_MODE", "none")
AUTH_SECRET: str = os.environ.get("VARDOGER_AUTH_SECRET", "")

# Cognito settings — all from env with empty defaults. Never hardcode pool ids.
COGNITO_USER_POOL_ID: str = os.environ.get("VARDOGER_COGNITO_USER_POOL_ID", "")
COGNITO_APP_CLIENT_ID: str = os.environ.get("VARDOGER_COGNITO_APP_CLIENT_ID", "")
COGNITO_REGION: str = os.environ.get("VARDOGER_COGNITO_REGION", "") or AWS_REGION

DEPLOYMENT_MODE: str = os.environ.get("VARDOGER_DEPLOYMENT_MODE", "self-hosted")  # self-hosted | managed

# The isolation/partition key for this deployment. Self-hosted is always "local".
DEFAULT_SCOPE_ID: str = os.environ.get("VARDOGER_SCOPE_ID", "local").strip() or "local"


def scope_id() -> str:
    """Return the isolation scope for this deployment (self-hosted: "local")."""
    return DEFAULT_SCOPE_ID


# Allowed auth modes (used for validation / documentation).
ALLOWED_AUTH_MODES = ("none", "token", "cognito", "cognito+identity-center")


def auth_enabled() -> bool:
    """Return True when auth is enforced (any mode other than "none")."""
    return AUTH_MODE.strip().lower() not in ("", "none")


def uses_function_url() -> bool:
    """Return True when the control plane is fronted by a Lambda Function URL.

    The "none" and "token" modes serve the API over a Lambda Function URL, whose
    own CORS config (infra/self-hosted.yaml, ControlPlaneUrl.Cors) sets the
    CORS response headers. The "cognito" modes sit behind API Gateway, which
    does NOT add CORS, so the app must. See main.py for why this gates the
    CORSMiddleware.
    """
    return AUTH_MODE.strip().lower() in ("", "none", "token")
