"""Role-based access control (RBAC) for the control plane.

Three roles with ascending privilege:

    viewer   < operator < admin

- viewer:   read-only (monitoring dashboards, listings, policy/signature reads)
- operator: viewer + triage / acknowledge actions
- admin:    everything, including enforcement policy writes, custom signatures,
            threat-feed subscription, and managed-upgrade intent

Auth modes (VARDOGER_AUTH_MODE):

- "none": DEV ONLY. No auth. The caller is treated as ``admin``. Never use on
  the public internet.
- "token": single-operator self-host. Every request must present
  ``Authorization: Bearer <VARDOGER_AUTH_SECRET>`` (constant-time compared). A
  valid secret maps to ``admin``; an empty configured secret fails closed (500).
- "cognito" / "cognito+identity-center": the JWT is verified upstream by the API
  Gateway authorizer. We READ the role ONLY from the verified ``cognito:groups``
  claim (group names viewer/operator/admin). We do NOT decode the bearer token
  ourselves and do NOT honor a user-writable ``role`` / ``custom:role`` claim —
  either would allow self-escalation. When auth is enabled and no role can be
  resolved, we FAIL CLOSED with 403.
"""
from __future__ import annotations

import hmac
import logging
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from control_plane import config

logger = logging.getLogger(__name__)

# Ascending privilege. Higher number => more privilege.
ROLE_RANK: dict[str, int] = {"viewer": 1, "operator": 2, "admin": 3}
VALID_ROLES = tuple(ROLE_RANK.keys())


class Principal:
    """The authenticated caller and their resolved role."""

    def __init__(self, role: str, subject: str = "", claims: dict | None = None) -> None:
        self.role = role
        self.subject = subject
        self.claims = claims or {}

    def has_at_least(self, minimum: str) -> bool:
        return ROLE_RANK.get(self.role, 0) >= ROLE_RANK.get(minimum, 99)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Principal(role={self.role!r}, subject={self.subject!r})"


def _claims_from_request(request: Request) -> dict:
    """Extract already-verified JWT claims from the request (cognito modes).

    API Gateway (Cognito authorizer / HTTP API JWT authorizer) forwards claims
    in the Lambda event under requestContext.authorizer. Mangum surfaces that on
    ``request.scope["aws.event"]``.

    There is deliberately NO fallback to self-decoding the bearer token: the
    signature is verified upstream by the API Gateway authorizer, and reading a
    role from an unverified token would let a caller forge
    ``{"cognito:groups":["admin"]}``. If the authorizer claims are absent, we
    return nothing and the caller fails closed with 403.
    """
    event = request.scope.get("aws.event") if isinstance(request.scope, dict) else None
    if isinstance(event, dict):
        authorizer = (
            event.get("requestContext", {})
            .get("authorizer", {})
        )
        if isinstance(authorizer, dict):
            # REST API Cognito authorizer: claims nested under "claims".
            claims = authorizer.get("claims")
            if isinstance(claims, dict) and claims:
                return claims
            # HTTP API JWT authorizer: claims under jwt.claims.
            jwt_block = authorizer.get("jwt")
            if isinstance(jwt_block, dict) and isinstance(jwt_block.get("claims"), dict):
                return jwt_block["claims"]
    return {}


def _role_from_claims(claims: dict) -> str:
    """Map Cognito claims to one of viewer/operator/admin.

    Role is taken ONLY from the ``cognito:groups`` claim. The ``role`` /
    ``custom:role`` claim path is intentionally NOT honored: a Cognito custom
    attribute is user-writable, so trusting it would let a user self-escalate.
    Unknown groups are ignored; the highest matching group wins.
    """
    resolved: list[str] = []

    groups = claims.get("cognito:groups")
    group_values: list[str] = []
    if isinstance(groups, str):
        # Cognito may serialize groups as a comma/space separated string.
        group_values = [g.strip() for g in groups.replace(",", " ").split() if g.strip()]
    elif isinstance(groups, (list, tuple, set)):
        group_values = [str(g).strip() for g in groups]
    for group in group_values:
        if group.lower() in ROLE_RANK:
            resolved.append(group.lower())

    if not resolved:
        return ""
    # Highest privilege among the resolved groups.
    return max(resolved, key=lambda r: ROLE_RANK[r])


def _bearer_token(request: Request) -> str:
    """Return the bearer token from the Authorization header, or ""."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


def _principal_from_token(request: Request) -> Principal:
    """Resolve the caller in ``token`` auth mode.

    A single shared secret (``VARDOGER_AUTH_SECRET``) gates access over an
    otherwise-open Lambda Function URL. Every request must present
    ``Authorization: Bearer <secret>``. This is the single-operator self-host
    posture: a valid secret is the owner, mapped to ``admin``.
    """
    secret = config.AUTH_SECRET.strip()
    if not secret:
        # Misconfiguration: token mode with no secret set. Fail closed rather
        # than defaulting to open — this must never silently allow access.
        logger.error("AUTH_MODE=token but VARDOGER_AUTH_SECRET is empty; refusing all requests")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server auth is misconfigured",
        )

    presented = _bearer_token(request)
    # Constant-time comparison to avoid leaking the secret via timing. Compare
    # as UTF-8 bytes: hmac.compare_digest raises TypeError on a non-ASCII str,
    # which would surface as a 500 instead of a clean 401.
    if not presented or not hmac.compare_digest(
        presented.encode("utf-8"), secret.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Principal(role="admin", subject="token-operator")


def get_principal(request: Request) -> Principal:
    """Resolve the caller into a Principal based on the configured auth mode."""
    mode = config.AUTH_MODE.strip().lower()

    if not config.auth_enabled():
        # Local dev: single owner is treated as admin.
        return Principal(role="admin", subject="local-dev")

    if mode == "token":
        return _principal_from_token(request)

    # Cognito modes: role comes only from upstream-verified authorizer claims.
    claims = _claims_from_request(request)
    subject = str(claims.get("sub") or claims.get("username") or claims.get("cognito:username") or "")
    role = _role_from_claims(claims)

    if not role:
        # Fail closed: auth is enabled but we could not resolve a role.
        logger.warning("Auth enabled (mode=%s) but no role resolved for caller sub=%s", mode, subject)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No authorized role for caller",
        )
    return Principal(role=role, subject=subject, claims=claims)


def require_role(minimum: str) -> Callable[[Principal], Principal]:
    """FastAPI dependency factory enforcing a minimum role.

    Usage::

        @router.get("/thing", dependencies=[Depends(require_role("viewer"))])

    or to receive the principal::

        def handler(principal: Principal = Depends(require_role("admin"))): ...
    """
    if minimum not in ROLE_RANK:
        raise ValueError(f"Unknown role {minimum!r}; expected one of {VALID_ROLES}")

    def _dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has_at_least(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum}' or higher",
            )
        return principal

    return _dependency
