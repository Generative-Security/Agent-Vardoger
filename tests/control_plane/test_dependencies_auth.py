"""RBAC / auth resolution tests for the control plane.

Covers the highest-severity auth findings:
- token mode requires a valid bearer secret (constant-time), else 401
- cognito modes read role ONLY from upstream-verified authorizer claims
- NO unverified-JWT fallback (a self-signed admin token must not escalate)
- the custom:role / role claim path is NOT honored (no self-escalation)
"""
from __future__ import annotations

import base64
import json
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from control_plane import dependencies as deps


class _FakeRequest:
    """Minimal stand-in for starlette Request: headers + scope."""

    def __init__(self, headers: dict | None = None, aws_event: dict | None = None):
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.scope = {"aws.event": aws_event} if aws_event is not None else {}


def _unsigned_jwt(claims: dict) -> str:
    """Build a syntactically valid but UNVERIFIED JWT (alg=none style)."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.sig"


def _authorizer_event(claims: dict) -> dict:
    """API Gateway HTTP API JWT authorizer event shape."""
    return {"requestContext": {"authorizer": {"jwt": {"claims": claims}}}}


class TestNoneMode:
    def test_none_mode_is_admin(self):
        with patch("control_plane.config.AUTH_MODE", "none"):
            principal = deps.get_principal(_FakeRequest())
        assert principal.role == "admin"


class TestTokenMode:
    def test_valid_secret_is_admin(self):
        with patch("control_plane.config.AUTH_MODE", "token"), \
                patch("control_plane.config.AUTH_SECRET", "s3cret-value"):
            req = _FakeRequest(headers={"Authorization": "Bearer s3cret-value"})
            principal = deps.get_principal(req)
        assert principal.role == "admin"

    def test_wrong_secret_is_401(self):
        with patch("control_plane.config.AUTH_MODE", "token"), \
                patch("control_plane.config.AUTH_SECRET", "s3cret-value"):
            req = _FakeRequest(headers={"Authorization": "Bearer wrong"})
            with pytest.raises(HTTPException) as exc:
                deps.get_principal(req)
        assert exc.value.status_code == 401

    def test_missing_token_is_401(self):
        with patch("control_plane.config.AUTH_MODE", "token"), \
                patch("control_plane.config.AUTH_SECRET", "s3cret-value"), pytest.raises(HTTPException) as exc:
            deps.get_principal(_FakeRequest())
        assert exc.value.status_code == 401

    def test_empty_configured_secret_fails_closed_500(self):
        with patch("control_plane.config.AUTH_MODE", "token"), \
                patch("control_plane.config.AUTH_SECRET", ""):
            req = _FakeRequest(headers={"Authorization": "Bearer anything"})
            with pytest.raises(HTTPException) as exc:
                deps.get_principal(req)
        assert exc.value.status_code == 500

    def test_non_ascii_bearer_is_401_not_500(self):
        # A non-ASCII bearer must not raise TypeError inside compare_digest
        # (which would surface as a 500); it should be a clean 401.
        with patch("control_plane.config.AUTH_MODE", "token"), \
                patch("control_plane.config.AUTH_SECRET", "s3cret-value"):
            req = _FakeRequest(headers={"Authorization": "Bearer nöt-ascii-🔑"})
            with pytest.raises(HTTPException) as exc:
                deps.get_principal(req)
        assert exc.value.status_code == 401


class TestCognitoMode:
    def test_role_from_verified_group_claim(self):
        event = _authorizer_event({"cognito:groups": ["operator"], "sub": "u1"})
        with patch("control_plane.config.AUTH_MODE", "cognito"):
            principal = deps.get_principal(_FakeRequest(aws_event=event))
        assert principal.role == "operator"

    def test_highest_group_wins(self):
        event = _authorizer_event({"cognito:groups": ["viewer", "admin"], "sub": "u1"})
        with patch("control_plane.config.AUTH_MODE", "cognito"):
            principal = deps.get_principal(_FakeRequest(aws_event=event))
        assert principal.role == "admin"

    def test_missing_authorizer_claims_fail_closed_403(self):
        # No authorizer block at all -> no role -> 403. Critically, there is NO
        # fallback to decoding the bearer token.
        with patch("control_plane.config.AUTH_MODE", "cognito"):
            req = _FakeRequest(headers={"Authorization": f"Bearer {_unsigned_jwt({'cognito:groups': ['admin']})}"})
            with pytest.raises(HTTPException) as exc:
                deps.get_principal(req)
        assert exc.value.status_code == 403

    def test_forged_unverified_admin_token_does_not_escalate(self):
        # A self-signed token claiming admin, with no authorizer claims, must be
        # rejected (403) rather than granting admin.
        forged = _unsigned_jwt({"cognito:groups": ["admin"], "sub": "attacker"})
        with patch("control_plane.config.AUTH_MODE", "cognito"):
            req = _FakeRequest(headers={"Authorization": f"Bearer {forged}"})
            with pytest.raises(HTTPException) as exc:
                deps.get_principal(req)
        assert exc.value.status_code == 403

    def test_custom_role_claim_is_ignored(self):
        # A user-writable custom:role claim must NOT grant a role on its own.
        event = _authorizer_event({"custom:role": "admin", "sub": "u1"})
        with patch("control_plane.config.AUTH_MODE", "cognito"):
            req = _FakeRequest(aws_event=event)
            with pytest.raises(HTTPException) as exc:
                deps.get_principal(req)
        assert exc.value.status_code == 403


class TestRoleFromClaims:
    def test_custom_role_not_honored(self):
        assert deps._role_from_claims({"role": "admin"}) == ""
        assert deps._role_from_claims({"custom:role": "admin"}) == ""

    def test_group_string_serialization(self):
        assert deps._role_from_claims({"cognito:groups": "viewer,admin"}) == "admin"
