"""RBAC gate tests for require_role and the admin-only write paths.

These exercise the same dependency the routers use (require_role), so a viewer
or operator hitting an admin-only path (e.g. PUT /api/policy) is rejected with
403, and only admin passes. No HTTP layer is needed — require_role returns a
FastAPI dependency callable we invoke with a Principal directly.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from control_plane.dependencies import Principal, require_role


def _gate(minimum: str, role: str) -> Principal:
    """Resolve require_role(minimum) for a caller with the given role."""
    principal = Principal(role=role, subject=f"{role}-user")
    dependency = require_role(minimum)
    # The inner dependency takes the resolved principal and enforces the floor.
    return dependency(principal=principal)


class TestRequireRole:
    def test_admin_only_rejects_viewer(self):
        with pytest.raises(HTTPException) as exc:
            _gate("admin", "viewer")
        assert exc.value.status_code == 403

    def test_admin_only_rejects_operator(self):
        with pytest.raises(HTTPException) as exc:
            _gate("admin", "operator")
        assert exc.value.status_code == 403

    def test_admin_only_allows_admin(self):
        principal = _gate("admin", "admin")
        assert principal.role == "admin"

    def test_operator_path_rejects_viewer(self):
        with pytest.raises(HTTPException) as exc:
            _gate("operator", "viewer")
        assert exc.value.status_code == 403

    def test_operator_path_allows_operator_and_admin(self):
        assert _gate("operator", "operator").role == "operator"
        assert _gate("operator", "admin").role == "admin"

    def test_viewer_path_allows_all_roles(self):
        for role in ("viewer", "operator", "admin"):
            assert _gate("viewer", role).role == role

    def test_unknown_minimum_raises_value_error(self):
        with pytest.raises(ValueError):
            require_role("superuser")


class TestPrincipalRank:
    def test_has_at_least(self):
        admin = Principal(role="admin")
        viewer = Principal(role="viewer")
        assert admin.has_at_least("admin")
        assert admin.has_at_least("viewer")
        assert viewer.has_at_least("viewer")
        assert not viewer.has_at_least("operator")
