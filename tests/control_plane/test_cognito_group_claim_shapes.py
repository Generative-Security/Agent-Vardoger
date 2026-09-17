"""`cognito:groups` does not arrive as a list. It arrives with brackets.

The API Gateway HTTP API JWT authorizer flattens every claim to a string, and
an ARRAY claim keeps its brackets:

    cognito:groups  ->  "[admin]"
                    ->  "[admin operator]"

The parser split on commas and spaces and never stripped them, so "[admin]" was
compared against the role table and never matched. Measured live: Cognito
reported the user in `admin`, a freshly issued token carried the claim, and
every route still returned 403 with "no role resolved".

That failure is expensive out of proportion to its size. It is indistinguishable
from a missing group, so the operator checks Cognito (correct), re-issues the
token (correct), and still cannot use the console — with nothing anywhere
suggesting the claim is being misread rather than missing.

This is an authorization path, so the tests below pin BOTH directions: every
delivery shape must resolve, and nothing may resolve that should not.
"""
from __future__ import annotations

import pytest

from control_plane.dependencies import _role_from_claims


def _role(groups) -> str:
    return _role_from_claims({"cognito:groups": groups})


class TestEveryDeliveryShapeResolves:
    """One of these is what AWS actually sends; the rest are what it might."""

    @pytest.mark.parametrize("claim,expected", [
        # The live shape, from the API Gateway JWT authorizer.
        ("[admin]", "admin"),
        ("[viewer]", "viewer"),
        ("[operator]", "operator"),
        # Several groups: bracketed and space separated.
        ("[admin operator]", "admin"),
        ("[viewer operator]", "operator"),
        # Unbracketed, as a plain claim or a single group.
        ("admin", "admin"),
        ("admin,operator", "admin"),
        ("admin operator", "admin"),
        # A decoded token rather than the authorizer: a genuine JSON array.
        ('["admin"]', "admin"),
        ('["viewer", "admin"]', "admin"),
        # An actual list, when claims come from a library that parsed them.
        (["admin"], "admin"),
        (["viewer", "admin"], "admin"),
        (("operator",), "operator"),
    ])
    def test_it_resolves(self, claim, expected: str) -> None:
        assert _role(claim) == expected


class TestHighestPrivilegeWins:
    @pytest.mark.parametrize("claim", ["[viewer operator admin]",
                                       "[admin viewer]",
                                       ["operator", "admin", "viewer"]])
    def test_admin_beats_the_others(self, claim) -> None:
        assert _role(claim) == "admin"

    def test_operator_beats_viewer(self) -> None:
        assert _role("[viewer operator]") == "operator"


class TestNothingUnintendedResolves:
    """The parse strips delimiters; it must not become permissive.

    Each of these would be a privilege escalation if it resolved.
    """

    @pytest.mark.parametrize("claim", [
        "", "   ", None, [], "[]", "[ ]",
        "[unknown]", "unknown", "[superadmin]", "[admins]",
        "[admin-ish]", "[ADMINISTRATOR]",
        123, {}, {"admin": True},
    ])
    def test_it_resolves_to_no_role(self, claim) -> None:
        assert _role(claim) == ""

    def test_a_missing_claim_resolves_to_no_role(self) -> None:
        assert _role_from_claims({}) == ""

    def test_a_user_writable_claim_is_never_honoured(self) -> None:
        """A Cognito custom attribute is user-writable: trusting it would let a
        caller grant themselves admin. Only cognito:groups counts."""
        assert _role_from_claims({"role": "admin"}) == ""
        assert _role_from_claims({"custom:role": "admin"}) == ""
        assert _role_from_claims({"groups": "admin"}) == ""

    def test_case_is_normalised_but_names_must_match_exactly(self) -> None:
        """Cognito group names are case sensitive; ours are lowercase.

        Accepting "Admin" is a convenience, not a widening — the name still has
        to be a known role.
        """
        assert _role("[ADMIN]") == "admin"
        assert _role("[Admin]") == "admin"
        assert _role("[admin_readonly]") == ""
