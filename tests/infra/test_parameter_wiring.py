"""Every CloudFormation parameter must actually reach the code.

This guards a bug class that appeared repeatedly and is invisible at deploy
time: a parameter that looks configurable, validates fine, deploys fine, and
changes nothing. CloudFormation cannot catch it — the template is valid either
way — and neither can a unit test of the handler, because the handler is
correct in isolation. The break is in the seam between them.

Instances this would have caught:

* ``DetectionRetentionDays`` was declared, documented, and passed to no Lambda.
  Setting it to 30 silently gave you the code's hardcoded 90.
* ``SignatureS3Bucket``/``SignatureS3Prefix`` were wired into the dispatcher's
  environment, but no module ever read them.
* Tier 3 read ``GLOBAL_KILL_ENABLED`` while the template set
  ``VARDOGER_GLOBAL_KILL_ENABLED``, so its kill gate could never be satisfied —
  and the outcome ledger blamed ``global_kill_disabled`` on an operator who had
  in fact enabled it.

The checks run in both directions: template -> code, and code -> template.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ["infra/self-hosted.yaml", "infra/managed-agent.yaml"]

# Source trees whose env reads count as "the code". Tests are excluded: a name
# that only a test references is still dead in production.
CODE_DIRS = ["vardoger", "adapters", "control_plane", "signatures"]

# Keys whose value is metadata, not behaviour. A parameter used ONLY under one
# of these is cosmetic. Note UserPoolTags: Cognito spells it differently, and
# missing it once let ScopeId look functional when all 27 of its uses are tags.
COSMETIC_KEYS = {"Tags", "UserPoolTags", "Description", "AlarmDescription"}

# Parameters that are legitimately cosmetic, with the reason they are allowed.
COSMETIC_BY_DESIGN = {
    "ScopeId": (
        "Self-hosted is always scope 'local' by design (see DESIGN-DECISIONS.md); "
        "this parameter only labels resources for cost attribution, and its "
        "description says so."
    ),
    "CostAllocationTagValue": "It is a tag value. Being used only in Tags is the point.",
    "DeploymentModel": (
        "Tag only, as its description states. The functional value is a literal "
        "(VARDOGER_DEPLOYMENT_MODE: self-hosted) because the self-hosted template "
        "IS the self-hosted deployment — deriving it from a parameter would let "
        "the control plane report a model the infrastructure does not match."
    ),
}


class _Loader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation's short-form intrinsics."""


def _intrinsic(loader: _Loader, tag_suffix: str, node: yaml.Node) -> dict:
    key = "Fn::" + tag_suffix if tag_suffix != "Ref" else "Ref"
    if isinstance(node, yaml.ScalarNode):
        return {key: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {key: loader.construct_sequence(node, deep=True)}
    return {key: loader.construct_mapping(node, deep=True)}


_Loader.add_multi_constructor("!", _intrinsic)


def _load(template: str) -> dict:
    return yaml.load((ROOT / template).read_text(encoding="utf-8"), Loader=_Loader)


def _param_refs(node: object, params: set[str], hits: dict[str, list[tuple]], path: tuple = ()) -> None:
    """Record every parameter reference together with the key path that reached it."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "Ref" and isinstance(value, str) and value in params:
                hits.setdefault(value, []).append(path)
            elif key == "Fn::Sub":
                body = value[0] if isinstance(value, list) else value
                local = set(value[1]) if isinstance(value, list) and len(value) > 1 else set()
                for name in re.findall(r"\$\{([^}!][^}]*)\}", body or ""):
                    root = name.split(".")[0]
                    if root in params and root not in local:
                        hits.setdefault(root, []).append(path)
            _param_refs(value, params, hits, (*path, key))
    elif isinstance(node, list):
        for item in node:
            _param_refs(item, params, hits, path)


def _template_env_vars(template: dict) -> dict[str, str]:
    """Map each env var the template sets to the resource that sets it."""
    found: dict[str, str] = {}
    for name, body in (template.get("Resources") or {}).items():
        variables = ((body.get("Properties") or {}).get("Environment") or {}).get("Variables") or {}
        for var in variables:
            found.setdefault(var, name)
    return found


_ENV_READ_PATTERN = re.compile(
    r"""os\.environ\.get\(\s*["']([A-Z0-9_]+)["']"""
    r"""|os\.environ\[\s*["']([A-Z0-9_]+)["']"""
    r"""|_get(?:_int|_float)?\(\s*["']([A-Z0-9_]+)["']"""
)


def _env_names_read_by_code() -> set[str]:
    names: set[str] = set()
    for directory in CODE_DIRS:
        for file in (ROOT / directory).rglob("*.py"):
            for match in _ENV_READ_PATTERN.finditer(file.read_text(encoding="utf-8", errors="replace")):
                names.add(next(g for g in match.groups() if g))
    return names


@pytest.fixture(scope="module")
def env_read() -> set[str]:
    names = _env_names_read_by_code()
    assert "VARDOGER_SESSION_TABLE" in names, "env-read scan found nothing; the regex is broken"
    return names


@pytest.mark.parametrize("template_path", TEMPLATES)
class TestParameterWiring:
    def test_every_parameter_is_referenced(self, template_path: str) -> None:
        """A parameter nothing references cannot do anything."""
        template = _load(template_path)
        params = set(template.get("Parameters") or {})
        hits: dict[str, list[tuple]] = {}
        for section in ("Resources", "Conditions", "Outputs"):
            _param_refs(template.get(section) or {}, params, hits)

        unreferenced = sorted(params - set(hits))
        assert not unreferenced, (
            f"{template_path}: parameters referenced nowhere: {unreferenced}. "
            "Either wire them up or delete them — shipping a knob that does "
            "nothing is worse than not offering it."
        )

    def test_no_parameter_is_only_cosmetic(self, template_path: str) -> None:
        """A parameter used only in Tags/Description changes no behaviour.

        It passes the reference check above while still being a no-op, which is
        how ``ScopeId`` initially looked correct.
        """
        template = _load(template_path)
        params = set(template.get("Parameters") or {})
        hits: dict[str, list[tuple]] = {}
        for section in ("Resources", "Conditions", "Outputs"):
            _param_refs(template.get(section) or {}, params, hits)

        cosmetic = [
            name
            for name, paths in hits.items()
            if name not in COSMETIC_BY_DESIGN
            and all(COSMETIC_KEYS & set(path) for path in paths)
        ]
        assert not cosmetic, (
            f"{template_path}: parameters used only as metadata: {sorted(cosmetic)}. "
            "If that is intended, add it to COSMETIC_BY_DESIGN with the reason."
        )

    def test_every_env_var_the_template_sets_is_read_by_code(
        self, template_path: str, env_read: set[str]
    ) -> None:
        """Template -> code. Catches a value handed to a Lambda that ignores it."""
        template = _load(template_path)
        unread = {
            var: resource
            for var, resource in _template_env_vars(template).items()
            if var not in env_read
        }
        assert not unread, (
            f"{template_path}: env vars set but never read: {sorted(unread)}. "
            "Each is a setting an operator can change with no effect. Check for "
            "a spelling mismatch with the name the handler reads before deleting."
        )


def test_tier_handlers_read_the_names_the_template_sets(env_read: set[str]) -> None:
    """Code -> template, for the settings the STACK is responsible for supplying.

    Tuning knobs deliberately live on their code defaults and are not listed
    here; these are the ones a deployment must wire or the feature is unreachable.
    """
    template = (ROOT / "infra/self-hosted.yaml").read_text(encoding="utf-8")
    must_be_wired = [
        "VARDOGER_SESSION_TABLE",
        "VARDOGER_DETECTION_EVENTS_TABLE",
        "VARDOGER_PROMPT_HISTORY_TABLE",
        "VARDOGER_TENANTS_TABLE",
        "VARDOGER_OUTCOME_TABLE",
        "VARDOGER_ENFORCEMENT_FUNCTION",
        "VARDOGER_GLOBAL_KILL_ENABLED",
        "VARDOGER_ALERT_QUEUE_URL",
        "VARDOGER_PROMPT_INTAKE_QUEUE_URL",
        "VARDOGER_TIER1_MODE",
        "VARDOGER_DETECTION_FAILURE_POLICY",
        "TIER3_ENABLED",
        "TIER3_KILL_ENABLED",
    ]
    missing_from_template = [name for name in must_be_wired if f"{name}:" not in template]
    assert not missing_from_template, (
        f"template never sets: {missing_from_template} — the feature is unreachable"
    )

    unread_by_code = [name for name in must_be_wired if name not in env_read]
    assert not unread_by_code, (
        f"no module reads: {unread_by_code} — check for a prefix mismatch"
    )


class _RouteLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation's short-form intrinsics."""


def _route_intrinsic(loader: _RouteLoader, tag_suffix: str, node: yaml.Node) -> dict:
    key = "Fn::" + tag_suffix if tag_suffix != "Ref" else "Ref"
    if isinstance(node, yaml.ScalarNode):
        return {key: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {key: loader.construct_sequence(node, deep=True)}
    return {key: loader.construct_mapping(node, deep=True)}


_RouteLoader.add_multi_constructor("!", _route_intrinsic)


@pytest.fixture(scope="module")
def resources() -> dict:
    path = Path(__file__).resolve().parents[2] / "infra/self-hosted.yaml"
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_RouteLoader)["Resources"]


class TestHealthIsReachableWithoutCredentials:
    """The one endpoint that must answer when everything else is broken.

    Every document says /api/health needs no credentials in any mode, and in
    token/none mode that held: the Function URL has no authorizer and the route
    declares no auth dependency. In cognito mode the HTTP API's single $default
    route applied the JWT authorizer to every path, so /api/health returned
    {"message":"Unauthorized"}.

    That inverts what a health check is for. An operator reaching for it is
    asking "is the control plane alive?", and got an answer indistinguishable
    from a broken deployment — while the real cause was an expired browser
    token. A more specific route overrides $default, so only this path is
    exempt.
    """

    @staticmethod
    def _routes(resources: dict) -> dict[str, dict]:
        return {
            body["Properties"]["RouteKey"]: body["Properties"]
            for body in resources.values()
            if body.get("Type") == "AWS::ApiGatewayV2::Route"
        }

    def test_a_dedicated_health_route_exists(self, resources: dict) -> None:
        routes = self._routes(resources)
        assert "GET /api/health" in routes, (
            "no unauthenticated health route; in cognito mode the $default JWT "
            "authorizer makes /api/health return Unauthorized, so the documented "
            "liveness check does not work in the mode teams actually deploy"
        )

    def test_the_health_route_requires_no_authorizer(self, resources: dict) -> None:
        health = self._routes(resources)["GET /api/health"]
        assert health.get("AuthorizationType") == "NONE"
        assert "AuthorizerId" not in health, (
            "the health route carries an authorizer, so it is not reachable "
            "without credentials after all"
        )

    def test_nothing_else_was_exempted(self, resources: dict) -> None:
        """The exemption must be one path, not a hole in the authorizer.

        Every other route has to keep the JWT authorizer; a second NONE route
        would be an unauthenticated control-plane API.
        """
        unauthenticated = sorted(
            key for key, props in self._routes(resources).items()
            if props.get("AuthorizationType") == "NONE"
        )
        assert unauthenticated == ["GET /api/health"], (
            f"routes reachable without credentials: {unauthenticated}. Only the "
            "health check may be exempt."
        )
