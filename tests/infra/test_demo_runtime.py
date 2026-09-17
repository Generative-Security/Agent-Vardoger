"""The self-managed demo runtime, and the parts cfn-lint will not catch.

It exists because the bundled harness cannot demonstrate the session kill:
AgentCore refuses StopRuntimeSession on a harness-managed runtime. A runtime the
stack owns is both the production shape and the only one where enforcement can
be proven.

cfn-lint does validate AgentCore resources — it rejects unknown properties
(E3002) and invalid enum values (E3030), verified by feeding it both. What it
does NOT check, also verified, is the `AgentRuntimeName` pattern: a name with
hyphens passes the linter and fails at create time. Everything below is either
in that gap or is a cross-file agreement the linter cannot see.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra/self-hosted.yaml"
DEPLOY_SH = ROOT / "scripts/deploy.sh"


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


@pytest.fixture(scope="module")
def template() -> dict:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_Loader)


@pytest.fixture(scope="module")
def runtime(template: dict) -> dict:
    return template["Resources"]["DemoAgentRuntime"]["Properties"]


class TestOffByDefault:
    def test_the_parameter_defaults_to_false(self, template: dict) -> None:
        assert template["Parameters"]["DeployDemoRuntime"]["Default"] == "false"

    def test_every_demo_resource_is_gated(self, template: dict) -> None:
        """An ungated demo resource would appear in every deployment."""
        ungated = [
            name for name, body in template["Resources"].items()
            if name.startswith("DemoAgent") and body.get("Condition") != "DeployDemoRuntime"
        ]
        assert not ungated, f"demo resources deployed unconditionally: {ungated}"


class TestTheNamePatternCfnLintIgnores:
    """Verified: a hyphenated name passes cfn-lint and fails at create time."""

    PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,47}$")

    def test_the_runtime_name_matches_the_documented_pattern(self, runtime: dict) -> None:
        # Resolve Fn::Sub against a worst-case 12-digit account id.
        name = runtime["AgentRuntimeName"]
        rendered = name["Fn::Sub"].replace("${AWS::AccountId}", "123456789012") \
            if isinstance(name, dict) else name
        assert self.PATTERN.match(rendered), (
            f"AgentRuntimeName resolves to {rendered!r}, which violates "
            "[a-zA-Z][a-zA-Z0-9_]{0,47}. Hyphens are the usual cause and "
            "cfn-lint does not catch them."
        )

    def test_it_stays_within_the_length_limit(self, runtime: dict) -> None:
        name = runtime["AgentRuntimeName"]
        rendered = name["Fn::Sub"].replace("${AWS::AccountId}", "123456789012") \
            if isinstance(name, dict) else name
        assert len(rendered) <= 48


class TestTheCodeDeploymentContract:
    """Each of these fails at start-up, inside a runtime nobody can shell into."""

    def test_the_entrypoint_is_the_file_at_the_archive_root(self, runtime: dict) -> None:
        entry = runtime["AgentRuntimeArtifact"]["CodeConfiguration"]["EntryPoint"]
        assert entry == ["main.py"], (
            f"EntryPoint is {entry!r}. It must name the file as packaged at the "
            "ROOT of the zip; a nested path is not found and the runtime never "
            "starts."
        )

    def test_no_otel_wrapper_without_the_dependency(self, runtime: dict) -> None:
        """`opentelemetry-instrument` is valid ONLY if the distro is packaged.

        The agent is deliberately dependency-free, so naming the wrapper would
        fail at start-up with a missing executable.
        """
        entry = runtime["AgentRuntimeArtifact"]["CodeConfiguration"]["EntryPoint"]
        assert "opentelemetry-instrument" not in entry

    def test_the_runtime_version_is_a_supported_value(self, runtime: dict) -> None:
        supported = {"PYTHON_3_10", "PYTHON_3_11", "PYTHON_3_12",
                     "PYTHON_3_13", "PYTHON_3_14", "NODE_22"}
        assert runtime["AgentRuntimeArtifact"]["CodeConfiguration"]["Runtime"] in supported

    def test_the_protocol_is_http_not_mcp(self, runtime: dict) -> None:
        """This runtime IS the agent; the gateway sits in FRONT of it and
        forwards the caller's raw prompt. MCP here would be the behind-the-agent
        topology, which is what the harness already covers."""
        assert runtime["ProtocolConfiguration"] == "HTTP"

    def test_the_code_comes_from_the_deploy_bucket(self, runtime: dict) -> None:
        s3 = runtime["AgentRuntimeArtifact"]["CodeConfiguration"]["Code"]["S3"]
        assert s3["Bucket"] == {"Ref": "CodeS3Bucket"}
        assert s3["Prefix"] == {"Ref": "DemoAgentS3Key"}

    def test_the_key_default_is_not_empty(self, template: dict) -> None:
        """S3Location.Prefix has a minimum length of 1, so an empty default
        fails validation even when the runtime is not deployed."""
        assert template["Parameters"]["DemoAgentS3Key"]["Default"]


class TestTheRoleCanActuallyStart:
    """Each missing permission presents as something other than a denial."""

    REQUIRED: ClassVar[set[str]] = {
        "s3:GetObject",                # pull the package
        "ecr-public:GetAuthorizationToken",  # managed base image
        "sts:GetServiceBearerToken",
        "logs:PutLogEvents",
        "bedrock-agentcore:GetWorkloadAccessToken",
    }

    def test_every_required_action_is_granted(self, template: dict) -> None:
        granted: set[str] = set()
        role = template["Resources"]["DemoAgentRuntimeRole"]["Properties"]
        for policy in role["Policies"]:
            for statement in policy["PolicyDocument"]["Statement"]:
                action = statement.get("Action", [])
                granted.update([action] if isinstance(action, str) else action)
        missing = sorted(self.REQUIRED - granted)
        assert not missing, f"the demo runtime role cannot start without: {missing}"

    def test_the_package_grant_is_scoped_to_the_deploy_bucket(self, template: dict) -> None:
        role = template["Resources"]["DemoAgentRuntimeRole"]["Properties"]
        s3_statements = [
            st for policy in role["Policies"]
            for st in policy["PolicyDocument"]["Statement"]
            if "s3:GetObject" in (st.get("Action") or [])
        ]
        assert s3_statements, "no s3:GetObject grant"
        resource = s3_statements[0]["Resource"]
        assert "CodeS3Bucket" in str(resource), (
            f"the package grant is {resource!r}, not scoped to the deploy bucket"
        )


class TestDeployScriptAgreement:
    """The zip and the template must agree, and nothing else checks that."""

    SCRIPT = DEPLOY_SH.read_text(encoding="utf-8")

    def test_the_agent_is_packaged_when_the_runtime_is_deployed(self) -> None:
        assert 'if [ "$DEMO_RUNTIME" = "true" ]' in self.SCRIPT

    def test_main_py_is_written_to_the_archive_root(self) -> None:
        """A nested path is simply not found at start-up."""
        assert 'zf.write(src, "main.py")' in self.SCRIPT

    def test_the_key_is_content_hashed(self) -> None:
        """A fixed key means CloudFormation sees no change and keeps the old
        code — the same trap the Lambda package already had to solve."""
        assert "vardoger-demo-agent-${DEMO_HASH}.zip" in self.SCRIPT

    def test_both_deploy_passes_carry_the_demo_parameters(self) -> None:
        """A parameter set on pass 1 and dropped on pass 2 reverts to default,
        which would tear the runtime down moments after creating it."""
        for param in ("DeployDemoRuntime=$DEMO_RUNTIME", "DemoAgentS3Key=$DEMO_AGENT_S3_KEY"):
            assert self.SCRIPT.count(param) == 2, (
                f"{param} appears {self.SCRIPT.count(param)} times; it must be on "
                "both CloudFormation passes"
            )
