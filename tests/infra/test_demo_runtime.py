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


class TestTheGatewayTopology:
    """A protocol-less gateway IN FRONT of the runtime.

    This is the topology the prompt-injection claim rests on: the interceptor
    sees the caller's raw prompt rather than an agent's tool-call arguments.
    Two things about it are easy to get wrong and silent when wrong.
    """

    @pytest.fixture()
    def gateway(self, template: dict) -> dict:
        return template["Resources"]["DemoGateway"]["Properties"]

    def test_the_gateway_declares_no_protocol_type(self, gateway: dict) -> None:
        """Omitting ProtocolType is what makes it protocol-less.

        Setting MCP would do two damaging things at once: make the interceptor
        see tool calls instead of prompts, and make an AgentCore Runtime target
        invalid — the pairing that yields `tools/list: []` while every component
        reports READY and no prompt ever reaches the monitor.
        """
        assert "ProtocolType" not in gateway, (
            "DemoGateway sets ProtocolType, so it is no longer protocol-less"
        )

    def test_the_target_routes_to_the_runtime_over_http(self, template: dict) -> None:
        target = template["Resources"]["DemoGatewayTarget"]["Properties"]
        config = target["TargetConfiguration"]
        assert "Mcp" not in config, "an MCP target cannot front a runtime"
        arn = config["Http"]["AgentcoreRuntime"]["Arn"]
        assert arn == {"Fn::GetAtt": "DemoAgentRuntime.AgentRuntimeArn"}

    def test_the_target_name_is_the_url_path(self, template: dict) -> None:
        """A protocol-less gateway routes by /<targetName>/invocations, so the
        name IS the endpoint. Renaming it moves the URL silently."""
        target = template["Resources"]["DemoGatewayTarget"]["Properties"]
        assert target["Name"] == "agent"
        script = DEPLOY_SH.read_text(encoding="utf-8")
        assert "/agent/invocations" in script, (
            "deploy.sh prints an endpoint that disagrees with the target name"
        )

    def test_the_dispatcher_is_attached_as_a_request_interceptor(
        self, gateway: dict
    ) -> None:
        interceptors = gateway["InterceptorConfigurations"]
        assert len(interceptors) == 1
        assert interceptors[0]["Interceptor"]["Lambda"]["Arn"] == {
            "Fn::GetAtt": "DispatcherFunction.Arn"
        }
        assert "REQUEST" in interceptors[0]["InterceptionPoints"]

    def test_request_headers_are_passed_to_the_interceptor(self, gateway: dict) -> None:
        """Without this the interceptor receives no headers at all."""
        interceptors = gateway["InterceptorConfigurations"]
        assert interceptors[0]["InputConfiguration"]["PassRequestHeaders"] is True

    def test_inbound_auth_is_jwt_so_the_test_console_can_reach_it(
        self, gateway: dict
    ) -> None:
        """AWS_IAM would make the gateway unreachable from the browser: the
        console presents a bearer token and cannot sign SigV4."""
        assert gateway["AuthorizerType"] == "CUSTOM_JWT"


class TestTheGatewayMayInvokeBothHops:
    """Both grants are required, and one of them failed silently before.

    A resource policy on the dispatcher is necessary but NOT sufficient: the
    gateway invokes the interceptor under its own role. Missing that grant
    produced a 500 from the gateway with an entirely empty dispatcher log — the
    monitor looked absent rather than denied.
    """

    @pytest.fixture()
    def statements(self, template: dict) -> list[dict]:
        role = template["Resources"]["DemoGatewayRole"]["Properties"]
        return [st for p in role["Policies"] for st in p["PolicyDocument"]["Statement"]]

    def test_it_may_invoke_the_runtime(self, statements: list[dict]) -> None:
        actions = {st.get("Action") for st in statements}
        assert "bedrock-agentcore:InvokeAgentRuntime" in actions

    def test_it_may_invoke_the_interceptor(self, statements: list[dict]) -> None:
        invoke = [st for st in statements if st.get("Action") == "lambda:InvokeFunction"]
        assert invoke, (
            "the gateway role cannot invoke the dispatcher, so the interceptor "
            "is never called and the gateway returns 500 with an empty log"
        )
        assert invoke[0]["Resource"] == {"Fn::GetAtt": "DispatcherFunction.Arn"}

    def test_the_resource_policy_exists_too(self, template: dict) -> None:
        perm = template["Resources"]["DemoDispatcherPermission"]["Properties"]
        assert perm["Principal"] == "bedrock-agentcore.amazonaws.com"
        assert perm["SourceArn"] == {"Fn::GetAtt": "DemoGateway.GatewayArn"}

    def test_the_role_grants_nothing_else(self, statements: list[dict]) -> None:
        """Narrower than the default gateway role, which can invoke every
        Lambda in the account."""
        actions = {st.get("Action") for st in statements}
        assert actions == {
            "bedrock-agentcore:InvokeAgentRuntime",
            "lambda:InvokeFunction",
        }, f"demo gateway role grants {sorted(actions)}"


class TestTheKillGrantIsScopedToTheDemoRuntime:
    """The whole point of the demo: a runtime StopRuntimeSession can stop."""

    SCRIPT = DEPLOY_SH.read_text(encoding="utf-8")

    def test_the_runtime_arn_is_fed_back_on_the_second_pass(self) -> None:
        assert "DemoAgentRuntimeArn" in self.SCRIPT, (
            "deploy.sh never reads the demo runtime ARN, so the kill grant stays "
            "widened to every runtime in the account"
        )
        assert 'AGENT_RUNTIME_ARN_EFFECTIVE="$DEMO_RUNTIME_ARN"' in self.SCRIPT

    def test_the_demo_runtime_wins_when_both_are_deployed(self) -> None:
        """A harness-managed runtime refuses StopRuntimeSession, so scoping the
        kill to it would make enforcement undemonstrable even with the demo
        present."""
        demo_at = self.SCRIPT.index('DEMO_RUNTIME_ARN"')
        harness_at = self.SCRIPT.index('HARNESS_RUNTIME_ARN"')
        assert demo_at < harness_at, (
            "the harness runtime ARN is read after the demo one and would "
            "overwrite it, scoping the kill to a runtime that cannot be stopped"
        )


class TestThePreconditionsKnowAboutBothModes:
    """A mode that builds its own gateway must not be asked for one.

    Both guards tested only NEW_HARNESS, so VARDOGER_DEMO_RUNTIME=true was
    refused for want of a gateway ARN and a runtime ARN — both of which that
    mode creates itself. Adding a second self-contained topology without
    updating the checks that exist to detect the absence of infrastructure.

    The operator sees this before anything else happens, and the message told
    them to use the harness: the one topology where the session kill, which is
    why the demo exists, cannot be demonstrated.
    """

    SCRIPT = DEPLOY_SH.read_text(encoding="utf-8")

    def test_the_gateway_guard_accepts_either_self_contained_mode(self) -> None:
        guard = self.SCRIPT[self.SCRIPT.index("VARDOGER_GATEWAY_ARN is required") - 400:]
        assert '[ "$DEMO_RUNTIME" != "true" ]' in guard[:400], (
            "the gateway precondition ignores DEMO_RUNTIME, so a mode that "
            "builds its own gateway is refused for not having one"
        )

    def test_the_runtime_guard_accepts_either_self_contained_mode(self) -> None:
        guard = self.SCRIPT[self.SCRIPT.index("VARDOGER_AGENT_RUNTIME_ARN is required") - 400:]
        assert '[ "$DEMO_RUNTIME" != "true" ]' in guard[:400], (
            "the runtime precondition ignores DEMO_RUNTIME, which creates a "
            "runtime and reads its ARN back on the second pass"
        )

    def test_the_error_message_offers_both_topologies(self) -> None:
        """Offering only the harness sends an operator to the one place the
        session kill cannot be shown."""
        start = self.SCRIPT.index("VARDOGER_GATEWAY_ARN is required")
        message = self.SCRIPT[start:start + 1600]
        assert "VARDOGER_DEMO_RUNTIME=true" in message
        assert "VARDOGER_NEW_HARNESS=true" in message

    def test_the_mode_flags_are_assigned_before_the_guards_read_them(self) -> None:
        """Under `set -u` an unassigned variable aborts the deploy outright."""
        assign = self.SCRIPT.index('DEMO_RUNTIME="${VARDOGER_DEMO_RUNTIME:-false}"')
        first_use = self.SCRIPT.index('[ "$DEMO_RUNTIME" != "true" ]')
        assert assign < first_use, (
            "DEMO_RUNTIME is read by a precondition before it is assigned"
        )


class TestOutputsAreVisibleWheneverTheirResourceExists:
    """An output gated more narrowly than its resource is a resource nobody
    can find.

    The Cognito pool moved to a shared condition so the demo gateway could use
    it, but its three outputs stayed on `DeployTestHarness`. With the harness
    off and the demo on, the pool existed and NOTHING published its token
    endpoint, client id or pool id — so the Test Console asked for a bearer
    token that could not be obtained from the stack at all.

    Nothing else compares the two. cfn-lint checks that a referenced resource
    exists, not that the conditions agree.
    """

    def test_no_output_is_gated_more_narrowly_than_what_it_describes(
        self, template: dict
    ) -> None:
        resources, outputs = template["Resources"], template["Outputs"]
        mismatched = []
        for name, output in outputs.items():
            value = str(output.get("Value"))
            for res_name, body in resources.items():
                if res_name not in value:
                    continue
                res_cond = body.get("Condition")
                if res_cond and output.get("Condition") != res_cond:
                    mismatched.append(
                        f"{name} (Condition: {output.get('Condition')}) describes "
                        f"{res_name} (Condition: {res_cond})"
                    )
        assert not mismatched, (
            "outputs whose condition disagrees with the resource they describe: "
            f"{mismatched}. Either the output is published when the resource "
            "does not exist, or the resource exists and cannot be found."
        )

    def test_the_gateway_auth_outputs_follow_the_shared_pool(
        self, template: dict
    ) -> None:
        """Explicit, because these are the three an operator needs to obtain a
        token, and a generic check would pass if all four moved together in the
        wrong direction."""
        for name in ("TestHarnessTokenEndpoint", "TestHarnessClientId",
                     "TestHarnessUserPoolId"):
            assert template["Outputs"][name]["Condition"] == "NeedsGatewayAuth", (
                f"{name} is not published when only the demo runtime is deployed, "
                "so its gateway token cannot be obtained"
            )


class TestTheDemoSummaryExplainsTheToken:
    """The Test Console asks for a bearer token; the summary must say which.

    It is a machine-to-machine token for the GATEWAY, not the Cognito login
    used for the dashboard — which is the natural thing to try, and the thing
    that fails with no indication why.
    """

    SCRIPT = DEPLOY_SH.read_text(encoding="utf-8")

    def test_the_demo_summary_prints_token_instructions(self) -> None:
        summary = self.SCRIPT[self.SCRIPT.index("=== Demo runtime (self-managed) ==="):]
        assert "Get a GATEWAY bearer token" in summary[:3000], (
            "the demo summary gives an endpoint but no way to authenticate to it"
        )

    def test_it_distinguishes_the_gateway_token_from_the_console_login(self) -> None:
        summary = self.SCRIPT[self.SCRIPT.index("=== Demo runtime (self-managed) ==="):]
        assert "NOT the Cognito login" in summary[:3000]
