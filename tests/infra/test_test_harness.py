"""The optional test harness must stay off by default, and stay valid.

The harness exists because assembling a working AgentCore gateway by hand has
several independent ways to fail silently. The most costly one is encoded here
as a test, because CloudFormation will not catch it and the AWS console will
happily let you build it:

    An AgentCore Runtime target cannot be attached to an MCP-protocol gateway.

That pairing yields a gateway that reports READY, completes the MCP handshake,
answers tools/list with [], and never invokes anything. Every component looks
healthy while no prompt ever reaches the interceptor.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra/self-hosted.yaml"
CONDITION = "DeployTestHarness"


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
def resources(template: dict) -> dict:
    return template["Resources"]


@pytest.fixture(scope="module")
def gateway(resources: dict) -> dict:
    return resources["TestHarnessGateway"]["Properties"]


class TestOffByDefault:
    def test_the_parameter_defaults_to_false(self, template: dict) -> None:
        param = template["Parameters"]["DeployTestHarness"]
        assert param["Default"] == "false"
        assert set(param["AllowedValues"]) == {"true", "false"}

    def test_every_harness_resource_is_gated(self, resources: dict) -> None:
        """An ungated harness resource bills every operator who never asked."""
        ungated = [
            name
            for name, body in resources.items()
            if name.startswith("TestHarness") and body.get("Condition") != CONDITION
        ]
        assert not ungated, f"not gated on {CONDITION}: {ungated}"

    def test_nothing_outside_the_harness_depends_on_it(self, resources: dict) -> None:
        """A default deploy must not reference resources it never creates."""
        harness = {n for n, b in resources.items() if b.get("Condition") == CONDITION}
        offenders = []
        for name, body in resources.items():
            if body.get("Condition") == CONDITION:
                continue
            rendered = yaml.dump(body)
            offenders += [f"{name} -> {h}" for h in harness if h in rendered]
        assert not offenders, f"unconditional resources referencing the harness: {offenders}"


class TestGatewayIsValid:
    def test_the_target_is_a_lambda_not_a_runtime(self, resources: dict) -> None:
        """The constraint this whole harness exists to avoid.

        A Runtime target on an MCP gateway advertises no tools and silently
        never fires the interceptor.
        """
        config = resources["TestHarnessTarget"]["Properties"]["TargetConfiguration"]
        assert "Mcp" in config, f"expected an MCP target configuration, got {sorted(config)}"
        assert "Lambda" in config["Mcp"], "the target must be a Lambda target"
        assert "RuntimeTargetConfiguration" not in str(config)
        assert "AgentCoreRuntime" not in str(config)

    def test_the_gateway_is_mcp_protocol(self, gateway: dict) -> None:
        assert gateway["ProtocolType"] == "MCP"

    def test_the_target_advertises_at_least_one_tool(self, resources: dict) -> None:
        """An empty tool list is the failure mode, not an edge case."""
        schema = (
            resources["TestHarnessTarget"]["Properties"]["TargetConfiguration"]
            ["Mcp"]["Lambda"]["ToolSchema"]["InlinePayload"]
        )
        assert schema, "the target must expose a tool or no client can call anything"
        assert all(t.get("Name") and t.get("InputSchema") for t in schema)


class TestInterceptorIsPreWired:
    def test_the_dispatcher_is_attached_as_a_request_interceptor(self, gateway: dict) -> None:
        """This is quickstart step 3, done by the stack."""
        (interceptor,) = gateway["InterceptorConfigurations"]
        assert interceptor["InterceptionPoints"] == ["REQUEST"], (
            "must be REQUEST: a RESPONSE interceptor cannot block a prompt in time"
        )
        arn = interceptor["Interceptor"]["Lambda"]["Arn"]
        assert arn == {"Fn::GetAtt": "DispatcherFunction.Arn"}, arn

    def test_request_headers_are_passed_to_the_interceptor(self, gateway: dict) -> None:
        """Without this the parser never sees mcp-session-id and falls back to a
        session id read from the request body, which a caller can forge."""
        (interceptor,) = gateway["InterceptorConfigurations"]
        assert interceptor["InputConfiguration"]["PassRequestHeaders"] is True

    def test_the_gateway_may_invoke_the_dispatcher(self, resources: dict) -> None:
        perm = resources["TestHarnessDispatcherPermission"]["Properties"]
        assert perm["Principal"] == "bedrock-agentcore.amazonaws.com"
        assert perm["SourceArn"] == {"Fn::GetAtt": "TestHarnessGateway.GatewayArn"}


class TestAuthAndLeastPrivilege:
    def test_inbound_auth_is_jwt_so_the_test_console_can_reach_it(self, gateway: dict) -> None:
        """AWS_IAM would be unreachable from the browser: the Test Console
        presents a bearer token and cannot sign SigV4."""
        assert gateway["AuthorizerType"] == "CUSTOM_JWT"
        assert "CustomJWTAuthorizer" in gateway["AuthorizerConfiguration"]

    def test_the_gateway_role_invokes_exactly_two_named_functions(
        self, resources: dict
    ) -> None:
        """The target and the interceptor, each named — and nothing else.

        Narrower than the BedrockAgentCoreFullAccess role AWS creates, which can
        invoke every Lambda in the account. The interceptor grant is not
        optional: a resource-based policy on the dispatcher is necessary but not
        sufficient, because the gateway invokes the interceptor under THIS role.
        Without it the gateway returns 500 and the dispatcher log stays empty,
        so the monitor looks absent rather than denied.
        """
        policies = resources["TestHarnessGatewayRole"]["Properties"]["Policies"]
        statements = [s for p in policies for s in p["PolicyDocument"]["Statement"]]
        assert statements, "the gateway role must grant something"

        granted = set()
        for statement in statements:
            assert statement["Action"] == "lambda:InvokeFunction", (
                f"unexpected action on the gateway role: {statement['Action']!r}"
            )
            resource = statement["Resource"]
            assert isinstance(resource, dict) and "Fn::GetAtt" in resource, (
                f"the gateway role must name functions by ARN, not {resource!r}"
            )
            granted.add(resource["Fn::GetAtt"])

        assert granted == {
            "TestHarnessEchoFunction.Arn",
            "DispatcherFunction.Arn",
        }, f"gateway role invokes {sorted(granted)}"

    def test_the_client_secret_is_not_a_stack_output(self, template: dict) -> None:
        """Outputs are readable by anyone who can describe the stack."""
        rendered = yaml.dump(template.get("Outputs", {}))
        assert "ClientSecret" not in rendered


class TestHarnessAgentCompletesTheChain:
    """The Harness is what makes enforcement testable.

    Without it the stack builds a gateway with nothing in front of it: there is
    no agent, therefore no runtime session, therefore StopRuntimeSession has
    nothing to terminate. Detection could be exercised; the kill could not.
    """

    def test_the_gateway_is_attached_to_the_harness_as_a_tool(self, resources: dict) -> None:
        """The Playground's Tools toggle, made declarative.

        If the gateway is not a tool of the agent, the agent answers on its own
        and no traffic ever crosses the interceptor.
        """
        (tool,) = resources["TestHarnessAgent"]["Properties"]["Tools"]
        assert tool["Type"] == "agentcore_gateway"
        gateway = tool["Config"]["AgentCoreGateway"]
        assert gateway["GatewayArn"] == {"Fn::GetAtt": "TestHarnessGateway.GatewayArn"}

    def test_the_harness_authenticates_to_a_jwt_gateway_with_oauth(self, resources: dict) -> None:
        """Harness->Gateway defaults to SigV4, which a CUSTOM_JWT gateway rejects.

        Omitting OutboundAuth here would produce a harness that cannot call the
        very gateway it is attached to.
        """
        (tool,) = resources["TestHarnessAgent"]["Properties"]["Tools"]
        oauth = tool["Config"]["AgentCoreGateway"]["OutboundAuth"]["Oauth"]
        assert oauth["ProviderArn"] == {"Fn::GetAtt": "TestHarnessOAuthProvider.CredentialProviderArn"}
        assert oauth["Scopes"] == ["vardoger-gateway/invoke"]

    def test_both_sides_use_the_same_cognito_client(self, resources: dict) -> None:
        """The gateway validates what the harness presents; a mismatch is a 401."""
        provider = resources["TestHarnessOAuthProvider"]["Properties"]
        config = provider["Oauth2ProviderConfigInput"]["CustomOauth2ProviderConfig"]
        assert config["ClientId"] == {"Ref": "TestHarnessUserPoolClient"}
        gateway_clients = (
            resources["TestHarnessGateway"]["Properties"]["AuthorizerConfiguration"]
            ["CustomJWTAuthorizer"]["AllowedClients"]
        )
        assert {"Ref": "TestHarnessUserPoolClient"} in gateway_clients

    def test_the_runtime_arn_is_published_for_the_second_pass(self, template: dict) -> None:
        """Gateway needs Dispatcher, Harness needs Gateway, Dispatcher would need
        Harness. deploy.sh breaks the cycle using this output."""
        output = template["Outputs"]["TestHarnessAgentRuntimeArn"]
        assert output["Value"] == {
            "Fn::GetAtt": "TestHarnessAgent.Environment.AgentCoreRuntimeEnvironment.AgentRuntimeArn"
        }

    def test_the_kill_grant_is_valid_before_the_runtime_exists(self, template: dict) -> None:
        """On the first pass AgentRuntimeArn is empty, and an empty string is not
        a valid policy Resource. It must fall back to an account-scoped ARN."""
        rendered = yaml.dump(template["Resources"])
        assert "HasAgentRuntimeArn" in rendered, "the fallback condition is not used"
        assert template["Parameters"]["AgentRuntimeArn"]["Default"] == ""


class TestExistingGatewayPathStillWorks:
    def test_the_gateway_arn_is_optional(self, template: dict) -> None:
        assert template["Parameters"]["ExistingGatewayArn"]["Default"] == ""

    def test_the_existing_gateway_permission_is_conditional(self, resources: dict) -> None:
        """An empty SourceArn is not a valid ARN, so this cannot be unconditional
        once the gateway ARN became optional."""
        assert resources["LambdaInvokePermission"]["Condition"] == "HasExistingGateway"


class TestHarnessRoleHasWhatAgentCoreNeeds:
    """The execution role's gaps surface only when someone uses the harness.

    CloudFormation reports CREATE_COMPLETE for a harness whose role cannot pull
    its own container, read its own memory, or fetch the OAuth token for the
    gateway hop. Three separate AccessDeniedExceptions were hit in the
    playground after a fully "successful" deploy:

        GetResourceOauth2Token on token-vault/.../vardoger-test-<stack>
        ListEvents on memory/vardoger_test_<account>-<suffix>

    and the ECR Public pull, which does not even present as access-denied — the
    session times out pulling the image.

    Action set follows the sample execution role policy in the AgentCore docs:
    docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-security.html

    A missing action here costs a full deploy-and-retry cycle, so the guard is
    worth more than the usual template assertion.
    """

    # Grouped by the failure each one causes, so a breakage names the symptom.
    REQUIRED = {
        "reading its own memory": {
            "bedrock-agentcore:CreateEvent",
            "bedrock-agentcore:GetEvent",
            "bedrock-agentcore:ListEvents",
            "bedrock-agentcore:RetrieveMemoryRecords",
        },
        "fetching the gateway OAuth token": {
            "bedrock-agentcore:GetResourceOauth2Token",
            "secretsmanager:GetSecretValue",
        },
        "minting a workload identity": {
            "bedrock-agentcore:GetWorkloadAccessToken",
        },
        "pulling its managed container": {
            "ecr-public:GetAuthorizationToken",
            "sts:GetServiceBearerToken",
        },
        "model inference": {
            "bedrock:InvokeModel",
        },
    }

    @staticmethod
    def _actions(resources: dict) -> set[str]:
        granted: set[str] = set()
        for policy in resources["TestHarnessAgentRole"]["Properties"]["Policies"]:
            for statement in policy["PolicyDocument"]["Statement"]:
                if statement.get("Effect") != "Allow":
                    continue
                action = statement.get("Action", [])
                granted.update([action] if isinstance(action, str) else action)
        return granted

    def test_every_required_action_is_granted(self, resources: dict) -> None:
        granted = self._actions(resources)
        missing = {
            reason: sorted(needed - granted)
            for reason, needed in self.REQUIRED.items()
            if needed - granted
        }
        assert not missing, (
            "TestHarnessAgentRole is missing actions the harness needs at "
            f"invoke time: {missing}. The stack will still report "
            "CREATE_COMPLETE; the failure appears in the playground."
        )

    def test_the_oauth_provider_grant_matches_the_provider_name(
        self, resources: dict
    ) -> None:
        """A grant scoped to the wrong provider name denies exactly like no grant.

        Both the resource and the policy derive the name from StackName, so they
        can drift apart silently if either is edited alone.
        """
        provider = resources["TestHarnessOAuthProvider"]["Properties"]["Name"]["Fn::Sub"]
        statements = [
            s for policy in resources["TestHarnessAgentRole"]["Properties"]["Policies"]
            for s in policy["PolicyDocument"]["Statement"]
            if s.get("Sid") == "AgentCoreOAuth2TokenVaultPerProvider"
        ]
        assert statements, "no per-provider token-vault grant on the harness role"
        resource = statements[0]["Resource"]["Fn::Sub"]
        assert resource.endswith(f"/{provider}"), (
            f"the token-vault grant ends in {resource.rsplit('/', 1)[-1]!r} but the "
            f"provider is named {provider!r}"
        )

    def test_the_memory_grant_matches_the_harness_name(self, resources: dict) -> None:
        """Memory is named after the harness plus a service-generated suffix."""
        harness = resources["TestHarnessAgent"]["Properties"]["HarnessName"]["Fn::Sub"]
        statements = [
            s for policy in resources["TestHarnessAgentRole"]["Properties"]["Policies"]
            for s in policy["PolicyDocument"]["Statement"]
            if s.get("Sid") == "AgentCoreMemory"
        ]
        assert statements, "no memory grant on the harness role"
        resource = statements[0]["Resource"]["Fn::Sub"]
        assert f"memory/{harness}-*" in resource, (
            f"memory grant {resource!r} does not cover the harness {harness!r}"
        )


class TestTheModelCanActuallyCallTools:
    """The harness does nothing but call a tool, so tool-use reliability is
    not a nice-to-have — it is the whole function.

    Amazon Nova's tool-use reliability is a documented AWS limitation, with its
    own troubleshooting page. With a Nova default the playground failed as:

        modelStreamErrorException ... Model produced invalid sequence as part
        of ToolUse

    before the gateway was reached, so the monitor under test was never
    exercised. The mitigations AWS documents (greedy decoding, higher max
    tokens) are not reachable here: bedrockModelConfig exposes only modelId,
    apiFormat and additionalParams — temperature and maxTokens are fields of
    liteLlmModelConfig, not this one.

    The model stays a parameter, so an operator can still choose Nova
    deliberately. This only governs what ships as the default.
    """

    UNRELIABLE_FOR_TOOL_USE = ("nova",)

    def test_the_default_model_is_not_one_with_known_tool_use_problems(
        self, template: dict
    ) -> None:
        model = template["Parameters"]["TestHarnessModelId"]["Default"].lower()
        bad = [name for name in self.UNRELIABLE_FOR_TOOL_USE if name in model]
        assert not bad, (
            f"the default harness model {model!r} is a {bad[0]} model, whose "
            "tool-use limitations are documented by AWS. This harness exists to "
            "exercise a tool call, so the model fails before the gateway is "
            "reached and the failure looks like a harness bug."
        )

    def test_the_system_prompt_does_not_hardcode_the_tool_name(
        self, resources: dict
    ) -> None:
        """The gateway assigns the real name, as <targetName>___<toolName>.

        Confirmed live: the target named `vardoger-echo` exposing a tool named
        `echo` is advertised to the model as `vardoger-echo___echo`. A prompt
        instructing the model to call "the echo tool" invites it to emit a name
        that does not exist, which is one documented cause of an invalid
        ToolUse sequence.
        """
        prompt = " ".join(
            block["Text"] for block in
            resources["TestHarnessAgent"]["Properties"]["SystemPrompt"]
        )
        target = resources["TestHarnessTarget"]["Properties"]["Name"]
        assert f"{target}___" not in prompt, (
            "the system prompt hardcodes a gateway-assigned tool name, which "
            "changes if the target is renamed"
        )
        assert "real name" in prompt.lower() or "whichever" in prompt.lower(), (
            "the system prompt should tell the model to use the tool it is "
            "given rather than assume a name"
        )


class TestThePublishedToolNameIsTheOneTheGatewayAccepts:
    """The output is copied straight into the Test Console, so it must be exact.

    The gateway does not advertise the bare name declared in the target's
    ToolSchema. It prefixes the target name:

        target `vardoger-echo` + tool `echo`  ->  `vardoger-echo___echo`

    Confirmed live from the harness playground's own trace. The output
    published the bare `echo`, so an operator following the stack outputs got
    an unknown-tool failure and no indication that the name was the problem.

    Derived from the template here rather than hardcoded, so renaming the
    target or the tool either propagates or fails loudly.
    """

    SEPARATOR = "___"

    @staticmethod
    def _expected(resources: dict) -> str:
        target = resources["TestHarnessTarget"]["Properties"]
        tool = target["TargetConfiguration"]["Mcp"]["Lambda"]["ToolSchema"][
            "InlinePayload"
        ][0]["Name"]
        return f"{target['Name']}{TestThePublishedToolNameIsTheOneTheGatewayAccepts.SEPARATOR}{tool}"

    def test_the_output_is_target_then_tool(self, template: dict, resources: dict) -> None:
        published = template["Outputs"]["TestHarnessToolName"]["Value"]
        assert published == self._expected(resources), (
            f"stack output publishes {published!r} but the gateway advertises "
            f"{self._expected(resources)!r}. An operator pasting the output into "
            "the Test Console gets an unknown-tool error."
        )

    def test_the_bare_tool_name_is_not_published_alone(self, template: dict) -> None:
        """The exact regression: `echo` on its own is rejected by the gateway."""
        published = template["Outputs"]["TestHarnessToolName"]["Value"]
        assert self.SEPARATOR in str(published), (
            f"{published!r} has no {self.SEPARATOR!r} prefix, so it is the bare "
            "ToolSchema name rather than the name the gateway exposes"
        )

    def test_the_docs_give_the_same_name_as_the_output(self, template: dict) -> None:
        """Two sources for one exact string; they drift silently otherwise."""
        published = template["Outputs"]["TestHarnessToolName"]["Value"]
        doc = (ROOT / "docs/test-harness.md").read_text(encoding="utf-8")
        assert f"`{published}`" in doc, (
            f"docs/test-harness.md never mentions {published!r}, the name the "
            "stack output tells operators to use"
        )
