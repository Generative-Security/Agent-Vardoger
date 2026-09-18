"""``deploy.sh`` must stay in agreement with the CloudFormation template.

The deploy script is a second, hand-maintained copy of the template's parameter
surface, and the two drift silently. Nothing fails, nothing warns — you simply
get a stack configured differently from what you asked for.

Three failures this guards, all of which have a plausible path into the repo:

1. **A parameter passed on the first deploy pass but not the second.**
   ``deploy.sh`` runs ``aws cloudformation deploy`` twice: once to create the
   stack, then again to fold in the CloudFront origin for CORS. The second pass
   re-supplies parameters, so anything omitted there reverts to the template
   default *immediately after* the first pass set it. Setting
   ``Tier3Enabled=true`` and getting ``false`` is invisible until you go looking
   at the stack.

2. **A shell default that disagrees with the template default.** The script
   defaults each value to the template's own default so an unset environment
   variable is a no-op. That creates two sources of truth for the same number;
   if the template default changes and the script does not, an operator who
   changed nothing silently gets the old behaviour.

3. **A parameter name that does not exist in the template.** A typo makes the
   whole deploy fail at the AWS call — late, after packaging and upload.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOY_SH = ROOT / "scripts/deploy.sh"
TEMPLATE = ROOT / "infra/self-hosted.yaml"

# The CloudFront domain does not exist during the first pass, so the callback
# URL genuinely cannot be supplied until the second. This is the ONLY legitimate
# asymmetry between the two parameter lists.
SECOND_PASS_ONLY = {"CognitoCallbackUrls"}


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
def template_params() -> dict[str, dict]:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_Loader)["Parameters"]


@pytest.fixture(scope="module")
def script() -> str:
    return DEPLOY_SH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def deploy_passes(script: str) -> list[str]:
    """Split the script into its two ``aws cloudformation deploy`` invocations.

    Matched on a line START so the prose comment above them, which quotes the
    same command, is not mistaken for a third invocation.
    """
    lines = script.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip().startswith("aws cloudformation deploy")]
    assert len(starts) == 2, (
        f"expected exactly 2 deploy invocations, found {len(starts)}. "
        "If a pass was added or removed, update this test deliberately — the "
        "parameter-symmetry check below depends on knowing how many there are."
    )
    return ["\n".join(lines[starts[0]:starts[1]]), "\n".join(lines[starts[1]:])]


_PARAM_ARG = re.compile(r'^\s+"([A-Za-z0-9]+)=', re.M)
# NAME="${VARDOGER_SOMETHING:-default}"  — the env var name does not always
# match the shell variable name (VARDOGER_ML_ENDPOINT feeds TIER2_ENDPOINT).
_SHELL_DEFAULT = re.compile(r'^([A-Z0-9_]+)="\$\{VARDOGER_[A-Z0-9_]+:-([^}]*)\}"', re.M)
_PARAM_TO_SHELL_VAR = re.compile(r'^\s+"([A-Za-z0-9]+)=\$([A-Z0-9_]+)"', re.M)


def test_both_deploy_passes_carry_the_same_parameters(deploy_passes: list[str]) -> None:
    """A parameter set on pass 1 and omitted on pass 2 is reset to its default."""
    first, second = (set(_PARAM_ARG.findall(p)) for p in deploy_passes)
    assert first, "parsed no parameters from the first deploy pass; the regex is broken"

    dropped = sorted(first - second)
    assert not dropped, (
        f"passed on the first deploy pass but not the second: {dropped}. "
        "The second pass re-supplies parameters, so these silently revert to "
        "their template defaults right after the first pass set them."
    )

    added = sorted(second - first - SECOND_PASS_ONLY)
    assert not added, (
        f"passed only on the second deploy pass: {added}. If that is "
        "deliberate (the value cannot exist until the stack does), add it to "
        "SECOND_PASS_ONLY with the reason."
    )


def test_every_parameter_deploy_sh_passes_exists_in_the_template(
    deploy_passes: list[str], template_params: dict[str, dict]
) -> None:
    """A typo'd parameter name fails the deploy late, after packaging and upload."""
    passed = set().union(*(set(_PARAM_ARG.findall(p)) for p in deploy_passes))
    unknown = sorted(passed - set(template_params))
    assert not unknown, (
        f"deploy.sh passes parameters the template does not define: {unknown}"
    )


def test_shell_defaults_match_template_defaults(
    script: str, deploy_passes: list[str], template_params: dict[str, dict]
) -> None:
    """The script defaults each value to the template's own default.

    That is what makes an unset VARDOGER_* variable a no-op. Two sources of
    truth for one default drift silently, and the operator who changed nothing
    is the one who gets surprised.
    """
    shell_defaults = dict(_SHELL_DEFAULT.findall(script))
    assert shell_defaults, "parsed no shell defaults from deploy.sh; the regex is broken"

    param_to_var: dict[str, str] = {}
    for pass_text in deploy_passes:
        for param, var in _PARAM_TO_SHELL_VAR.findall(pass_text):
            param_to_var.setdefault(param, var)

    mismatches = []
    checked = 0
    for param, var in sorted(param_to_var.items()):
        if var not in shell_defaults:
            continue  # computed at runtime (ARNs, bucket names, CORS origins)
        shell_value = shell_defaults[var]
        template_value = str(template_params.get(param, {}).get("Default", ""))
        checked += 1
        if shell_value != template_value:
            mismatches.append(f"{param}: deploy.sh={shell_value!r} template={template_value!r}")

    assert checked >= 6, f"only cross-checked {checked} defaults; the parse is probably wrong"
    assert not mismatches, "deploy.sh defaults disagree with the template:\n  " + "\n  ".join(mismatches)


def test_enforcement_posture_is_settable_from_the_deploy_script(deploy_passes: list[str]) -> None:
    """The settings that decide what the system DOES must not require editing YAML.

    These are the parameters an operator is most likely to want to change, and
    each one was unreachable from deploy.sh at some point.
    """
    passed = set().union(*(set(_PARAM_ARG.findall(p)) for p in deploy_passes))
    posture = {
        "Tier1Mode",
        "DetectionFailurePolicy",
        "Tier2MlEndpoint",
        "Tier3Enabled",
        "GlobalKillEnabled",
        "Tier2KillEnabled",
        "Tier3KillEnabled",
        "AuthMode",
    }
    missing = sorted(posture - passed)
    assert not missing, (
        f"deploy.sh cannot set: {missing}. An operator would have to edit the "
        "template to change what the system does."
    )


# Variables deploy.sh reads from the environment rather than assigning. Each is
# an operator input documented in docs/quickstart.md, or set by the shell.
_ENVIRONMENT_INPUTS = {
    "AWS_REGION", "HOME", "PATH", "SKIP_FRONTEND",
    "VARDOGER_GATEWAY_ARN", "VARDOGER_AGENT_RUNTIME_ARN", "VARDOGER_ALERT_EMAIL",
    "VARDOGER_ML_ENDPOINT", "VARDOGER_AUTH_MODE", "VARDOGER_AUTH_SECRET",
    "VARDOGER_TIER1_MODE", "VARDOGER_DETECTION_FAILURE_POLICY",
    "VARDOGER_LOG_LEVEL",
    "VARDOGER_DEMO_RUNTIME",
    # Tier 2 model endpoint built by the stack. VARDOGER_HF_TOKEN is only
    # needed for gated models such as Llama Prompt Guard 2.
    "VARDOGER_TIER2_MODEL", "VARDOGER_TIER2_MODEL_ID", "VARDOGER_HF_TOKEN",
    "VARDOGER_TIER2_KILL_ENABLED", "VARDOGER_TIER3_ENABLED",
    "VARDOGER_TIER3_KILL_ENABLED", "VARDOGER_GLOBAL_KILL_ENABLED",
    "VARDOGER_NEW_HARNESS", "VARDOGER_PREMIUM_SIGNATURE_BUCKET",
    "VARDOGER_PREMIUM_SIGNATURE_PREFIX", "VARDOGER_PREMIUM_SIGNATURE_ROLE_ARN",
    # Passed to the frontend build, not expanded by the script itself.
    "VITE_API_BASE_URL", "VITE_AUTH_MODE", "VITE_COGNITO_DOMAIN",
    "VITE_COGNITO_CLIENT_ID", "VITE_COGNITO_REDIRECT_URI",
    # Printed inside an escaped echo as instructions for the operator to run.
    "SECRET",
}


def test_no_variable_is_expanded_without_being_assigned(script: str) -> None:
    """deploy.sh runs under `set -u`, so an unassigned variable aborts the deploy.

    This shipped once: a half-applied edit left AGENT_RUNTIME_ARN_EFFECTIVE
    referenced on both CloudFormation passes and assigned nowhere, and the
    deploy died at step 4 with "unbound variable". Nothing else in the suite
    would have caught it — the parameter lists were symmetric and the defaults
    agreed; the variable holding them simply did not exist.

    Known limitation: this is a text scan, not control-flow analysis. A variable
    assigned ONLY inside a conditional branch counts as assigned here, yet is
    still unbound at runtime when that branch does not run. Assign at top level
    and let a branch overwrite, which is what the script does.
    """
    expanded = set(re.findall(r"\$\{?([A-Z_][A-Z0-9_]*)", script))
    assigned = set(re.findall(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)=", script, re.M))
    assigned |= set(re.findall(r"^\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in", script, re.M))
    # `for _tool in ...` is captured as "_" by the uppercase-anchored pattern.
    assigned.add("_")

    unassigned = sorted(expanded - assigned - _ENVIRONMENT_INPUTS)
    assert not unassigned, (
        f"expanded but never assigned: {unassigned}. Under `set -u` each of these "
        "aborts the deploy. If it is an operator input, add it to "
        "_ENVIRONMENT_INPUTS and document it in the quickstart appendix."
    )


class TestTheHarnessSummaryPrintsUsableValues:
    """deploy.sh's closing summary is what an operator copies from.

    Both values it printed for the test harness were wrong at once: a tool name
    hardcoded to `echo` when the gateway advertises `vardoger-echo___echo`, and
    a gateway URL with `/mcp` appended to a value that already ended in `/mcp`,
    producing `/mcp/mcp`. Neither is caught by anything else — the summary is
    plain `echo` output, so it cannot drift "loudly".
    """

    def test_the_tool_name_is_read_from_the_stack_output(self, script: str) -> None:
        """Not hardcoded — the gateway assigns it, and it changes on rename."""
        assert "TestHarnessToolName" in script, (
            "deploy.sh does not read the TestHarnessToolName output, so it is "
            "printing a literal that cannot track the gateway's actual tool name"
        )
        summary = script[script.index("=== Test harness ==="):]
        assert "with tool name  echo\"" not in summary, (
            "deploy.sh still prints the bare tool name `echo`, which the gateway "
            "rejects as unknown"
        )

    def test_the_gateway_url_does_not_get_a_second_mcp_path(self, script: str) -> None:
        """TestHarnessGatewayUrl already ends in /mcp."""
        summary = script[script.index("=== Test harness ==="):]
        assert "${TH_URL%/}/mcp" not in summary and "$TH_URL/mcp" not in summary, (
            "deploy.sh appends /mcp to a gateway URL that already ends in /mcp, "
            "printing a /mcp/mcp endpoint that 404s"
        )


class TestNoTempDirectoryIsUsedAfterItIsRemoved:
    """A build directory outlives nothing. Using one after `rm -rf` fails at
    run time only, and only in the mode that reaches that line.

    This shipped: the demo agent packaging landed one line after
    `rm -rf "$BUILD_DIR"` and wrote into the deleted directory —

        FileNotFoundError: '/tmp/tmp.0v9xBy6ps5/demo-agent.zip'

    — which nothing caught, because the zip logic had been tested in isolation
    and its PLACEMENT in the script had not. Sharing the directory was the real
    error: its lifetime belongs to the Lambda build, so anything else depending
    on it is one reordering away from breaking.
    """

    @staticmethod
    def _removal_points(script: str) -> dict[str, int]:
        return {
            var: script.index(f'rm -rf "${{{var}}}"')
            for var in re.findall(r'rm -rf "\$\{?([A-Z_][A-Z0-9_]*)\}?"', script)
            if f'rm -rf "${{{var}}}"' in script
        }

    def test_no_variable_is_referenced_after_its_directory_is_removed(
        self, script: str
    ) -> None:
        offenders = []
        for var, removed_at in self._removal_points(script).items():
            tail = script[removed_at + 1:]
            # A later re-assignment starts a fresh lifetime, which is fine.
            if re.search(rf'^{var}=\$\(mktemp', tail, re.M):
                continue
            for match in re.finditer(rf'\$\{{?{var}\}}?/', tail):
                line = tail[:match.start()].count("\n") + 1
                offenders.append(f"{var} used {line} lines after its rm -rf")
        assert not offenders, (
            f"temp directories used after removal: {offenders}. The reference "
            "resolves to a path that no longer exists, and only at run time, in "
            "whichever mode reaches that line."
        )

    def test_the_demo_agent_builds_in_its_own_directory(self, script: str) -> None:
        """Explicit, because the generic check above would also pass if the
        demo packaging were simply moved earlier — which would work today and
        break again on the next reordering."""
        assert "DEMO_BUILD_DIR=$(mktemp -d)" in script
        assert "$BUILD_DIR/demo-agent.zip" not in script

    def test_every_temp_directory_is_cleaned_up(self, script: str) -> None:
        # Leading whitespace matters: the demo agent's directory is created
        # inside an `if`, so anchoring at ^ silently excluded it and this guard
        # passed while the cleanup was missing.
        created = set(re.findall(r'^\s*([A-Z_][A-Z0-9_]*)=\$\(mktemp -d\)', script, re.M))
        removed = set(re.findall(r'rm -rf "\$\{?([A-Z_][A-Z0-9_]*)\}?"', script))
        leaked = sorted(created - removed)
        assert not leaked, f"temp directories never removed: {leaked}"


class TestSwitchingIntoTokenModeIssuesAUsableSecret:
    """A retained secret is only useful if somebody has it.

    "Do not rotate on update" is correct for token -> token: rotating on every
    redeploy would lock an operator out of a console they were using.

    It is wrong coming from any other mode. The retained AuthSecret is then
    whatever some earlier deploy generated, and the parameter is NoEcho, so it
    cannot be read back from the stack by anyone. Going cognito -> token
    therefore produced a console protected by a credential that exists and that
    nobody holds — no error, no output, just a locked door.
    """

    def test_the_previous_auth_mode_is_read_before_deciding(self, script: str) -> None:
        """The two cases are indistinguishable without it."""
        assert "PREVIOUS_AUTH_MODE" in script, (
            "deploy.sh cannot tell a token->token redeploy from a switch into "
            "token mode, so it reuses a secret nobody has"
        )
        assert "ParameterKey=='AuthMode'" in script

    def test_the_secret_is_reused_only_when_already_in_token_mode(
        self, script: str
    ) -> None:
        reuse = script[script.index("AUTH_SECRET_USE_PREVIOUS=1") - 300:]
        assert '"$PREVIOUS_AUTH_MODE" = "token"' in reuse[:300], (
            "the secret is reused on any update, including switches into token "
            "mode where the retained value is unknowable"
        )

    def test_a_switch_into_token_mode_explains_the_new_secret(
        self, script: str
    ) -> None:
        """Otherwise it reads as an unexplained rotation."""
        assert "Switched from $PREVIOUS_AUTH_MODE to token auth" in script

    def test_the_secret_is_still_never_printed_when_reused(self, script: str) -> None:
        """A genuine token->token redeploy must not echo the credential; there
        is no reason to put it on a terminal again."""
        start = script.index('elif [ "$AUTH_SECRET_USE_PREVIOUS" = "1" ]')
        branch = script[script.index("then", start):][:400]
        #  alone is not enough: $AUTH_SECRET_USE_PREVIOUS starts with the
        # same characters, so the negative lookahead is what makes this mean
        # "the secret itself" rather than "any variable named like it".
        leaked = re.search(r"\$AUTH_SECRET(?![A-Z_])", branch)
        assert not leaked, (
            f"the retained secret is echoed on a plain redeploy: "
            f"{branch[max(0, leaked.start() - 60):leaked.end() + 20]!r}"
        )
