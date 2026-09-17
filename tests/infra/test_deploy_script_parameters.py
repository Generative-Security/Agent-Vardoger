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
