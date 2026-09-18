"""Guards for the stack-built Tier 2 model endpoint.

Three properties, each of which fails quietly if broken:

1. The IAM grant names the endpoint by a derived string rather than a !Ref,
   because the grant is written before the endpoint exists. Derived names that
   drift apart deny on every invoke, and the deploy still succeeds.
2. The Hugging Face token is NoEcho. It is a real credential and CloudFormation
   will otherwise echo it in console and describe-stacks output.
3. The endpoint is serverless. Nothing schedules the keep-alive, so a real-time
   endpoint bills around the clock for a model invoked only when prompts arrive
   -- a mistake nobody notices until the bill does.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

TEMPLATE = Path(__file__).resolve().parents[2] / "infra" / "self-hosted.yaml"


class _Loader(yaml.SafeLoader):
    pass


for _tag in ("Ref", "Sub", "GetAtt", "If", "Or", "Not", "Equals", "And", "Join",
             "Select", "Split", "FindInMap", "ImportValue", "Base64", "Condition"):
    _Loader.add_constructor("!" + _tag, lambda loader, node: None)


@pytest.fixture(scope="module")
def raw() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def template() -> dict:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_Loader)


def test_the_endpoint_resources_exist_and_are_conditioned(template: dict) -> None:
    resources = template["Resources"]
    for name, kind in [
        ("Tier2Model", "AWS::SageMaker::Model"),
        ("Tier2ModelEndpointConfig", "AWS::SageMaker::EndpointConfig"),
        ("Tier2ModelEndpoint", "AWS::SageMaker::Endpoint"),
        ("Tier2ModelRole", "AWS::IAM::Role"),
    ]:
        assert name in resources, f"{name} is missing"
        assert resources[name]["Type"] == kind
        assert resources[name].get("Condition") == "DeployTier2ModelEndpoint", (
            f"{name} must be conditioned, or it deploys for everyone"
        )


def test_iam_grant_and_endpoint_agree_on_the_name(raw: str) -> None:
    """A derived name appears twice; if the two drift, every invoke denies."""
    grant = re.search(
        r'Resource: !If\s*\n\s*- DeployTier2ModelEndpoint\s*\n\s*- !Sub "([^"]+)"',
        raw,
    )
    assert grant, "the conditioned SageMaker IAM grant is no longer recognisable"
    granted = grant.group(1).rsplit("endpoint/", 1)[-1]

    named = re.search(r'EndpointName: !Sub "([^"]+)"', raw)
    assert named, "Tier2ModelEndpoint no longer sets a derived EndpointName"

    assert granted == named.group(1), (
        f"IAM grants endpoint/{granted!r} but the endpoint is named "
        f"{named.group(1)!r}; Tier 2 would be denied on every invoke"
    )


def test_hugging_face_token_is_noecho(template: dict) -> None:
    param = template["Parameters"]["HuggingFaceToken"]
    assert param.get("NoEcho") is True, "the HF token would be echoed in stack output"
    assert param.get("Default") == "", "the token must default to empty, not a value"


def test_endpoint_is_serverless_not_real_time(template: dict) -> None:
    variants = template["Resources"]["Tier2ModelEndpointConfig"]["Properties"]["ProductionVariants"]
    assert len(variants) == 1
    variant = variants[0]
    assert "ServerlessConfig" in variant, (
        "the Tier 2 endpoint must be serverless -- nothing schedules the "
        "keep-alive, so a real-time endpoint bills while idle"
    )
    for field in ("InstanceType", "InitialInstanceCount"):
        assert field not in variant, f"{field} makes this a real-time endpoint"


def test_model_serves_the_task_the_handler_expects(template: dict) -> None:
    """_invoke_ml posts {"inputs": ...} and reads [{"label","score"}]."""
    env = template["Resources"]["Tier2Model"]["Properties"]["PrimaryContainer"]["Environment"]
    assert env["HF_TASK"] == "text-classification"


def test_default_model_is_ungated(template: dict) -> None:
    """The default must work with no token, or the one-flag path is a lie."""
    default = template["Parameters"]["Tier2ModelId"]["Default"]
    assert not default.startswith("meta-llama/"), (
        f"{default} is gated; it cannot be the default for a path documented as "
        "working on first run with no Hugging Face token"
    )
