"""Names AWS reserves, which only AWS rejects — at stack-creation time.

`cfn-lint` validates that a property has the right *shape*. It cannot know that
a particular string is reserved, so a reserved value is a valid template that
fails in CloudFormation after packaging, upload and several minutes of stack
creation, leaving a rolled-back stack behind.

This shipped once. `AWS::BedrockAgentCore::HarnessEndpoint` was declared with
`EndpointName: DEFAULT` on the reasoning that a harness needs an endpoint. It
does — but AgentCore creates the `DEFAULT` one itself, always pointing at the
latest version, which is exactly why the name is reserved:

    Endpoint name 'DEFAULT' is reserved. Use a different name.
    (Service: Bedrock AgentCore Control; Operation: CreateHarnessEndpoint)

The resource was redundant rather than misconfigured, so the fix was to delete
it. This test keeps it deleted, and catches the same mistake on a named
endpoint added later.

Also guards the documented resource count, which had already drifted to
"fourteen" and "all ten" in the same file describing the same set.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra/self-hosted.yaml"
HARNESS_DOC = ROOT / "docs/test-harness.md"

# Endpoint names AgentCore owns. DEFAULT is created automatically for every
# harness and every runtime; declaring it is rejected outright.
RESERVED_ENDPOINT_NAMES = {"DEFAULT"}

_NUMBER_WORDS = {
    "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20,
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


@pytest.fixture(scope="module")
def resources() -> dict[str, dict]:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_Loader)["Resources"]


def test_no_endpoint_claims_a_reserved_name(resources: dict[str, dict]) -> None:
    """A reserved name is a valid string, so only AWS says no — after the wait."""
    offenders = []
    for logical_id, body in resources.items():
        if not str(body.get("Type", "")).endswith("Endpoint"):
            continue
        name = body.get("Properties", {}).get("EndpointName")
        if isinstance(name, str) and name.strip().upper() in RESERVED_ENDPOINT_NAMES:
            offenders.append(f"{logical_id} ({body['Type']}) -> {name!r}")
    assert not offenders, (
        f"endpoint resources claiming a name AgentCore reserves: {offenders}. "
        "AgentCore creates DEFAULT itself; declaring it fails stack creation with "
        "\"Endpoint name 'DEFAULT' is reserved\". If the resource exists only to "
        "provide DEFAULT, delete it — the endpoint is created either way."
    )


def test_the_harness_resource_count_in_the_docs_is_right(resources: dict[str, dict]) -> None:
    """The doc enumerates these resources; a stale count means a stale table.

    Both numbers in docs/test-harness.md ("Fourteen resources" and "removes all
    ten") described the same set and disagreed with each other, so neither was
    load-bearing enough for anyone to notice when it drifted.
    """
    actual = sum(1 for body in resources.values()
                 if body.get("Condition") == "DeployTestHarness")
    text = HARNESS_DOC.read_text(encoding="utf-8")

    claims = {
        word: value for word, value in _NUMBER_WORDS.items()
        if re.search(rf"\b{word}\b", text, re.I)
    }
    assert claims, (
        "docs/test-harness.md states no resource count. If the wording changed, "
        "update this test deliberately rather than dropping the guard."
    )
    wrong = {word: value for word, value in claims.items() if value != actual}
    assert not wrong, (
        f"the template gates {actual} resources on DeployTestHarness, but "
        f"docs/test-harness.md says {sorted(wrong)}. Update the prose AND the "
        "table that enumerates them."
    )


def test_every_gated_resource_appears_in_the_doc_table(resources: dict[str, dict]) -> None:
    """A resource missing from the table is one nobody knows the stack creates."""
    text = HARNESS_DOC.read_text(encoding="utf-8")
    missing = sorted(
        logical_id for logical_id, body in resources.items()
        if body.get("Condition") == "DeployTestHarness" and f"`{logical_id}`" not in text
    )
    assert not missing, f"created by the harness but undocumented: {missing}"


def test_the_doc_table_lists_nothing_the_template_does_not_create(
    resources: dict[str, dict],
) -> None:
    """The inverse: a row left behind after a resource is deleted.

    Exactly what happened with TestHarnessAgentEndpoint — had the row survived,
    the doc would promise a resource the stack no longer creates.
    """
    text = HARNESS_DOC.read_text(encoding="utf-8")
    documented = set(re.findall(r"^\| `(TestHarness[A-Za-z0-9]+)`", text, re.M))
    assert documented, "parsed no resource rows from the doc table; the regex is broken"
    phantom = sorted(documented - set(resources))
    assert not phantom, f"documented but not in the template: {phantom}"
