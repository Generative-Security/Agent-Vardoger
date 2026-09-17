"""The documented teardown must name the buckets the template actually creates.

CloudFormation will not delete a bucket that still holds objects. Both of this
stack's buckets have *derived* names rather than generated ones, so a bucket
that survives a delete is not inert leftover state — the next deploy asks for a
name that already exists and the changeset fails during
`AWS::EarlyValidation::ResourceExistenceCheck`. That error names the stack, not
the bucket, so it reads as a broken template. This happened to a real operator.

The quickstart documents the buckets to empty first, by name. Rename a bucket in
the template and those `aws s3 rm` commands quietly match nothing: they exit 0,
delete no objects, and the operator hits the original trap having followed the
instructions exactly. Nothing else in the suite reads the template's bucket
names, so nothing else would notice.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra/self-hosted.yaml"
QUICKSTART = ROOT / "docs/quickstart.md"


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

# How the docs render a template pseudo-parameter in a bucket name.
_PLACEHOLDERS = {
    "${AWS::AccountId}": "<account>",
    "${AWS::Region}": "<region>",
}


@pytest.fixture(scope="module")
def bucket_names() -> dict[str, str]:
    """Logical id -> documented spelling of each bucket the template names."""
    resources = yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_Loader)["Resources"]
    names = {}
    for logical_id, body in resources.items():
        if body.get("Type") != "AWS::S3::Bucket":
            continue
        raw = body.get("Properties", {}).get("BucketName")
        if isinstance(raw, dict):
            raw = raw.get("Fn::Sub")
        if not isinstance(raw, str):
            # A generated name cannot collide, so it needs no teardown note.
            continue
        for token, rendered in _PLACEHOLDERS.items():
            raw = raw.replace(token, rendered)
        names[logical_id] = raw
    assert names, "parsed no fixed-name buckets from the template; the parse is broken"
    return names


@pytest.fixture(scope="module")
def teardown_section() -> str:
    text = QUICKSTART.read_text(encoding="utf-8")
    match = re.search(r"^### Removing the stack$(.*?)^### ", text, re.M | re.S)
    assert match, (
        "docs/quickstart.md has no '### Removing the stack' section. Teardown "
        "instructions are what keep a non-empty bucket from blocking the next "
        "deploy; if the section moved, update this test deliberately."
    )
    return match.group(1)


def test_every_fixed_name_bucket_is_named_in_the_teardown(
    bucket_names: dict[str, str], teardown_section: str
) -> None:
    """A bucket missing from the docs is one the operator will not empty."""
    missing = sorted(
        f"{logical_id} ({name})"
        for logical_id, name in bucket_names.items()
        if name not in teardown_section
    )
    assert not missing, (
        f"buckets with fixed names that the teardown section does not mention: "
        f"{missing}. Left behind non-empty, each one blocks the next deploy with "
        "a ResourceExistenceCheck failure that does not name the bucket."
    )


def test_the_teardown_actually_empties_each_bucket(
    bucket_names: dict[str, str], teardown_section: str
) -> None:
    """Naming a bucket in prose is not enough; there must be a command for it.

    The whole point is that `delete-stack` leaves a non-empty bucket standing,
    so a section that lists the buckets without emptying them documents the
    trap instead of avoiding it.
    """
    emptied = set(re.findall(r"aws s3 rm \"s3://([^\"]+)\"", teardown_section))
    # The shell snippet uses ${ACCOUNT} / ${REGION}; map those onto the doc spelling.
    emptied = {
        name.replace("${ACCOUNT}", "<account>").replace("${REGION}", "<region>")
        for name in emptied
    }
    uncleaned = sorted(set(bucket_names.values()) - emptied)
    assert not uncleaned, (
        f"named in the teardown section but never emptied: {uncleaned}. "
        "`aws cloudformation delete-stack` will leave these behind."
    )


def test_the_recursive_flag_is_present(teardown_section: str) -> None:
    """`aws s3 rm` without --recursive deletes nothing and still exits 0.

    That failure is invisible: the command succeeds, the bucket stays full, and
    the delete fails later for a reason that points somewhere else entirely.
    """
    for line in teardown_section.splitlines():
        if "aws s3 rm" in line:
            assert "--recursive" in line, f"deletes nothing and exits 0: {line.strip()}"
