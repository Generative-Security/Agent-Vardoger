"""A handler that writes DynamoDB must have permission to.

This shipped twice in one project. The most recent: `record_kill_outcome` was
added to the alert Lambda, whose role had no DynamoDB permissions at all. The
kill itself succeeded —

    Session terminated: runtime_session_id=test-console-1af5c678-...

— but the write-back was denied, so the session registry kept `kill_outcome:
"deferred"` forever. A successful kill and one still in flight became
indistinguishable, which is the exact ambiguity that recording the outcome
exists to remove.

It fails quietly by design: the write is best-effort and reports degraded
rather than raising, because bookkeeping must never undo enforcement. That is
the right behaviour and it is also why nothing surfaced.

The check pairs each Lambda's handler module against its role by reading both
out of the template, so adding a registry write to a handler whose role cannot
write is caught here rather than in production.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra/self-hosted.yaml"

# Functions in adapters.agentcore.session_registry that write.
REGISTRY_WRITERS = (
    "record_kill_outcome",
    "record_session_evaluation",
    "mark_session_decision",
    "ensure_session",
    "update_session_risk",
    "record_detection_event",
)
WRITE_ACTIONS = {"dynamodb:UpdateItem", "dynamodb:PutItem"}


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
def resources() -> dict:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_Loader)["Resources"]


def _handler_source(body: dict) -> Path | None:
    """Locate the Python module behind a Lambda's Handler property."""
    handler = body.get("Properties", {}).get("Handler", "")
    # Inline ZipFile handlers (index.lambda_handler) have no module on disk.
    if not handler or handler.startswith("index."):
        return None
    module = ROOT / (handler.rsplit(".", 1)[0].replace(".", "/") + ".py")
    return module if module.exists() else None


def _granted_actions(resources: dict, body: dict) -> set[str]:
    role_ref = body["Properties"]["Role"]
    role_name = role_ref["Fn::GetAtt"].split(".")[0]
    actions: set[str] = set()
    for policy in resources[role_name]["Properties"].get("Policies", []):
        for statement in policy["PolicyDocument"]["Statement"]:
            action = statement.get("Action", [])
            actions.update([action] if isinstance(action, str) else action)
    return actions


def _lambdas_with_source(resources: dict) -> list[tuple[str, dict, Path]]:
    found = []
    for name, body in resources.items():
        if body.get("Type") != "AWS::Lambda::Function":
            continue
        source = _handler_source(body)
        if source:
            found.append((name, body, source))
    return found


def test_the_scan_finds_the_handlers(resources: dict) -> None:
    """If this drops to zero the checks below pass vacuously."""
    found = _lambdas_with_source(resources)
    assert len(found) >= 4, (
        f"only matched {len(found)} Lambda handlers to source files; the "
        "Handler-to-module mapping is probably broken"
    )


def test_every_handler_that_writes_the_registry_may_write_it(resources: dict) -> None:
    offenders = []
    for name, body, source in _lambdas_with_source(resources):
        src = source.read_text(encoding="utf-8")
        writes = [w for w in REGISTRY_WRITERS if re.search(rf"\b{w}\s*\(", src)]
        if not writes:
            continue
        if not (_granted_actions(resources, body) & WRITE_ACTIONS):
            offenders.append(f"{name} calls {sorted(writes)} but its role grants no write")
    assert not offenders, (
        f"handlers whose DynamoDB writes would be denied: {offenders}. The write "
        "is best-effort and reports degraded rather than raising, so this fails "
        "silently and the record simply never appears."
    )


def test_the_alert_lambda_can_record_the_kill_outcome(resources: dict) -> None:
    """Named explicitly: this is the one that shipped broken, and the generic
    check above would pass if the call were quietly removed instead."""
    alert = resources["AlertFunction"]
    source = _handler_source(alert)
    assert source and "record_kill_outcome(" in source.read_text(encoding="utf-8"), (
        "the alert Lambda no longer records the kill outcome, so the session "
        "registry keeps 'deferred' after a successful kill"
    )
    assert "dynamodb:UpdateItem" in _granted_actions(resources, alert)
