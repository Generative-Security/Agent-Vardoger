"""The kill grant must land on the runtime that can actually be stopped.

`VARDOGER_NEW_HARNESS` and `VARDOGER_DEMO_RUNTIME` are independent flags, so one
deploy can build both. deploy.sh resolves an effective runtime ARN for the
`AgentRuntimeArn` parameter, which is what scopes the StopRuntimeSession grant.

Its comment promises the demo runtime wins, and for a real reason: AgentCore
refuses StopRuntimeSession on a harness-managed runtime, so scoping the grant to
the harness makes enforcement undemonstrable. The harness block ran second and
overwrote the demo ARN, doing exactly that -- while the summary printed both
ARNs, so nothing looked wrong.

This asserts the ordering property directly rather than the wording, so a
rewrite that keeps the behaviour still passes and a rewrite that loses it fails.
"""
from __future__ import annotations

import re
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[2] / "scripts" / "deploy.sh"


def _script() -> str:
    return DEPLOY.read_text(encoding="utf-8")


def _assignments(text: str) -> list[int]:
    return [m.start() for m in re.finditer(r"^\s*AGENT_RUNTIME_ARN_EFFECTIVE=", text, re.M)]


def test_both_modes_assign_the_effective_arn() -> None:
    """Sanity: the two branches this test reasons about still exist."""
    text = _script()
    assert 'AGENT_RUNTIME_ARN_EFFECTIVE="$DEMO_RUNTIME_ARN"' in text
    assert 'AGENT_RUNTIME_ARN_EFFECTIVE="$HARNESS_RUNTIME_ARN"' in text


def test_harness_assignment_is_guarded_against_the_demo_runtime() -> None:
    """The later assignment must not unconditionally clobber the earlier one."""
    text = _script()
    demo_at = text.index('AGENT_RUNTIME_ARN_EFFECTIVE="$DEMO_RUNTIME_ARN"')
    harness_at = text.index('AGENT_RUNTIME_ARN_EFFECTIVE="$HARNESS_RUNTIME_ARN"')

    if harness_at < demo_at:
        # Reordered so the demo assignment wins by position. Acceptable.
        return

    # The harness assignment comes later, so it MUST be conditioned on the demo
    # runtime being absent, or it silently overwrites the killable ARN.
    window = text[text.rindex("if ", 0, harness_at):harness_at]
    assert "DEMO_RUNTIME" in window, (
        "the harness runtime ARN is assigned after the demo runtime ARN without "
        "testing DEMO_RUNTIME, so deploying both scopes the StopRuntimeSession "
        "grant to the harness runtime -- the one AgentCore refuses to stop"
    )


def test_the_comment_still_matches_the_code() -> None:
    """The promise is load-bearing; if it is dropped, the guard above loses its rationale."""
    text = _script()
    assert "demo runtime takes precedence" in text, (
        "deploy.sh no longer states which runtime wins when both are deployed"
    )
