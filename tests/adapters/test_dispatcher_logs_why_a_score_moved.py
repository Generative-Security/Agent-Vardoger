"""The decision log must explain a score, not just state it.

The line reported decision, risk and matched signatures. It did not report
`risk_signals`, so the contributions that produced the number were computed and
discarded -- including the point an unverified session identity now carries.
Two identical prompts could score differently with nothing in any log, table or
metric to say why, which is the failure mode this product exists to prevent,
turned inward.

The field is `risk_signals=`, not `signals=`, because `signatures=` is already
on the same line and the two would be a glance apart when someone is reading a
log at speed.
"""
from __future__ import annotations

import ast
from pathlib import Path

DISPATCHER = Path(__file__).resolve().parents[2] / "adapters" / "agentcore" / "dispatcher.py"


def _log_call() -> str:
    source = DISPATCHER.read_text(encoding="utf-8")
    start = source.index('"Evaluated prompt:')
    return source[start:source.index("\n        )", start)]


def _evaluated_prompt_call() -> ast.Call:
    tree = ast.parse(DISPATCHER.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str) \
                and first.value.startswith("Evaluated prompt:"):
            return node
    raise AssertionError("the Evaluated prompt log call was not found")


def test_the_decision_line_reports_risk_signals() -> None:
    call = _log_call()
    assert "risk_signals=%s" in call, (
        "the evaluation log no longer explains what contributed to the score"
    )
    assert "result.risk_signals" in call, "the format placeholder has no argument"


def test_signals_are_not_confusable_with_signatures() -> None:
    call = _log_call()
    assert "signatures=%s" in call, "the signature field was removed"
    assert " signals=%s" not in call, (
        "a bare `signals=` sits one glance from `signatures=` on the same line"
    )


def test_placeholders_and_arguments_stay_balanced() -> None:
    """A mismatched %s count raises at log time, on the request path.

    Parsed rather than pattern-matched: counting arguments by splitting on
    commas miscounts the moment a comment or a sliced subscript appears, which
    is exactly what happened on the first attempt at this test.
    """
    node = _evaluated_prompt_call()
    fmt = node.args[0].value
    assert fmt.count("%s") == len(node.args) - 1, (
        f"{fmt.count('%s')} placeholders but {len(node.args) - 1} arguments; "
        "logging would raise on the request path"
    )


def test_the_signal_list_is_bounded() -> None:
    """An unbounded list would let a crafted prompt choose how much we log."""
    assert "result.risk_signals[:" in _log_call(), (
        "risk_signals must be sliced; an attacker deciding our log volume is a "
        "cost problem at best"
    )
