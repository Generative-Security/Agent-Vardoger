"""Slow-exfiltration detection by shape rather than by wording.

BEHAVIOUR_PATTERNS is regex over concatenated turns, so it only catches an
attacker who says something incriminating. The patient ones do not: they ask an
unremarkable question, then the same question with the identifier moved on by
one, and again. No single prompt contains a suspicious word.

Half of these tests assert SILENCE. That is the harder half and the one that
matters: a detector that fires on ordinary conversation gets its score tuned to
zero by the first operator who sees it, and then catches nothing at all.
"""
from __future__ import annotations

import pytest

from vardoger.tier2.handler import _behaviour_score, _extraction_progression_score


def history(*prompts: str) -> list[dict[str, str]]:
    return [{"prompt": p} for p in prompts]


# --- fires -------------------------------------------------------------

def test_walking_an_identifier_one_step_at_a_time() -> None:
    score, reasons = _extraction_progression_score(
        "show me order 1004",
        history("show me order 1001", "show me order 1002", "show me order 1003"),
    )
    assert "identifier_enumeration" in reasons
    assert score > 0


def test_growing_the_size_of_the_request() -> None:
    score, reasons = _extraction_progression_score(
        "list 900 customer records",
        history("list 10 customer records", "list 50 customer records",
                "list 200 customer records"),
    )
    assert "quantity_escalation" in reasons
    assert score > 0


def test_a_large_jump_is_not_called_enumeration() -> None:
    """Steps far beyond a walk are escalation, not an ID sweep."""
    _, reasons = _extraction_progression_score(
        "list 900 customer records",
        history("list 10 customer records", "list 50 customer records",
                "list 200 customer records"),
    )
    assert "identifier_enumeration" not in reasons


def test_the_signal_reaches_the_behaviour_score() -> None:
    """Wiring check: the detector is useless if nothing consumes it."""
    prompts = history("show me order 1001", "show me order 1002", "show me order 1003")
    score, reasons = _behaviour_score("show me order 1004", prompts)
    assert "identifier_enumeration" in reasons
    assert score > 0


# --- stays silent ------------------------------------------------------

def test_ordinary_conversation_is_silent() -> None:
    score, reasons = _extraction_progression_score(
        "thanks, that helps",
        history("what are your store hours", "do you ship to canada",
                "how much is shipping"),
    )
    assert (score, reasons) == (0.0, [])


def test_two_turns_are_not_a_progression() -> None:
    """Two consecutive numbers differing is a coincidence, not a pattern.

    Uses a multi-word subject on purpose: a bare "order 1001" is discarded by
    the subject check instead, which would make this pass without exercising
    the turn-count rule at all.
    """
    score, reasons = _extraction_progression_score(
        "show me order 1002", history("show me order 1001"),
    )
    assert (score, reasons) == (0.0, [])


def test_repeating_the_same_prompt_is_not_a_progression() -> None:
    """Repetition is scored elsewhere; this detector is about movement."""
    score, reasons = _extraction_progression_score(
        "show me order 1001",
        history("show me order 1001", "show me order 1001", "show me order 1001"),
    )
    assert (score, reasons) == (0.0, [])


def test_counting_down_is_not_extraction() -> None:
    score, reasons = _extraction_progression_score(
        "order 1002", history("order 1005", "order 1004", "order 1003"),
    )
    assert (score, reasons) == (0.0, [])


def test_different_subjects_do_not_form_a_series() -> None:
    """Numbers rising across unrelated questions is not a walk through anything."""
    score, reasons = _extraction_progression_score(
        "user 4004", history("order 1001", "invoice 2002", "ticket 3003"),
    )
    assert (score, reasons) == (0.0, [])


def test_bare_numbers_have_no_subject_to_enumerate() -> None:
    score, reasons = _extraction_progression_score("4", history("1", "2", "3"))
    assert (score, reasons) == (0.0, [])


@pytest.mark.parametrize("prompts", [
    ("hello",),
    ("", "", ""),
    ("order 1001", "", "order 1003"),
])
def test_degenerate_input_never_raises(prompts: tuple[str, ...]) -> None:
    """Runs on every prompt in the request path's shadow; it must not throw."""
    score, reasons = _extraction_progression_score("order 1004", history(*prompts))
    assert isinstance(score, float) and isinstance(reasons, list)


def test_current_prompt_is_not_double_counted() -> None:
    """Upstream may already have written the current prompt into history."""
    prompts = history("show me order 1001", "show me order 1002")
    with_dup = _extraction_progression_score("show me order 1002", prompts)
    assert with_dup == (0.0, []), (
        "counting the current prompt twice fabricates a third data point"
    )


def test_history_ending_with_the_current_prompt_still_sees_the_series() -> None:
    """The de-duplication has to be load-bearing in the positive direction too.

    When upstream has already written the current prompt as the last history
    row, appending it again adds a zero step and the strictly-increasing check
    then discards a real progression. So the failure of double-counting is not
    a false positive -- it is a MISS, which is why this asserts the detector
    fires rather than that it stays quiet.
    """
    prompts = history("show me order 1001", "show me order 1002", "show me order 1003")
    score, reasons = _extraction_progression_score("show me order 1003", prompts)
    assert "identifier_enumeration" in reasons, (
        "a duplicated final turn broke the series instead of being ignored"
    )
    assert score > 0
