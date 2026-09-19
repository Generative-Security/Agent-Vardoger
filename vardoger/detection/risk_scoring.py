"""Prompt and session risk scoring.

Scores individual prompts via pattern-group matching and term combinations,
then accumulates session-level risk with time decay and repeat-intent bonuses.

The scale
---------
These numbers are the product's security policy in code: they decide whether a
real user gets blocked. They are documented here because the thresholds are what
a deployer most needs to reason about when tuning for their own traffic.

Prompt scores are additive over a 0-20ish range, calibrated so that:

- **8 = block.** One match in a group whose weight is 8 is, on its own, strong
  enough to terminate the session. Those groups are the ones with no plausible
  benign phrasing: ``system_prompt_extraction``, ``secret_extraction``,
  ``payload_injection``, ``insider_cyber_abuse``, ``workplace_retaliation``.
  Asking an agent to print its system prompt is not something a legitimate user
  does by accident.
- **4 = escalate (medium).** A single weight-4 or -5 match is suspicious but
  survivable alone: ``employee_safety`` and ``account_takeover`` (4) have real
  benign phrasings ("who is working today?"), and ``instruction_override`` /
  ``roleplay_jailbreak`` / ``safety_bypass`` (5) are common in security research
  and testing. These need corroboration — a second signal in the same prompt, or
  repetition across the session — before reaching 8.
- **7 = tool_injection.** Deliberately just below the block line: a single match
  escalates, and any second signal pushes it over.

Weights are intentionally coarse (4/5/7/8). Finer gradations imply a precision
the underlying regexes do not have.

Session accumulation
--------------------
Session risk is the decayed prior score plus this prompt's score plus small
bonuses, capped at ``_SESSION_SCORE_CAP`` (20) so a long session cannot drift
upward forever and eventually block a user for volume alone.

- ``_DECAY_HALF_LIFE`` (900s / 15 min): prior risk halves every 15 minutes, so a
  probe abandoned early does not poison a session an hour later. The
  ``_DECAY_FLOOR`` (0.25) keeps a *quarter* of prior risk no matter how long the
  gap — a patient attacker pacing requests hours apart should not fully reset.
- ``_REPEAT_BONUS_CAP`` (3): repeating the same attack *category* adds at most 3,
  enough to push a persistent prober over the line without letting one repeated
  category dominate the score.
- ``prompt_bonus`` (+1): a small nudge once a session has multiple prompts and
  the current one is already medium-risk, capturing "escalating conversation".

Session thresholds are higher than prompt thresholds (12 block / 6 escalate vs
8 / 4) because session risk aggregates many prompts; using the same line would
block sessions that merely contain several mildly-suspicious turns.

Tuning note: raising the block thresholds reduces false-positive kills and
increases missed attacks; lowering them does the reverse. Tier 1 is the only
tier that blocks synchronously, so changes here are felt immediately by users.
"""
from __future__ import annotations

import re
import time
from typing import Any

RISK_GROUP_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "instruction_override": [
        re.compile(r"\bignore (all )?(previous|prior|above|earlier) (instructions|rules|messages|context)\b"),
        re.compile(r"\bdisregard (the )?(policy|rules|instructions|system message)\b"),
        re.compile(r"\bforget (all )?(previous|prior|above|earlier) (instructions|rules|messages)\b"),
        re.compile(r"\boverride (the )?(system|developer|safety|policy) (instructions|rules|message)\b"),
    ],
    "system_prompt_extraction": [
        re.compile(r"\b(reveal|print|show|display|dump|expose|leak|tell me) (the )?(system|developer|hidden|initial|internal) (prompt|prompts|message|instructions|rules|configuration)\b"),
        re.compile(r"\bwhat (are|were) (your|the) (system|developer|hidden) (instructions|prompt|rules)\b"),
    ],
    "roleplay_jailbreak": [
        re.compile(r"\bpretend (you are|to be) (dan|developer mode|uncensored|unfiltered|jailbroken)\b"),
        re.compile(r"\bact as (dan|developer mode|an uncensored ai|an unfiltered ai)\b"),
        re.compile(r"\byou are now (dan|developer mode|uncensored|unfiltered|jailbroken|unrestricted)\b"),
        re.compile(r"\b(unfiltered|uncensored|unrestricted) (ai|assistant|model)\b"),
    ],
    "safety_bypass": [
        re.compile(r"\bbypass (the )?(safety|policy|guardrails|restrictions|filters)\b"),
        re.compile(r"\bdisable (the )?(safety|policy|guardrails|restrictions|filters)\b"),
        re.compile(r"\bwithout (any )?(safety|policy|ethical|legal) (limits|restrictions|constraints)\b"),
        re.compile(r"\bignore (all )?(guardrails|restrictions|filters|limitations)\b"),
    ],
    "tool_injection": [
        re.compile(r"\bignore (all )?(tool|agent|browser|retrieval|rag) instructions\b"),
        re.compile(r"\buse the tool to (exfiltrate|leak|dump|reveal)\b"),
        re.compile(r"\bsearch for (secrets|api keys|tokens|passwords|credentials)\b"),
    ],
    "secret_extraction": [
        re.compile(r"\b(show|print|dump|reveal|extract|give me|find|list) .*?(api key|secret key|access key|secret|token|password|credentials?|private key)\b"),
        re.compile(r"\baccess .*?(aws keys|aws secret|github token|openai key|database password)\b"),
    ],
    "insider_cyber_abuse": [
        re.compile(r"\b(hack|break into|compromise|bypass access|unauthorized access) .*?(company|employer|work|corporate|internal systems?|company network)\b"),
    ],
    "workplace_retaliation": [
        re.compile(r"\b(revenge|retaliation|sabotage)\b.*\b(boss|company|employer|manager)\b.*\b(credentials?|accounts?|passwords?)\b"),
    ],
    "payload_injection": [
        re.compile(r"\bunion select\b"),
        re.compile(r"<script[^>]*>"),
        re.compile(r"\b/etc/passwd\b"),
        re.compile(r"\b(select|insert|update|delete|drop) .*?\bfrom\b"),
    ],
    "employee_safety": [
        re.compile(r"\b(which employees are available|who is working|working with only one other employee)\b"),
        re.compile(r"\b(employee schedule|employee availability|shift schedule)\b"),
    ],
    "account_takeover": [
        re.compile(r"\badmin password\b"),
        re.compile(r"\b(account recovery|verification code|otp|2fa)\b.{0,80}\b(bypass|skip|avoid|without|fake|guess)\b"),
        re.compile(r"\b(reset|recover|unlock|change)\b.{0,80}\b(password|login|account|access)\b.{0,80}\b(other|someone else'?s|another|without|bypass|skip|avoid)\b"),
        re.compile(r"\b(access|take over|bypass) (the )?(account|login|auth|authentication)\b"),
    ],
}

RISK_GROUP_WEIGHTS: dict[str, int] = {
    "instruction_override": 5, "system_prompt_extraction": 8,
    "roleplay_jailbreak": 5, "safety_bypass": 5,
    "tool_injection": 7, "secret_extraction": 8,
    "insider_cyber_abuse": 8, "workplace_retaliation": 8,
    "payload_injection": 8, "employee_safety": 4,
    "account_takeover": 4,
}

RISK_COMBO_TERMS: list[tuple[list[str], int, str]] = [
    (["ignore", "instructions"], 5, "combo:ignore_instructions"),
    (["reveal", "system", "prompt"], 8, "combo:reveal_system_prompt"),
    (["hidden", "system", "instructions"], 8, "combo:hidden_system_instructions"),
    (["production", "password"], 8, "combo:production_password"),
    (["aws", "secret", "key"], 8, "combo:aws_secret_key"),
    (["hack", "company"], 8, "combo:insider_company_hack"),
    (["developer", "mode"], 5, "combo:developer_mode"),
    (["bypass", "policy"], 6, "combo:bypass_policy"),
    (["api", "key"], 7, "combo:api_key"),
    (["no", "restrictions"], 5, "combo:no_restrictions"),
    (["without", "safeguards"], 6, "combo:without_safeguards"),
]

# --- Calibrated thresholds. See the module docstring for the rationale. ---
# Prompt-level verdicts.
# Added to a prompt's score when the session identifier was not asserted by
# the gateway. One point, on purpose: enough that a weight-7 tool_injection or a
# pair of weight-4 signals reaches the block line when we cannot verify who is
# asking, and not enough to block anything on unverifiability alone. A prompt
# that scores 0 still scores 0.
#
# It does NOT defeat an attacker rotating session ids -- each forged session
# starts clean either way. What it buys is that traffic we cannot attribute is
# judged slightly more strictly than traffic we can.
UNVERIFIED_SESSION_RISK = 1

BLOCK_THRESHOLD = 8
ESCALATE_THRESHOLD = 4
# Session-level verdicts (higher: session risk aggregates many prompts).
SESSION_BLOCK_THRESHOLD = 12
SESSION_ESCALATE_THRESHOLD = 6

# Session accumulation shape.
_DECAY_HALF_LIFE = 900.0   # prior risk halves every 15 minutes
_DECAY_FLOOR = 0.25        # ...but never decays below a quarter
_SESSION_SCORE_CAP = 20.0  # long sessions cannot drift upward forever
_REPEAT_BONUS_CAP = 3      # repeating one category adds at most this much
# Weight used when a risk group is missing from RISK_GROUP_WEIGHTS.
_DEFAULT_GROUP_WEIGHT = 3


def assess_risk(normalized_text: str) -> dict[str, Any]:
    """Score a normalized prompt against risk-group patterns and term combos."""
    score = 0
    signals: list[str] = []
    intent_categories: list[str] = []
    text_lower = normalized_text.lower()

    for group_name, patterns in RISK_GROUP_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(text_lower):
                weight = RISK_GROUP_WEIGHTS.get(group_name, _DEFAULT_GROUP_WEIGHT)
                score += weight
                signals.append(f"risk_group:{group_name}")
                if group_name not in intent_categories:
                    intent_categories.append(group_name)
                break

    words = set(text_lower.split())
    for combo_terms, combo_score, signal in RISK_COMBO_TERMS:
        if all(term in words for term in combo_terms):
            score += combo_score
            signals.append(signal)

    bucket = (
        "high" if score >= BLOCK_THRESHOLD
        else "medium" if score >= ESCALATE_THRESHOLD
        else "low"
    )
    recommendation = (
        "block" if score >= BLOCK_THRESHOLD
        else "escalate" if score >= ESCALATE_THRESHOLD
        else "allow"
    )

    return {
        "score": score, "bucket": bucket, "signals": signals,
        "recommendation": recommendation, "intent_categories": intent_categories,
    }


def _session_decay(elapsed_seconds: float) -> float:
    """Compute an exponential decay factor for session risk over elapsed time."""
    if elapsed_seconds <= 0:
        return 1.0
    decay = 0.5 ** (elapsed_seconds / _DECAY_HALF_LIFE)
    # Floor the decay: a patient attacker pacing requests hours apart should not
    # be able to fully reset accumulated session risk by waiting.
    return max(_DECAY_FLOOR, min(1.0, decay))


def score_session_risk(
    prompt_score: int,
    intent_categories: list[str],
    session_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Accumulate session-level risk from prompt score, decay, and repeated intents."""
    now = time.time()
    state = session_state or {}
    prev_score = float(state.get("accumulated_risk_score", 0))
    prev_epoch = float(state.get("last_risk_epoch", 0))
    prompts_seen = int(state.get("prompts_seen", 0))
    intent_counts: dict[str, int] = state.get("intent_counts", {}) or {}

    elapsed = max(0.0, now - prev_epoch) if prev_epoch else 0.0
    decayed = prev_score * _session_decay(elapsed)
    # One point per attack category already seen in this session: a prober
    # returning to the same technique is more suspicious than variety alone.
    repeat_bonus = min(_REPEAT_BONUS_CAP, sum(1 for c in intent_categories if intent_counts.get(c, 0) > 0))
    # Small nudge for an escalating conversation: not the first prompt, and this
    # one is already at least medium risk.
    prompt_bonus = 1 if prompts_seen >= 2 and prompt_score >= ESCALATE_THRESHOLD else 0
    session_score = min(
        _SESSION_SCORE_CAP,
        decayed + float(prompt_score) + float(repeat_bonus) + float(prompt_bonus),
    )

    prompts_seen += 1
    for c in intent_categories:
        intent_counts[c] = intent_counts.get(c, 0) + 1

    session_bucket = (
        "high" if session_score >= SESSION_BLOCK_THRESHOLD
        else "medium" if session_score >= SESSION_ESCALATE_THRESHOLD
        else "low"
    )
    session_rec = (
        "block" if session_score >= SESSION_BLOCK_THRESHOLD
        else "escalate" if session_score >= SESSION_ESCALATE_THRESHOLD
        else "allow"
    )

    return {
        "session_score": round(session_score),
        "session_bucket": session_bucket,
        "session_recommendation": session_rec,
        "prompts_seen": prompts_seen,
        "intent_counts": intent_counts,
        "accumulated_risk_score": session_score,
    }
