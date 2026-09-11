"""Central detection orchestrator.

Runs all detection layers and produces a single allow/block verdict.
Platform-agnostic: receives text and returns an EvaluationResult.
Platform adapters handle event parsing and response formatting.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from vardoger.detection import risk_scoring
from vardoger.detection.detection_policy import evaluate_detection_policy
from vardoger.detection.hash_scanner import HashScanner
from vardoger.detection.models import EvaluationResult
from vardoger.detection.prompt_normalizer import normalize_prompt
from vardoger.detection.signature_scanner import SignatureScanner, build_scanner
from vardoger.health import SIGNATURE_REFRESH, report_degraded

logger = logging.getLogger(__name__)

SIGNATURE_SEVERITY_SCORE = {
    "critical": 12,
    "high": 8,
    "medium": 5,
    "low": 2,
}

HASH_SEVERITY_SCORE = {
    "sig-h-001": 12,
    "sig-h-002": 8,
    "sig-h-003": 12,
    "sig-h-004": 8,
    "sig-h-005": 8,
    "sig-h-006": 8,
}


class DetectionEngine:
    """Central orchestrator: runs all detection layers and produces a single allow/block verdict."""

    def __init__(self, scanner_reinit_seconds: float = 300.0, signatures=None):
        # Explicit signatures (tests) are used verbatim; otherwise build the
        # full set (community + premium + custom, append-only).
        self.signature_scanner = SignatureScanner(signatures) if signatures is not None else build_scanner()
        self._signature_scanner_loaded_at = time.time()
        self._scanner_reinit_seconds = scanner_reinit_seconds
        self.hash_scanner = HashScanner()
        logger.info("DetectionEngine initialized with %d regex signatures",
                    self.signature_scanner.pattern_count)

    def _refresh_signature_scanner_if_needed(self) -> None:
        """Refresh dynamic regex signatures on warm Lambda containers."""
        reinit_seconds = max(self._scanner_reinit_seconds, 1.0)
        if time.time() - self._signature_scanner_loaded_at < reinit_seconds:
            return
        # Rebuild the full set so premium/custom signature changes are picked up
        # on warm containers, not just community.
        previous = self.signature_scanner
        try:
            rebuilt = build_scanner()
        except Exception as exc:
            # A refresh failure must never drop us below what we already have.
            logger.warning("Scanner refresh failed; keeping previous scanner", exc_info=True)
            report_degraded(
                SIGNATURE_REFRESH,
                f"scanner refresh raised: {type(exc).__name__}",
                pattern_count=previous.pattern_count,
            )
            self._signature_scanner_loaded_at = time.time()
            return

        # Never let a transient premium/custom load blip DOWNGRADE a container
        # (e.g. premium -> community) mid-life. The community floor is constant,
        # so a smaller count means an additive source failed to load; keep the
        # richer previous scanner and retry at the next interval.
        if rebuilt.pattern_count < previous.pattern_count:
            logger.warning(
                "Scanner refresh yielded fewer signatures (%d < %d); keeping previous scanner",
                rebuilt.pattern_count,
                previous.pattern_count,
            )
            # Detection coverage silently shrinking is the worst failure mode a
            # security product has; make it an alarm, not just a log line.
            report_degraded(
                SIGNATURE_REFRESH,
                "refresh returned fewer signatures; an additive source failed to load",
                rebuilt_count=rebuilt.pattern_count,
                previous_count=previous.pattern_count,
            )
            self._signature_scanner_loaded_at = time.time()
            return

        self.signature_scanner = rebuilt
        self._signature_scanner_loaded_at = time.time()
        logger.info(
            "DetectionEngine refreshed regex scanner with %d signatures",
            self.signature_scanner.pattern_count,
        )

    def evaluate(
        self,
        prompt: str,
        session_id: str = "",
        tenant_id: str = "",
        session_state: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        """Run a prompt through normalize -> regex -> hash -> policy -> risk and return a verdict."""

        self._refresh_signature_scanner_if_needed()

        # Step 1: Normalize the prompt
        norm = normalize_prompt(prompt)

        # Step 2: Regex scan against multiple text variants
        sig_details = self.signature_scanner.scan_detailed(norm.corrected_prompt)
        sig_details += self.signature_scanner.scan_detailed(norm.normalized_prompt)
        sig_details += self.signature_scanner.scan_detailed(prompt)
        sig_matches = list(dict.fromkeys(match["id"] for match in sig_details))

        # Step 3: Check known-bad SHA-256 hashes
        hash_matches = self.hash_scanner.scan(prompt)

        # Step 4: Run deterministic policy rules
        policy_result = evaluate_detection_policy(prompt)

        # Step 5: Score per-prompt risk
        risk_assessment = risk_scoring.assess_risk(norm.corrected_prompt)

        # Step 6: Accumulate session-level risk
        session_risk: dict[str, Any] = {}
        if session_id:
            session_risk = risk_scoring.score_session_risk(
                risk_assessment["score"],
                risk_assessment["intent_categories"],
                session_state=session_state,
            )

        # Final decision: block if ANY detection layer flags the prompt
        all_matches = list(dict.fromkeys(sig_matches + hash_matches))
        is_malicious = (
            len(all_matches) > 0
            or policy_result.decision == "block"
            or risk_assessment["recommendation"] == "block"
            or session_risk.get("session_recommendation") == "block"
        )

        # Pick the highest score across all layers
        signature_score = max(
            [SIGNATURE_SEVERITY_SCORE.get(match.get("severity", ""), 0) for match in sig_details]
            + [HASH_SEVERITY_SCORE.get(match_id, 8) for match_id in hash_matches]
            + [0]
        )
        best_score = max(policy_result.risk_score, risk_assessment["score"], signature_score)
        best_bucket = "high" if best_score >= 8 else "medium" if best_score >= 4 else "low"

        return EvaluationResult(
            decision="block" if is_malicious else "allow",
            matched_signature_ids=all_matches,
            risk_score=best_score,
            risk_bucket=best_bucket,
            risk_signals=sorted(set(policy_result.risk_signals + risk_assessment["signals"])),
            risk_recommendation="block" if is_malicious else risk_assessment["recommendation"],
            session_risk_score=session_risk.get("session_score", 0),
            session_risk_bucket=session_risk.get("session_bucket", "low"),
            session_risk_recommendation=session_risk.get("session_recommendation", "allow"),
            attack_intents=risk_assessment["intent_categories"],
            session_signal_counts=session_risk.get("intent_counts", {}),
            matched_policy_rules=policy_result.matched_policy_rules,
            matched_terms=policy_result.matched_terms,
            critical_signal=policy_result.critical_signal,
            escalation_reason=policy_result.escalation_reason or "",
        )
