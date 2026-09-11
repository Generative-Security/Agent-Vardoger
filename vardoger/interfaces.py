"""Core interfaces (protocols) for pluggable backend services.

These define the contracts between the detection core and the infrastructure
layer. Implementations live in adapters/ or are provided by the user's
deployment configuration.
"""
from __future__ import annotations

from typing import Any, Protocol


class SessionStore(Protocol):
    """Interface for session state persistence."""

    def get_status(self, session_id: str) -> str | None:
        """Return 'active', 'terminated', or None if unknown."""
        ...

    def get_risk_state(self, session_id: str) -> dict[str, Any]:
        """Return accumulated risk state for a session."""
        ...

    def update_risk(self, session_id: str, score: float, prompts_seen: int, intent_counts: dict[str, int]) -> None:
        """Persist updated risk state."""
        ...

    def ensure_session(self, session_id: str, agent_runtime_arn: str, tenant_id: str) -> None:
        """Create or update a session record (idempotent upsert)."""
        ...

    def mark_decision(self, session_id: str, decision: str, risk_score: int, matched_ids: list[str]) -> None:
        """Record the latest allow/block decision."""
        ...

    def record_detection_event(self, session_id: str, tenant_id: str, decision: str, **kwargs: Any) -> None:
        """Write a durable detection/audit event."""
        ...


class SignatureProvider(Protocol):
    """Interface for loading detection signatures from an external source."""

    def load(self) -> list[dict[str, Any]] | None:
        """Return a list of signature dicts, or None if unavailable.

        Each dict should have: id, severity, category, pattern.
        Returns None to signal "use bundled fallback."
        """
        ...


class EnforcementAction(Protocol):
    """Interface for terminating a detected-malicious session."""

    def terminate(self, session_id: str, agent_runtime_arn: str, reason: str, **kwargs: Any) -> bool:
        """Attempt to terminate a session. Return True on success."""
        ...


class AlertSink(Protocol):
    """Interface for publishing security alerts."""

    def publish(self, event: dict[str, Any]) -> bool:
        """Send an alert event. Return True on success."""
        ...


class PromptTelemetry(Protocol):
    """Interface for exporting prompt telemetry (to managed backend or local store)."""

    def send(self, record: dict[str, Any]) -> str:
        """Send a prompt record. Return 'sent', 'degraded', or 'fail_closed'."""
        ...
