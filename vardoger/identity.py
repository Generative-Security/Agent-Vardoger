"""Scope and source identity model.

Agent Vardøger separates two independent axes:

- **scope_id** — the isolation / partition key. In self-hosted deployments it
  is always the single value ``"local"`` (one organization, one scope). In the
  managed multi-tenant service it becomes the tenant id. All stored records are
  partitioned by scope_id, so migrating from self-hosted to managed is a matter
  of rewriting scope_id from ``"local"`` to the assigned tenant id.

- **source** — the segmentation dimension a central security team uses to tell
  which of its own environments a record came from. A source is the pair of an
  AWS account id and an agent (runtime ARN or a friendly alias). One account
  running three agents is three sources. Source is stored as an indexed
  attribute on every record and is used for filtering and rollups, NOT for
  isolation.

This module is the single source of truth for how those values are derived and
formatted so every handler and the control plane agree.
"""
from __future__ import annotations

import os

# The self-hosted default. Managed deployments override via VARDOGER_SCOPE_ID
# (injected per-tenant), but in the open-source build this is always "local".
DEFAULT_SCOPE_ID = "local"

# Separator between the account id and the agent portion of a source key.
_SOURCE_SEP = "/"


def scope_id() -> str:
    """Return the isolation scope for this deployment.

    Self-hosted: ``"local"``. Managed: the tenant id, injected via env.
    """
    return os.environ.get("VARDOGER_SCOPE_ID", DEFAULT_SCOPE_ID).strip() or DEFAULT_SCOPE_ID


def make_source(account_id: str, agent: str) -> str:
    """Build a stable source key from an AWS account id and an agent.

    ``agent`` may be a full agent runtime ARN or a friendly alias. The last
    path segment of an ARN is used so the key stays readable.

    Returns an empty string when neither component is known, so callers can
    decide how to handle unattributed records.
    """
    account = (account_id or "").strip()
    agent_part = _agent_key(agent)
    if account and agent_part:
        return f"{account}{_SOURCE_SEP}{agent_part}"
    return account or agent_part or ""


def _agent_key(agent: str) -> str:
    """Reduce an agent ARN (or alias) to a short, stable key segment."""
    value = (agent or "").strip()
    if not value:
        return ""
    if value.startswith("arn:"):
        # e.g. arn:aws:bedrock:...:agent-runtime/my-agent -> my-agent
        return value.rsplit(_SOURCE_SEP, 1)[-1] or value
    return value


def split_source(source: str) -> tuple[str, str]:
    """Split a source key back into (account_id, agent_key). Best-effort."""
    value = (source or "").strip()
    if not value:
        return "", ""
    if _SOURCE_SEP in value:
        account, agent = value.split(_SOURCE_SEP, 1)
        return account, agent
    return value, ""
