"""Shared AWS client construction with explicit, bounded timeouts.

Every AWS call in this codebase falls into one of two latency classes, and the
difference matters for security:

- **inline** — runs inside the AgentCore Gateway REQUEST interceptor, which has
  a ~30s Lambda ceiling and a <30ms detection budget. The dispatcher is
  fail-closed, so an AWS call that hangs past the Lambda timeout does not merely
  slow a request down: the interceptor dies, the gateway sees an error, and a
  **legitimate user is blocked**. Inline calls therefore get a hard, short
  budget and a single attempt — degrade fast and fall back, never stall.

- **async** — Tier 2 / Tier 3 / control plane. These run off the request path,
  so durability beats latency: longer timeouts and real retries.

Before this module, most clients were constructed with no ``Config`` at all and
silently inherited botocore's defaults (60s connect, 60s read, multi-attempt
retries with backoff) — including on the inline path, where a stalled call
means the interceptor is killed by the Lambda ceiling and a legitimate request
is blocked.

Clients are cached per (service, class) because constructing a boto3 client is
expensive (it parses service JSON) and Lambda containers are reused.
"""
from __future__ import annotations

import os
import threading
from typing import Any

import boto3
from botocore.config import Config

# Inline path: the interceptor must decide fast or fall back. One attempt, no
# retry storm — a retry inside a 30s fail-closed budget is a self-inflicted
# outage, not resilience.
INLINE_CONFIG = Config(
    connect_timeout=1.0,
    read_timeout=2.0,
    retries={"max_attempts": 1},
)

# Off-request path: favour durability. Standard retry mode adds adaptive
# backoff for throttling.
ASYNC_CONFIG = Config(
    connect_timeout=3.0,
    read_timeout=10.0,
    retries={"max_attempts": 3, "mode": "standard"},
)

_CONFIGS: dict[str, Config] = {"inline": INLINE_CONFIG, "async": ASYNC_CONFIG}

# Cache keyed by (kind, service, region). Guarded by a lock because Lambda can
# invoke concurrently within one container.
_clients: dict[tuple[str, str, str | None], Any] = {}
_resources: dict[tuple[str, str, str | None], Any] = {}
_lock = threading.Lock()


def _region() -> str | None:
    """Return an explicit region, or None to let boto3 resolve it.

    Deliberately does NOT fall back to a hardcoded default: forcing a region
    would override a caller's profile/instance configuration. Lambda always sets
    AWS_REGION, so in deployment this is always explicit anyway.
    """
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or None


def _config(kind: str) -> Config:
    try:
        return _CONFIGS[kind]
    except KeyError:  # pragma: no cover - programming error
        raise ValueError(f"Unknown client kind {kind!r}; expected 'inline' or 'async'") from None


def client(service: str, kind: str = "async", region: str | None = None) -> Any:
    """Return a cached boto3 client with the timeout profile for ``kind``.

    ``kind`` is "inline" (request path, fail fast) or "async" (off-path).
    """
    resolved = region or _region()
    key = (kind, service, resolved)
    existing = _clients.get(key)
    if existing is not None:
        return existing
    with _lock:
        existing = _clients.get(key)
        if existing is None:
            kwargs: dict[str, Any] = {"config": _config(kind)}
            if resolved:
                kwargs["region_name"] = resolved
            existing = boto3.client(service, **kwargs)
            _clients[key] = existing
        return existing


def resource(service: str, kind: str = "async", region: str | None = None) -> Any:
    """Return a cached boto3 resource with the timeout profile for ``kind``."""
    resolved = region or _region()
    key = (kind, service, resolved)
    existing = _resources.get(key)
    if existing is not None:
        return existing
    with _lock:
        existing = _resources.get(key)
        if existing is None:
            kwargs: dict[str, Any] = {"config": _config(kind)}
            if resolved:
                kwargs["region_name"] = resolved
            existing = boto3.resource(service, **kwargs)
            _resources[key] = existing
        return existing


def table(name: str, kind: str = "async", region: str | None = None) -> Any:
    """Return a cached DynamoDB Table handle with the right timeout profile."""
    return resource("dynamodb", kind=kind, region=region).Table(name)


def reset_cache() -> None:
    """Clear cached clients. Test-support only; not used at runtime."""
    with _lock:
        _clients.clear()
        _resources.clear()
