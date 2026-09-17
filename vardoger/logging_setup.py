"""Make the configured log level actually take effect.

``config.LOG_LEVEL`` was read and never applied. Nothing called ``setLevel`` or
``basicConfig`` anywhere in the codebase, so every module's logger inherited
whatever the Lambda runtime had configured on the root logger — which drops
INFO. The observable result: a dispatcher log group containing only
START/END/REPORT while detection events were being written to DynamoDB. The
component was running correctly and reporting nothing, and the quickstart tells
operators to consult exactly that log group when prompts are not arriving.

Call :func:`configure_logging` once at import time in every Lambda entry
module. Idempotent, and never raises: a logging-setup failure must not take the
handler down with it.
"""
from __future__ import annotations

import logging

from vardoger import config

_VALID = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"})
_FALLBACK = "INFO"
_configured = False


def configure_logging() -> str:
    """Apply ``VARDOGER_LOG_LEVEL`` to the root logger. Returns the level set.

    The level is applied to the ROOT logger rather than a named one, because
    every module here uses ``logging.getLogger(__name__)`` and inherits from
    root. Setting one module's logger would leave the rest silent.
    """
    global _configured

    requested = str(getattr(config, "LOG_LEVEL", "") or "").strip().upper()
    level = requested if requested in _VALID else _FALLBACK

    try:
        root = logging.getLogger()
        # The Lambda runtime installs its own handler. Adding another would
        # duplicate every line, so only the level is changed here.
        root.setLevel(level)
        if requested and requested not in _VALID:
            root.warning(
                "Invalid VARDOGER_LOG_LEVEL=%r; using %s. Valid values: %s",
                requested, _FALLBACK, ", ".join(sorted(_VALID)),
            )
        _configured = True
    except Exception:  # pragma: no cover - defensive
        # Logging setup failing must never be the reason a prompt goes
        # uninspected. Fall through silently; the runtime default still applies.
        pass
    return level


def is_configured() -> bool:
    """True once :func:`configure_logging` has run. For tests and diagnostics."""
    return _configured
