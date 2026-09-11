"""Load operator-authored custom signatures for the deployment's scope.

Custom signatures are written by the control plane into the scope-config table
(``VARDOGER_TENANTS_TABLE``) under the scope record's ``custom_signatures``
attribute. This provider reads them back so the inline interceptor actually
enforces them — closing the gap where an authored signature was stored but
never fired.

Loading is best-effort and fail-open-to-community: any read/parse error returns
[] so the scanner falls back to the bundled (+ premium) set rather than losing
detection entirely. Each pattern is re-validated here (compile + ReDoS screen)
as defense in depth, even though the write path already validates — a malformed
pattern must never reach the inline regex engine.
"""
from __future__ import annotations

import logging
import os
import re

from vardoger import aws, config
from vardoger.detection.models import RegexPattern
from vardoger.detection.signature_scanner import redos_risk
from vardoger.health import CUSTOM_SIGNATURES, report_degraded

logger = logging.getLogger(__name__)

# Bound how many custom signatures we load, so a runaway table cannot blow up
# the inline scanner's per-request cost.
_MAX_CUSTOM_SIGNATURES = 200

def _enabled() -> bool:
    """Custom-signature loading is opt-in via env, off by default.

    Set VARDOGER_LOAD_CUSTOM_SIGNATURES=true to enable. This keeps the inline
    path from making a DynamoDB call on every cold start unless the operator
    actually uses custom signatures, and keeps unit tests hermetic by default.
    """
    return os.environ.get("VARDOGER_LOAD_CUSTOM_SIGNATURES", "false").strip().lower() == "true"


def load_custom_signatures() -> list[RegexPattern]:
    """Return validated custom signatures for this deployment's scope.

    Returns [] when disabled, unconfigured, or on any error (fail-safe).
    """
    if not _enabled():
        return []

    # Same table the control plane writes to (scope-config / "tenants").
    table_name = config.SCOPE_CONFIG_TABLE
    if not table_name:
        return []

    try:
        # Inline profile: this runs on the interceptor's fail-closed path, so a
        # slow or unreachable DynamoDB must fail fast and fall back rather than
        # stall the request (see vardoger/aws.py).
        table = aws.table(table_name, kind="inline", region=config.AWS_REGION)
        resp = table.get_item(Key={"scope_id": config.SCOPE_ID or "local"})
    except Exception as exc:
        logger.warning("Could not read custom signatures; using community/premium only", exc_info=True)
        report_degraded(
            CUSTOM_SIGNATURES,
            f"read failed: {type(exc).__name__}; community/premium only",
            table=table_name,
        )
        return []

    item = resp.get("Item") or {}
    raw = item.get("custom_signatures") or []
    if not isinstance(raw, list):
        return []

    out: list[RegexPattern] = []
    skipped = 0
    for entry in raw[:_MAX_CUSTOM_SIGNATURES]:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        sig_id = str(entry.get("signature_id") or "").strip()
        pattern = str(entry.get("pattern") or "")
        if not sig_id or not pattern:
            skipped += 1
            continue
        # Defense in depth: compile + ReDoS screen before this ever reaches the
        # inline engine. The write path validates too, but a table could be
        # edited out of band.
        try:
            re.compile(pattern)
        except re.error:
            skipped += 1
            continue
        if redos_risk(pattern):
            skipped += 1
            continue
        out.append(
            RegexPattern(
                id=sig_id,
                severity=str(entry.get("severity") or "medium"),
                category=str(entry.get("category") or "custom"),
                pattern=pattern,
                description=str(entry.get("description") or ""),
                author=str(entry.get("author") or ""),
            )
        )
    if skipped:
        logger.warning("Skipped %d invalid/unsafe custom signature(s)", skipped)
        report_degraded(
            CUSTOM_SIGNATURES,
            "custom signatures rejected at load (invalid regex or ReDoS risk)",
            skipped=skipped,
        )
    return out
