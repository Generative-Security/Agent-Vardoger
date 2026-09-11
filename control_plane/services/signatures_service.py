"""Community/premium signature metadata and custom signature authoring.

Community signature metadata (count + categories) is derived by introspecting
the ``signatures.community`` package. Premium status is env-driven:
VARDOGER_PREMIUM_SIGNATURE_BUCKET being set means premium is enabled. There is
no in-app payment — only a Marketplace link placeholder.

Custom signatures are stored in the TENANTS_TABLE, keyed by scope_id, under a
``custom_signatures`` list attribute. (We reuse the existing scope-keyed table
rather than introducing a new one; documented here and in docs/signatures.md.)
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

from control_plane import config
from control_plane.schemas.management import (
    CustomSignatureRequest,
    CustomSignatureResponse,
    SignaturesResponse,
)
from vardoger import aws
from vardoger.health import TENANT_POLICY, report_degraded

logger = logging.getLogger(__name__)

# Where custom signatures live. We key by scope_id in the existing TENANTS_TABLE.
CUSTOM_SIGNATURE_STORE = "TENANTS_TABLE (scope_id-keyed, attribute custom_signatures)"


class SignatureWriteError(RuntimeError):
    """The custom signature could not be persisted.

    A failed write is reported as a failure, not as a 200 carrying
    ``stored=False``. An operator who believes they authored a detection that
    was never stored has a gap they do not know about — the worst outcome for a
    security tool. The router turns this into a 503.

    Note the deliberate split: a signature REJECTED by validation (bad regex,
    ReDoS risk) is a client error -> 400, while a signature that passed
    validation but could not be stored is a dependency failure -> 503.
    """



def _dynamodb():
    return aws.resource("dynamodb", region=config.AWS_REGION)


def _community_metadata() -> tuple[int, list[str]]:
    """Count community signatures and collect their distinct categories.

    Introspects the community package's module-level lists of signature
    dataclasses. Falls back to (0, []) if the package can't be imported.
    """
    count = 0
    categories: set[str] = set()
    module_names = (
        "signatures.community.mitre_atlas",
        "signatures.community.named_jailbreaks",
        "signatures.community.zero_day_patterns",
        "signatures.community.hash_lookups",
    )
    import importlib

    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
        except Exception:
            logger.warning("Could not import %s for signature metadata", module_name)
            continue
        for attr_name in dir(module):
            if attr_name.startswith("_"):
                continue
            value = getattr(module, attr_name)
            if not isinstance(value, list):
                continue
            for entry in value:
                category = getattr(entry, "category", None)
                if category is None:
                    continue
                count += 1
                categories.add(str(category))
    return count, sorted(categories)


def get_signatures() -> SignaturesResponse:
    """Return community signature metadata plus premium status."""
    count, categories = _community_metadata()
    premium_enabled = bool(os.environ.get("VARDOGER_PREMIUM_SIGNATURE_BUCKET", "").strip())
    marketplace_link = os.environ.get("VARDOGER_MARKETPLACE_URL", "").strip()
    aws_account_id = os.environ.get("VARDOGER_AWS_ACCOUNT_ID", "").strip()
    return SignaturesResponse(
        community_count=count,
        categories=categories,
        premium_enabled=premium_enabled,
        marketplace_link=marketplace_link,
        aws_account_id=aws_account_id,
    )


def _validate_pattern(pattern: str) -> str:
    """Return an error string if the pattern is unusable, else "".

    Uses the SAME checks the premium/bundled pipeline applies: it must compile,
    and it must pass the catastrophic-backtracking (ReDoS) screen. This runs at
    author time so a bad pattern is rejected here rather than detonating in the
    inline interceptor (compile error or ReDoS -> timeout -> fail-closed block
    of all traffic).
    """
    import re

    from vardoger.detection.signature_scanner import redos_risk

    if not pattern or not pattern.strip():
        return "Pattern is empty."
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"Invalid regex: {exc}"
    unsafe = redos_risk(pattern)
    if unsafe:
        return f"Pattern rejected (ReDoS risk): {unsafe}"
    return ""


def add_custom_signature(req: CustomSignatureRequest, author: str = "") -> CustomSignatureResponse:
    """Store a custom signature in TENANTS_TABLE under the scope's record.

    The pattern is validated (compile + ReDoS screen) before storage; an invalid
    or catastrophic pattern is rejected with an error and never persisted.
    """
    scope = config.scope_id()
    signature_id = req.signature_id.strip() or f"sig-custom-{int(time.time())}"

    error = _validate_pattern(req.pattern)
    if error:
        logger.warning("Rejected custom signature %s for scope=%s: %s", signature_id, scope, error)
        return CustomSignatureResponse(
            stored=False,
            signature_id=signature_id,
            scope_id=scope,
            store=CUSTOM_SIGNATURE_STORE,
            error=error,
        )

    entry: dict[str, Any] = {
        "signature_id": signature_id,
        "category": req.category.strip(),
        "pattern": req.pattern,
        "severity": req.severity.strip() or "medium",
        "description": req.description,
        "author": author,
        "created_at": int(time.time()),
    }
    try:
        _dynamodb().Table(config.TENANTS_TABLE).update_item(
            Key={"scope_id": scope},
            UpdateExpression=(
                "SET custom_signatures = list_append("
                "if_not_exists(custom_signatures, :empty), :entry)"
            ),
            ExpressionAttributeValues={":empty": [], ":entry": [entry]},
        )
    except Exception as exc:
        logger.exception("Failed to store custom signature for scope=%s", scope)
        report_degraded(
            TENANT_POLICY,
            f"custom signature write failed: {type(exc).__name__}",
            scope_id=scope,
        )
        raise SignatureWriteError(
            f"Signature {signature_id} could not be saved ({type(exc).__name__}). "
            "The scope configuration table may be unavailable; the signature is NOT active."
        ) from exc

    return CustomSignatureResponse(
        # A 200 from this endpoint now means the write landed.
        stored=True,
        signature_id=signature_id,
        scope_id=scope,
        store=CUSTOM_SIGNATURE_STORE,
        # Custom signatures ARE loaded by the inline interceptor (append-only,
        # scope-keyed). New/updated signatures take effect after the scanner's
        # refresh interval (VARDOGER_SCANNER_REINIT_SECONDS) on warm containers,
        # or immediately on the next cold start.
        enforced=True,
        note=(
            "Stored and validated. Enforced by the inline interceptor after the "
            "scanner refresh interval (append-only: cannot override bundled "
            "community signatures)."
        ),
    )
