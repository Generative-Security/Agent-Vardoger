"""Premium signature provider (AWS Marketplace cross-account S3).

Premium tier customers subscribe on AWS Marketplace and are granted cross-account
read access to an S3 bucket holding the latest premium signatures. This module
reads that signatures object and validates it through the same pipeline used for
community signatures (ReDoS screening + min_patterns + optional manifest hash).

Premium is strictly additive and optional. When the bucket is not configured, or
on any error, ``load_premium_signatures`` returns ``None`` (never raises) so the
scanner degrades gracefully to the community-only path.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from vardoger import aws, config
from vardoger.detection import signature_scanner
from vardoger.detection.models import RegexPattern
from vardoger.health import PREMIUM_SIGNATURES, report_degraded

logger = logging.getLogger(__name__)

# Object key (relative to the configured prefix) holding the signatures package.
_SIGNATURES_OBJECT = "signatures.json"
# Optional sidecar object holding a manifest hash for integrity verification.
_MANIFEST_OBJECT = "manifest.json"

# Bounded-timeout client config. Premium load now runs on the inline request
# path (engine refresh inside evaluate()), so a slow S3/STS must fail fast and
# fall back to community rather than stalling the interceptor past the
# dispatcher's 30s timeout (which would fail-closed and block a real user).
def _bounded_config() -> Any:
    from botocore.config import Config

    return Config(connect_timeout=1.0, read_timeout=2.0, retries={"max_attempts": 1})


def _s3_client() -> Any:
    """Return an S3 client, assuming the cross-account role first when configured.

    Both the STS and S3 clients use the INLINE timeout profile. This matters:
    the engine refreshes signatures from inside ``evaluate()``, so one request
    every ``SCANNER_REINIT_SECONDS`` pays this cost on the interceptor's
    fail-closed path. With botocore's 60s defaults a single S3 blip could stall
    that request past the Lambda ceiling and block a legitimate user.
    """
    import boto3

    role_arn = config.PREMIUM_SIGNATURE_ROLE_ARN
    if role_arn:
        sts = aws.client("sts", kind="inline", region=config.AWS_REGION)
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="vardoger-premium-signatures",
        )
        creds = assumed["Credentials"]
        # Built directly rather than via vardoger.aws: these are per-assumption
        # temporary credentials, so the client is not cacheable. The same
        # bounded config the shared helper would apply is passed explicitly.
        return boto3.client(
            "s3",
            region_name=config.AWS_REGION,
            config=aws.INLINE_CONFIG,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    return aws.client("s3", kind="inline", region=config.AWS_REGION)


def _read_object(client: Any, bucket: str, key: str) -> bytes | None:
    """Return the raw body of an S3 object, or None when it is absent."""
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        response = client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Premium signatures: could not read s3://%s/%s: %s", bucket, key, exc)
        report_degraded(
            PREMIUM_SIGNATURES,
            f"S3 read failed: {type(exc).__name__}",
            bucket=bucket,
            key=key,
        )
        return None


def load_premium_signatures() -> list[RegexPattern] | None:
    """Load and validate premium signatures from the cross-account S3 bucket.

    Returns a validated ``list[RegexPattern]`` on success, or ``None`` when the
    bucket is not configured or on any error. Never raises.
    """
    bucket = config.PREMIUM_SIGNATURE_BUCKET
    if not bucket:
        # Free/community tier — nothing to load.
        return None

    prefix = config.PREMIUM_SIGNATURE_PREFIX or ""
    signatures_key = f"{prefix}{_SIGNATURES_OBJECT}"
    manifest_key = f"{prefix}{_MANIFEST_OBJECT}"

    try:
        client = _s3_client()

        raw_body = _read_object(client, bucket, signatures_key)
        if raw_body is None:
            return None

        # Optional manifest hash: verified by validate_and_parse when present.
        manifest_hash: str | None = None
        manifest_body = _read_object(client, bucket, manifest_key)
        if manifest_body is not None:
            try:
                manifest = json.loads(manifest_body)
                manifest_hash = manifest.get("sha256") or manifest.get("hash") or None
            except (ValueError, AttributeError) as exc:
                logger.warning("Premium signatures: ignoring unreadable manifest: %s", exc)

        try:
            data = json.loads(raw_body)
        except ValueError as exc:
            logger.warning("Premium signatures: invalid JSON in %s: %s", signatures_key, exc)
            return None

        # Accept either a bare list or a wrapped {"signatures": [...]} object.
        if isinstance(data, dict):
            data = data.get("signatures", [])
        if not isinstance(data, list):
            logger.warning("Premium signatures: unexpected payload shape in %s", signatures_key)
            return None

        patterns = signature_scanner.validate_and_parse(
            data,
            manifest_hash=manifest_hash,
            raw_body=raw_body if manifest_hash else None,
            min_patterns=config.SIGNATURE_MIN_PATTERNS,
        )
        if patterns is None:
            logger.warning("Premium signatures: validation failed; falling back to community-only")
            report_degraded(
                PREMIUM_SIGNATURES,
                "package failed validation (ReDoS/min-patterns/hash); community-only",
                bucket=bucket,
            )
            return None

        logger.info("Loaded %d premium signatures from s3://%s/%s", len(patterns), bucket, signatures_key)
        return patterns
    except Exception as exc:
        logger.warning("Premium signatures: load failed (%s); falling back to community-only", exc)
        report_degraded(
            PREMIUM_SIGNATURES,
            f"load failed: {type(exc).__name__}; community-only",
            bucket=bucket,
        )
        return None


def premium_status() -> dict[str, Any]:
    """Return a non-sensitive summary of the premium configuration.

    Does not read or leak any credentials or object contents.
    """
    bucket = config.PREMIUM_SIGNATURE_BUCKET
    return {
        "enabled": bool(bucket),
        "bucket": bucket or "",
        "role_arn": config.PREMIUM_SIGNATURE_ROLE_ARN or "",
    }
