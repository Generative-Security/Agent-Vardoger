"""KMS envelope encryption for prompt evidence.

Encrypts blocked prompt text with a KMS data key before persisting
to S3 for forensic analysis.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from typing import Any

from botocore.exceptions import ClientError

from vardoger import aws, config
from vardoger.health import EVIDENCE_STORE, report_degraded

logger = logging.getLogger(__name__)

_GCM_NONCE_SIZE = 12


def encrypt_and_log(
    prompt_text: str,
    session_id: str,
    *,
    decision: str = "block",
    risk_score: int = 0,
    matched_signature_ids: list[str] | None = None,
    attack_intents: list[str] | None = None,
    agent_runtime_arn: str = "",
) -> dict[str, Any] | None:
    """Encrypt a prompt with KMS envelope encryption and persist the evidence record."""
    key_id = config.KMS_KEY_ID
    if not key_id:
        return None

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Inline profile: this runs on the interceptor path when a prompt is
        # blocked, so it must fail fast rather than stall the request.
        kms = aws.client("kms", kind="inline")
        dk_response = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        plaintext_key = dk_response["Plaintext"]
        encrypted_key = dk_response["CiphertextBlob"]

        nonce = os.urandom(_GCM_NONCE_SIZE)
        aes = AESGCM(plaintext_key)
        ciphertext = aes.encrypt(nonce, prompt_text.encode("utf-8"), session_id.encode("utf-8"))

        # Drop our reference to the plaintext key. Note: this only rebinds the
        # name; CPython does not guarantee the original bytes are wiped from
        # memory. It is a best-effort hygiene step, not a secure erase.
        del plaintext_key

        record: dict[str, Any] = {
            "session_id": session_id,
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_data_key": base64.b64encode(encrypted_key).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "decision": decision,
            "risk_score": risk_score,
            "matched_signature_ids": matched_signature_ids or [],
            "attack_intents": attack_intents or [],
            "agent_runtime_arn": agent_runtime_arn,
            "timestamp": int(time.time()),
        }

        s3_key = _write_evidence_to_s3(record)
        if s3_key:
            record["evidence_s3_key"] = s3_key

        return record

    except Exception:
        logger.exception("Encryption failed for session %s", session_id)
        return None


def _write_evidence_to_s3(record: dict[str, Any]) -> str | None:
    """Write an encrypted evidence record to S3."""
    bucket = config.EVIDENCE_S3_BUCKET
    if not bucket:
        return None

    try:
        session_id = record["session_id"]
        ts = record.get("timestamp", int(time.time()))
        decision = record.get("decision", "block")
        s3_key = f"sessions/{session_id}/{ts}-{decision}.enc.json"

        aws.client("s3", kind="inline").put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=json.dumps(record).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=config.KMS_KEY_ID,
        )
        return s3_key

    except (ClientError, Exception) as exc:
        logger.exception("Failed to write evidence to S3")
        report_degraded(
            EVIDENCE_STORE,
            f"evidence S3 write failed: {type(exc).__name__}",
            bucket=bucket,
        )
        return None
