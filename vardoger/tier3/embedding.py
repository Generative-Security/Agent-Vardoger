"""Optional embedding adapters for Tier 3.

Embeddings are disabled by default. The deployed Lambda can optionally
call a SageMaker embedding endpoint when explicitly enabled.
"""
from __future__ import annotations

import json
import os
from typing import Protocol

from vardoger import aws


class Embedder(Protocol):
    """Protocol implemented by Tier 3 embedding providers."""

    model_version: str

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one embedding vector per input text."""


class DisabledEmbedder:
    """Embedding provider used when Tier 3 semantic clustering is disabled."""

    model_version = "disabled"

    def embed(self, texts: list[str]) -> list[list[float]]:
        return []


class SageMakerEmbedder:
    """Embedding provider that invokes a SageMaker endpoint."""

    def __init__(self, endpoint_name: str, model_version: str = "") -> None:
        self.endpoint_name = endpoint_name
        self.model_version = model_version or endpoint_name
        # Async profile: Tier 3 runs on a schedule, off the request path.
        self._runtime = aws.client("sagemaker-runtime")

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = self._runtime.invoke_endpoint(
            EndpointName=self.endpoint_name,
            ContentType="application/json",
            Body=json.dumps({"inputs": texts}),
        )
        payload = json.loads(response["Body"].read())
        if isinstance(payload, dict):
            payload = payload.get("embeddings", payload.get("vectors", []))
        if not isinstance(payload, list):
            return []
        return [[float(value) for value in vector] for vector in payload if isinstance(vector, list)]


def get_embedder() -> Embedder:
    """Return the configured embedding provider."""
    endpoint = os.environ.get("VARDOGER_TIER3_EMBEDDING_ENDPOINT", "").strip()
    enabled = os.environ.get("VARDOGER_TIER3_EMBEDDING_ENABLED", "false").lower() == "true"
    if enabled and endpoint:
        return SageMakerEmbedder(endpoint, os.environ.get("VARDOGER_TIER3_EMBEDDING_MODEL_VERSION", endpoint))
    return DisabledEmbedder()
