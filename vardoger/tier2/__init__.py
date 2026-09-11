"""Tier 2 — Async ML-based prompt classification.

Optional self-hosted SageMaker (or compatible) endpoint that classifies
prompts after they pass Tier 1 inline detection. Applies guarded risk
scoring with safe-intent gates to prevent false-positive kills.

Users can choose to:
- Skip Tier 2 entirely (regex-only detection)
- Self-host a DistilBERT or equivalent model on SageMaker
- Point to the managed Agent Vardøger ML endpoint (Model 2)
"""
