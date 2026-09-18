# Signatures

## Overview

Agent Vardøger uses regex-based signatures to detect prompt injection, jailbreaks, and other attacks. Signatures are organized into tiers:

## Community Signatures (included)

Shipped with the repository and updated via pull requests:

- **MITRE ATLAS patterns** — prompt injection, jailbreak, indirect injection, data exfiltration
- **Named jailbreaks** — DAN, STAN, DUDE, AIM, skeleton key, developer mode
- **Encoding attacks** — base64, ROT13, hex-encoded instructions
- **Multilingual bypass** — common injection phrases in Spanish, French, Japanese, Chinese, Russian, Arabic
- **Tokenizer injection** — special tokens ([INST], <|im_start|>, etc.)
- **Agentic exploitation** — tool call injection, multi-agent compromise, data exfiltration via tools
- **Known-bad hashes** — SHA-256 lookup table of confirmed malicious prompts

## Premium Signatures (AWS Marketplace subscription)

Premium signatures are delivered through a private **AWS Marketplace subscription**, not an in-app payment. Contact us at [sales@generativesecurity.ai](mailto:sales@generativesecurity.ai) to subscribe. When you subscribe, your AWS account is granted cross-account read access to an S3 bucket holding the latest premium signatures. Configure the scanner with:

- `VARDOGER_PREMIUM_SIGNATURE_BUCKET` — the cross-account bucket name
- `VARDOGER_PREMIUM_SIGNATURE_PREFIX` — object prefix (default `premium/`)
- `VARDOGER_PREMIUM_SIGNATURE_ROLE_ARN` — optional cross-account role to assume; when empty, the bucket policy grants access directly

The scanner loads premium signatures through the **same validation pipeline** as community ones (ReDoS screen, minimum-pattern floor, optional manifest-hash integrity check) and merges them **append-only**: premium may add new ids but can never override or replace a bundled community signature by reusing its id, so a compromised feed cannot neuter community detections. If the bucket is unset or a load fails, the scanner degrades to the community-only set and emits a `premium_signatures` degraded metric.

> **Package size floor:** a premium package must contain at least
> `VARDOGER_SIGNATURE_MIN_PATTERNS` valid patterns (default **20**) or the whole
> package is rejected and the scanner stays community-only. A single invalid
> regex, or one flagged for catastrophic backtracking, rejects the entire
> package — not just that entry.

Premium content includes:

- **Social engineering** — authority impersonation, urgency manipulation, context manipulation
- **Business logic abuse** — account takeover, refund fraud, employee safety
- **Advanced evasion** — virtual terminal simulation, gradual escalation
- **Rapid response** — new patterns published quickly after disclosure

## Self-Authored Signatures

Add your own patterns to `signatures/community/` following the format:

```python
RegexPattern(
    id="sig-custom-001",
    severity="high",        # critical, high, medium, low
    category="your_category",
    pattern=r"(?i)your\s+regex\s+here",
    mitre_atlas_id="",      # optional
)
```

All patterns are validated against:
- ReDoS screening (catastrophic backtracking detection)
- Regex compilation check
- False-positive test suite

## Dynamic Loading

The SignatureScanner supports runtime updates without redeployment:
1. Bundled community patterns (always available)
2. Your own signatures in S3 (versioned with manifest.json + SHA-256 integrity)
3. Premium patterns from the Marketplace cross-account bucket (see above)

Pattern refresh interval: 300 seconds (configurable via `VARDOGER_SCANNER_REINIT_SECONDS`).

## Tier 2 ML Self-Hosting Guide

For teams that want ML-based classification (Tier 2) without the managed backend:

1. Download a purpose-built prompt-injection classifier (Llama Prompt Guard 2 recommended)
2. Deploy as a SageMaker endpoint accepting `{"inputs": "text"}` format
3. Set `VARDOGER_ML_ENDPOINT` to your endpoint name
4. The scoring pipeline handles safe-intent gating, behaviour analysis, and session accumulation on top of whatever label the model returns

See [docs/tier2-setup.md](tier2-setup.md) for detailed instructions.

## Control plane signature endpoints

The control plane exposes signature management under `/api/signatures`:

- `GET /api/signatures` (viewer role) — returns community signature metadata
  (count and distinct categories, derived by introspecting the
  `signatures.community` package) plus premium status. Premium is considered
  enabled when the `VARDOGER_PREMIUM_SIGNATURE_BUCKET` environment variable is
  set. The response also includes a Marketplace link placeholder
  (`VARDOGER_MARKETPLACE_URL`, empty by default) and the customer's AWS account
  id (`VARDOGER_AWS_ACCOUNT_ID`, empty by default). There is no in-app payment.
- `POST /api/signatures/custom` (admin role) — authors a custom signature.

### Custom signature storage

Custom signatures are stored in the existing `TENANTS_TABLE` (env var
`VARDOGER_TENANTS_TABLE`), keyed by `scope_id`, appended to a
`custom_signatures` list attribute on the scope's record. We reuse the existing
scope-keyed table rather than introducing a new one, keeping the isolation model
consistent (every record is partitioned by `scope_id`; self-hosted is `"local"`).
