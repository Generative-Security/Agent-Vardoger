# Security

## Reporting

Report suspected vulnerabilities privately to the maintainers rather than via a
public issue.

## Dependency auditing

Dependencies are pinned and audited. Run both audits with:

```bash
make audit          # python + frontend
make audit-python   # pip-audit against scripts/requirements-lambda.txt
make audit-frontend # npm audit against frontend/
```

- **Lambda runtime deps** are pinned in `scripts/requirements-lambda.txt` and
  installed for the Lambda platform (manylinux2014_x86_64, cp314) at package
  time. Bump versions deliberately and re-run `make audit-python`. The current
  pin set (including `fastapi==0.141.1`, `starlette==1.3.1`, `cryptography==50.0.0`)
  reports **no known vulnerabilities** under `pip-audit`.
- **Frontend deps** are in `frontend/package.json`. `axios` is pinned to
  `^1.8.2` or later (the fix for CVE-2025-27152, SSRF/credential leak).

## Authentication modes (self-hosted control plane)

`VARDOGER_AUTH_MODE` selects how the control plane authenticates callers:

- `token` (default, recommended single-operator): the Lambda Function URL is
  open at the URL layer, but every request must present
  `Authorization: Bearer <VARDOGER_AUTH_SECRET>`. `deploy.sh` generates and
  prints the secret if you do not supply one.
- `none` (DEV ONLY): open, unauthenticated admin API. Never use on the public
  internet.
- `cognito` / `cognito+identity-center` (team): API Gateway JWT authorizer in
  front of the control plane; roles come only from the verified
  `cognito:groups` claim. The SPA uses the Cognito Hosted UI (OAuth PKCE).

Roles are `viewer < operator < admin`; every non-health route is gated
server-side by `require_role`. The role is never read from an unverified token,
and the user-writable `custom:role` claim is not honored.

## Known hardening steps (accepted for v1)

- In `token` mode the shared secret lives in the Lambda environment and in the
  browser's `localStorage`, and the CSP `connect-src https:` permits connections
  to any HTTPS origin. This is acceptable for a single-operator v1. To harden:
  move the secret to an SSM SecureString read at runtime, and pin `connect-src`
  to your specific API origin at build time.

## Data at rest

- Self-hosted: the `PromptHistory` and `SessionRisk` DynamoDB tables use CMK
  (KMS) encryption (PromptHistory also has PITR); blocked-prompt evidence is
  envelope-encrypted to the evidence S3 bucket with the same CMK. (In the
  managed template it is `SessionRegistry` + `DetectionEvents` that carry CMK
  encryption.)
- The dashboard is served over HTTPS via CloudFront (Origin Access Control);
  the UI S3 bucket is private.
