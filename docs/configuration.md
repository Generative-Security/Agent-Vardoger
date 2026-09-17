# Configuration reference

Every environment variable `scripts/deploy.sh` reads, what it defaults to,
and what it changes. Each maps to a CloudFormation parameter of the same
concept; leaving one unset applies the default shown, which is also the
template's default.

Deploying for the first time? [The quick start](quickstart.md) covers the
handful of variables you actually need — everything here is optional.

## Required

| Variable | Description |
|---|---|
| `VARDOGER_GATEWAY_ARN` | The AgentCore Gateway to protect. The script exits without it. |
| `VARDOGER_AGENT_RUNTIME_ARN` | The agent runtime behind that gateway. Authoritative for `StopRuntimeSession`, so it is deploy-time config and never read from a request. |

**Both become optional when `VARDOGER_NEW_HARNESS=true`**, which builds its own
gateway and has no agent runtime to terminate.

## Test harness

| Variable | Default | Description |
|---|---|---|
| `VARDOGER_NEW_HARNESS` | `false` | Build a self-contained test gateway — MCP protocol, a callable echo tool, `CUSTOM_JWT` inbound auth with its own Cognito pool, and the dispatcher pre-attached as a REQUEST interceptor. Adds 10 resources. For evaluating Vardøger, not for production. See [test-harness.md](test-harness.md). |

## Recommended

| Variable | Default | Description |
|---|---|---|
| `VARDOGER_ALERT_EMAIL` | *(none)* | Subscribes an address to the security SNS topic. **Leaving this unset on a re-run deletes an existing subscription** and alerts stop silently. |

## Enforcement posture

| Variable | Default | Values | Description |
|---|---|---|---|
| `VARDOGER_TIER1_MODE` | `sidecar` | `sidecar`, `gate` | `sidecar` terminates the session and lets the triggering prompt through; `gate` also refuses it (JSON-RPC error on an MCP gateway, HTTP 403 on a protocol-less one). Both kill the session. |
| `VARDOGER_DETECTION_FAILURE_POLICY` | `fail_open` | `fail_open`, `fail_closed` | What happens when detection cannot run at all. `fail_open` passes the prompt and raises the `DegradedComponents` alarm. Does **not** apply to an uninspectable body or a request with no source identity — those are always refused. |
| `VARDOGER_GLOBAL_KILL_ENABLED` | `false` | `true`, `false` | Master switch for Tier 2/3 session termination. |
| `VARDOGER_TIER2_KILL_ENABLED` | `false` | `true`, `false` | Lets Tier 2 terminate sessions. Necessary but not sufficient — see the note below. |
| `VARDOGER_TIER3_KILL_ENABLED` | `false` | `true`, `false` | Lets Tier 3 terminate sessions. Same caveat. |

> **A kill flag alone does not enable kills.** Tier 2/3 termination needs the
> per-scope policy set to `enforce` (a dashboard setting, default `shadow`),
> **plus** `GlobalKillEnabled`, **plus** the per-tier flag, **plus** the
> per-finding confidence and evidence guards. When a kill is declined the
> outcome ledger records which gate stopped it.

## Observability

| Variable | Default | Description |
|---|---|---|
| `VARDOGER_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`, applied to every Vardoger Lambda. At `INFO` the dispatcher emits one line per evaluated prompt — decision, risk score, session id, whether that session id was asserted by the gateway or synthesised, source, envelope and matched signatures. Below `INFO` a *working* dispatcher writes nothing at all, so an empty log group cannot be distinguished from an interceptor that was never invoked. **Prompt text is never logged at any level**; encrypted evidence is where content lives. |

## Detection tiers

| Variable | Default | Description |
|---|---|---|
| `VARDOGER_ML_ENDPOINT` | *(none)* | SageMaker endpoint for Tier 2 ML classification. Empty means the Tier 2 function still runs and still writes prompt history — it just records `tier2_no_endpoint` instead of a verdict. See [tier2-setup.md](tier2-setup.md). |
| `VARDOGER_TIER3_ENABLED` | `false` | Deploys the Tier 3 cross-session analyser on a 5-minute schedule. Off by default because it runs whether or not there is anything to find, and needs real traffic volume before bursts separate from noise. |

## Authentication

| Variable | Default | Description |
|---|---|---|
| `VARDOGER_AUTH_MODE` | `token` | `token` (shared bearer secret), `cognito` / `cognito+identity-center` (team RBAC), or `none` (**dev only, open**). |
| `VARDOGER_AUTH_SECRET` | *(generated)* | Only for `token` mode. Generated and printed once on first deploy. **Leave unset when re-deploying** — omitting it preserves the existing secret; setting it rotates it. |

## Premium signatures

Set these before deploying; `deploy.sh` forwards them to the stack.

| Variable | Default | Description |
|---|---|---|
| `VARDOGER_PREMIUM_SIGNATURE_BUCKET` | *(none)* | Cross-account bucket granted by the AWS Marketplace subscription. Empty means community signatures only. |
| `VARDOGER_PREMIUM_SIGNATURE_PREFIX` | `premium/` | Object prefix within that bucket. |
| `VARDOGER_PREMIUM_SIGNATURE_ROLE_ARN` | *(none)* | Cross-account role to assume. Leave empty when the bucket policy grants your account directly. |

## Test Console

| Variable | Default | Description |
|---|---|---|
| `VARDOGER_TEST_CONSOLE_GATEWAY_TOKEN` | *(none)* | Server-side default for the gateway's inbound OAuth token, so it need not be pasted into the browser. Read by the control plane, not by `deploy.sh`. |
| `VARDOGER_MCP_PROTOCOL_VERSION` | `2025-11-25` | Protocol version sent as `MCP-Protocol-Version`. **Usually leave this unset.** Supported versions vary per gateway, so the Test Console reads the supported list out of a rejection and retries once on the gateway's terms; setting this only changes which version is tried first. |

## Script behaviour

| Variable | Default | Description |
|---|---|---|
| `AWS_REGION` | `us-east-1` | Also settable as the first positional argument: `./scripts/deploy.sh eu-west-1`. |
| `SKIP_FRONTEND` | *(unset)* | Set to `1` to skip the dashboard build and upload. Useful where disk is tight, such as AWS CloudShell. |

Stack name is the second positional argument, defaulting to `agent-vardoger`:
`./scripts/deploy.sh us-east-1 my-stack`.

## Re-running on an existing stack

`deploy.sh` passes every value above on **both** of its CloudFormation passes, so
an unset variable is applied as its default rather than leaving the current
value alone. Before re-deploying, read back what is live:

```bash
aws cloudformation describe-stacks --stack-name agent-vardoger   --query "Stacks[0].Parameters[].[ParameterKey,ParameterValue]" --output table
```

Re-export anything non-default — `VARDOGER_ALERT_EMAIL` above all — then deploy.
The script prints the effective configuration before it applies anything; check
that block against the table.

Two things are preserved automatically and should be left unset: the auth secret
(omitting the override is what keeps it) and the Function URL, CloudFront domain
and dashboard URL, which do not regenerate.

## Signing out

The dashboard header carries a **Sign out** control in every mode except
`none`. What it does depends on the mode, and the difference matters on a
shared machine:

- **`cognito`** — clears the stored token and the in-flight PKCE state, then
  redirects to the Cognito Hosted UI `/logout` endpoint. That last step is the
  one that ends the *IdP* session. Clearing browser storage alone would leave
  the Cognito session cookie intact, so the next sign-in would complete
  silently with no prompt: a sign-out that looks like it worked and did not.
- **`token`** — clears the stored secret and returns to the sign-in view. There
  is no IdP session to end.

**Token lifetime differs by mode**, which surprises people moving from `token`
to `cognito`. The `token`-mode shared secret is static and never expires, so a
browser stays signed in indefinitely. Cognito access tokens expire (an hour by
default), so the console will ask you to sign in again — that is the mode
working, not a fault.

An expired Cognito token presents badly: the API Gateway authorizer rejects the
request before it reaches the app, and that rejection carries no CORS headers,
so the browser reports a **network error** rather than a 401. If the dashboard
suddenly shows "Network Error" or "Could not load sources", sign in again
before suspecting the deployment — and confirm with
`curl <api-url>/api/health`, which needs no credentials in any mode.

## Removing the stack

```bash
aws cloudformation delete-stack --stack-name agent-vardoger
```

**Empty the S3 buckets first.** CloudFormation cannot delete a bucket that still
has objects in it, and the stack has two, both named deterministically:

| Bucket | Holds |
|---|---|
| `vardoger-evidence-<account>` | Encrypted prompt evidence |
| `vardoger-ui-<account>-<region>` | The dashboard build |

A delete against a non-empty bucket leaves the *bucket* behind even when the
rest of the stack goes. Because the names are derived rather than generated, the
next deploy asks for a name that already exists and the changeset fails during
`AWS::EarlyValidation::ResourceExistenceCheck` — which reads as a template
problem rather than as leftover state. Empty them before deleting:

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
aws s3 rm "s3://vardoger-evidence-${ACCOUNT}" --recursive
aws s3 rm "s3://vardoger-ui-${ACCOUNT}-${REGION}" --recursive
```

If the stack is already gone and the buckets are not, the same two commands
followed by `aws s3 rb` on each clears the collision.

A third bucket, `agent-vardoger-<account>-<region>`, holds the packaged Lambda
code. `deploy.sh` creates it outside CloudFormation, so the stack never touches
it and re-running the deploy reuses it. Leave it unless you are removing
Vardøger entirely.

## Not exposed as variables

These are CloudFormation parameters with no `deploy.sh` variable. Pass them with
`--parameter-overrides` on a manual `aws cloudformation deploy`, or edit the
template: `DetectionRetentionDays` (90), `SessionTtlMinutes` (30),
`Tier3Schedule` (`rate(5 minutes)`), `DispatcherReservedConcurrency` (0),
`CostAllocationTagKey` / `CostAllocationTagValue`, `ScopeId` (`local`;
self-hosted is always this scope) and `DeploymentModel`.
