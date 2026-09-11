# Architecture

## System Overview

Agent Vardøger is a three-tier AI agent session security monitor:

```
Your Environment (scope "local")        Managed Backend (optional)
┌────────────────────────┐              ┌──────────────────────────┐
│  AgentCore Gateway     │              │  Multi-scope analytics   │
│       │                │              │  Premium signatures      │
│  ┌────▼─────────────┐  │   telemetry  │  Cross-scope Tier 3      │
│  │ Dispatcher (T1)  │──┼──────────────►  ML inference hosting    │
│  │ Inline detection │  │              │  Evaluation benchmarks   │
│  └─┬───────────┬────┘  │              └──────────────────────────┘
│    │ allow     │ block │
│    ▼           ▼       │
│  Agent      Session    │
│  Runtime    Kill + SNS │
│                        │
│  ┌─────────────────┐   │
│  │ Tier 2 ML (opt) │   │  ← Self-hosted SageMaker or managed
│  │ Async scoring   │   │
│  └─────────────────┘   │
│                        │
│  ┌─────────────────┐   │
│  │ Tier 3 (sched)  │   │  ← Cross-session detection
│  │ Pattern/burst   │   │
│  └─────────────────┘   │
│                        │
│  ┌─────────────────┐   │
│  │ Control Plane   │   │  ← Dashboard + management API
│  │ (FastAPI)       │   │
│  └─────────────────┘   │
└────────────────────────┘
```

## Detection Tiers

### Tier 1 — Inline (< 30ms latency budget)

Runs synchronously in the gateway request path:
1. Prompt normalization (leet-speak, typos, Unicode tricks)
2. Regex signature scan (community + premium patterns)
3. Known-bad hash lookup
4. Detection policy (deterministic term-combination rules)
5. Per-prompt risk scoring with session accumulation

Decision: **allow** (pass through) or **block**.

A "block" always terminates the session. Whether it also refuses the triggering
prompt depends on `Tier1Mode`:

- **`sidecar`** (default) — the session is terminated and the prompt is passed
  through. Tier 1 holds the same lever as Tier 2 and Tier 3 (kill the session)
  rather than a second one of its own (refuse the call), so a detection
  component cannot take the agent offline. The triggering prompt may be
  answered; the next one is refused.
- **`gate`** — the prompt is additionally refused with HTTP 403. Choose this
  when a single successful malicious prompt is unacceptable on its own, such as
  one-shot data exfiltration.

### Tier 2 — Async (~600ms; ML classification optional)

Consumes the prompt intake queue after Tier 1 has decided. It always runs — it
is the only writer of `PromptHistory`, which the dashboard and Tier 3 read — and
takes one of four paths per prompt:

- **Tier 1 already blocked it** — stored for audit and used to raise session
  risk, but not classified (the prompt never reached the agent).
- **Tenant policy set `tier2_mode: off`** — recorded as a skip, no inference.
- **No ML endpoint configured** (the default) — recorded as a skip, no
  inference. Prompt history and Tier 3 still work; only the ML verdict is absent.
- **Scored** — the full path:
  1. Build session context (last 5 turns)
  2. Invoke ML classifier (Llama Prompt Guard 2 or equivalent)
  3. Deterministic scoring: regex + ML + behaviour + repetition + escalation - safe intent
  4. Cumulative session risk tracking
  5. Guarded kill eligibility (requires enforce mode + confidence + evidence)

Every path writes a result and an outcome-ledger row, so a prompt is never
silently dropped — a skip is visible as a skip, with the reason that caused it.

### Tier 3 — Scheduled (every 5 min, cross-session)

Scans recent prompt history across sessions:
- Exact hash repeats across sessions
- SimHash near-duplicates (hamming distance ≤ 3)
- Normalized prompt pattern bursts
- Category bursts (same attack type from multiple sessions)
- Session risk bursts (many sessions trending high simultaneously)
- Optional: semantic embedding clusters

## Scope and Source

Records carry two identity axes (full rationale in [../DESIGN-DECISIONS.md](../DESIGN-DECISIONS.md)):

- **`scope_id`** — the isolation / partition key on every table. Self-hosted is always `"local"`; managed injects a tenant id. Control-plane queries are always scoped by it first.
- **`source`** — `"<aws_account_id>/<agent>"`, a non-key segmentation attribute for filtering and rollups. Tier 3 groups across all sources in a scope, so a finding can span multiple accounts/agents (cross-account detection).

A third field, **`provenance`** (`dispatcher` / `tier2` / `tier3`), records which component produced a record. `scope_id` is a deploy-time constant and `source` is derived from the gateway-asserted account plus the deploy-time agent — neither is ever read from the request body.

## Access Control

The control plane enforces three roles — **viewer** < **operator** < **admin** — via a `require_role` dependency on every protected endpoint. Roles come from a verified Cognito JWT (`cognito:groups` claim). `VARDOGER_AUTH_MODE` selects `none` (local dev, admin), `cognito`, or `cognito+identity-center`. Under `cognito`, the control plane sits behind an API Gateway JWT authorizer; the open Lambda Function URL exists only when auth is `none`.

## Cost Attribution

Every taggable resource carries a consistent tag set — `Application=AgentVardoger`, `ManagedBy=agent-vardoger`, `Scope=<scope_id>`, `DeploymentModel=self-hosted|managed-agent` — plus an optional customer-defined cost-allocation tag (`CostAllocationTagKey`/`CostAllocationTagValue`). Activate these as cost-allocation tags to break out spend in AWS Cost Explorer. There is no in-app cost page by design.

## Key Design Principles

- **Attack-shaped input is always refused**: missing source identity or a body
  too large/deep to inspect, in either Tier 1 mode. These are evasion attempts,
  not failures.
- **Detection failure is fail-open by default** (`DetectionFailurePolicy`): if
  the engine cannot run, the prompt passes and the `DegradedComponents` alarm
  fires. A monitoring component that is broken should not also break the thing
  it monitors. Set `fail_closed` to invert this.
- **Scan everything forwarded**: All strings in the request body, not just one extracted field
- **Identity from platform only**: `scope_id`/`source` never come from the request body (prevents spoofing)
- **Backend-first RBAC**: Every control-plane permission is enforced server-side; the UI only mirrors it
- **Shadow by default**: Tier 2/3 default to log-only until explicitly set to enforce
- **Safe intent gates**: Prevents false-positive kills on legitimate business questions

## Module Boundaries

| Module | Responsibility |
|--------|---------------|
| `vardoger/detection/` | Platform-agnostic detection core |
| `vardoger/tier2/` | Async queue consumer: prompt history + optional ML classification |
| `vardoger/tier3/` | Cross-session pattern detection |
| `adapters/agentcore/` | AgentCore Gateway integration |
| `signatures/community/` | Open detection patterns |
| `control_plane/` | Dashboard and management API |
| `infra/` | CloudFormation templates |
