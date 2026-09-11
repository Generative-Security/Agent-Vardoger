# Capabilities by Deployment Mode

What Agent Vardøger actually does, what is on by default, and where the timing
claims hold. Every number here was measured or read from the code in this
repository rather than estimated.

## At a glance

| | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| **Sees** | one prompt | that prompt + the last 5 turns of the session | many sessions in a 5-minute window |
| **Catches** | known-bad patterns, hashes, policy rules | novel evasion, multi-turn escalation and staged exfiltration | coordinated campaigns across sessions |
| **Acts** | inline, before the agent replies | ~1 second later | every 5 minutes |
| **Can refuse a prompt** | only with `Tier1Mode=gate` | no — it terminates the session | no — it terminates the session |
| **Self-hosted** | on, 92 bundled signatures | deployed; ML optional (bring your own endpoint) | available, **off by default** |
| **+ signature subscription** | adds the premium feed | same feed, same scanner | unchanged |
| **Managed backend** | on | ML hosted for you | hosted, correlates across scopes |

> This table is duplicated verbatim in the project README. Change both together.

## The three deployment modes

| | Self-hosted | Self-hosted + premium signatures | Managed backend |
|---|---|---|---|
| Template | `infra/self-hosted.yaml` (57 resources) | same, plus subscription parameters | `infra/managed-agent.yaml` (15 resources) |
| Tier 1 inline detection | Yes | Yes | Yes |
| Tier 2 function | Deployed | Deployed | Runs in the managed backend |
| Tier 2 ML classification | Only if you attach a SageMaker endpoint | Same | Hosted for you |
| Tier 3 cross-session | Available, **off by default** | Same | Hosted, cross-scope |
| Prompt History | Yes | Yes | In the managed dashboard |
| Dashboard / control plane | CloudFront + Lambda | Same | Managed dashboard |
| Premium signatures | No | Cross-account S3 | Included |

**Tier 3 is not a managed-only feature.** It ships in the self-hosted template
and is enabled with `Tier3Enabled=true`, deploying a Lambda on a
`rate(5 minutes)` schedule. It is **off by default** because it runs on a timer
whether or not there is anything to find, and needs a meaningful volume of
prompt history before repeats and bursts separate from ordinary traffic. What
the managed service adds is *cross-scope* analysis — correlating across
customers and agents rather than only within your own `scope_id`.

**Tier 3 has no signatures of its own.** It ships no rule set and loads no
signature module. It reads the `matched_signatures` that Tier 1 already recorded
on each prompt, applies substring hints (`credential`, `exfil`, `secret`,
`system_prompt`) to weight findings, and otherwise detects statistically: exact
hash repeats, SimHash near-duplicates, category and pattern bursts, and
correlated session-risk spikes. Its findings are labelled synthetically as
`tier3-<method>`.

## The SLA that matters is time-to-kill

Every tier acts on the same lever: **terminate the session**. They differ only
in how long they take to reach it and what evidence they need.

| Tier | Evidence | Session closed to new prompts | `StopRuntimeSession` issued |
|---|---|---|---|
| Tier 1, `sidecar` | one prompt, signature/policy/risk | **immediately** (synchronous registry write) | deferred — SQS + alert Lambda, **~1 s** |
| Tier 1, `gate` | same | **immediately** | **inline, milliseconds** |
| Tier 2 | one prompt + last 5 turns, ML verdict | on the kill | **~1 second** — SQS + Lambda + endpoint invoke |
| Tier 3 | many prompts across many sessions | on the kill | **up to 5 minutes + runtime** — the schedule interval, not compute |

The two columns matter separately. Tier 1 marks the session terminated in the
registry **before it returns**, in both modes — so the very next prompt on that
session is refused by the dispatcher regardless of whether the runtime kill has
landed yet. The deferred `StopRuntimeSession` tears down the live runtime; the
registry write is what closes the door.

That is why deferring is safe: the window it opens is "the agent finishes
answering one prompt", not "the attacker gets another turn".

Only Tier 1 can refuse a prompt, and only in `gate` mode. The tiers are ordered
by evidence: Tier 1 acts instantly on cheap certainty, Tier 3 waits for a
pattern no single session could show.

The corollary is that **a tier failing does not open a hole in the others**. A
Tier 2 outage costs the ML verdict, not Tier 1's inline kill; a Tier 1 engine
failure passes the prompt and alarms, and Tier 2 still sees it.

## Tier 1 — inline, synchronous

**Always on, in every mode. The only tier in the request path — but by default
it does not gate that path.**

Runs inside the AgentCore Gateway REQUEST interceptor. On a detection it
terminates the session; `Tier1Mode` decides whether the triggering prompt is
also refused.

| `Tier1Mode` | Triggering prompt | Session marked terminated | Runtime kill |
|---|---|---|---|
| `sidecar` (default) | passed through and answered | immediately | deferred to the alert queue |
| `gate` | refused, HTTP 403 | immediately | inline |

Sidecar is the default so that every tier converges on one lever — terminate the
session — rather than Tier 1 alone owning a second one. A security component
that is wrong or broken then cannot refuse the agent's traffic; a false positive
costs one dead session instead of a failed request.

The kill is **deferred** rather than issued inline precisely so the agent can
finish the answer: a `StopRuntimeSession` fired before the passthrough returns
would race the response the sidecar just promised to deliver.

The trade is real: in sidecar mode a **one-shot** attack ("print every customer
record") is answered before the kill lands. Choose `gate` when a single
successful malicious prompt is itself the loss.

If the alert-queue publish fails, the dispatcher falls back to killing inline
and emits a degraded metric. The deferred kill has exactly one carrier and no
retry behind it, so a late answer is accepted in preference to a session that
was supposed to be terminated and silently never was.

- 92 bundled regex signatures + 6 known-bad hashes
  - 43 MITRE ATLAS-derived (prompt injection, jailbreak, data exfiltration, indirect injection)
  - 30 community intel (named jailbreaks, encoding attacks, multilingual bypass, workflow abuse)
  - 19 zero-day patterns (advanced evasion, tokenizer injection, agentic exploitation)
- Prompt normalization runs first (leet-speak, typos, Unicode tricks), so
  misspelling an attack does not evade the signature
- Deterministic term-combination policy rules
- Per-prompt risk scoring with session accumulation
- Operator-authored custom signatures, loaded inline

### Measured latency

Detection compute only — excludes DynamoDB, SQS, and cold start. Measured on a
developer workstation; **Lambda at 512 MB gets roughly a third of a vCPU, so
production numbers are likely slower, not faster.**

| Prompt size | p50 | Within 30 ms? |
|---|---|---|
| 26 chars (typical chat turn) | 0.9 ms | Yes |
| 61 chars (attack string) | 2.4 ms | Yes |
| ~2,000 chars | ~30 ms | At the limit |
| 4,000 chars | 59 ms | No |
| 16,000 chars | 234 ms | No |
| 64,000 chars | 1.06 s | No |
| 256,000 chars (parser cap) | 4.15 s | No |

Cost is **linear in prompt length** — 92 regexes over the text — at roughly
16 µs per character. The 30 ms budget holds below about **2,000 characters**.

On top of that the inline path makes 4 DynamoDB round trips and 1 SQS send per
prompt, plus about 10 ms of engine construction on a cold start.

**Implication:** a conversational agent stays inside budget comfortably. A
document-processing agent passing 10–50 KB of context per call will see
200 ms–1 s of added inline latency. There is currently no latency guard: the
parser admits 256 KB (`_MAX_INSPECTABLE_CHARS`) and the engine scans all of it.

## Tier 2 — asynchronous

**The function is deployed in every self-hosted deployment. The ML model is optional.**

Tier 2 is **not in the request path**, but it holds the same lever every tier
holds: terminating the session. It consumes prompts from SQS after Tier 1 has
decided, and its SLA is **time-to-kill**, not time-to-answer — it cannot refuse
the prompt that triggered it, but it can end the session before the next one.
Under the sidecar architecture that is the same lever Tier 1 uses, reached a
little later.

It runs regardless of ML because it is the only writer of `PromptHistory`, which
the Prompt History page and Tier 3 both read. Four paths per prompt:

| Path | When | Recorded as |
|---|---|---|
| Layer 1 blocked | Tier 1 already blocked it | audit only; raises session risk |
| Policy off | tenant set `tier2_mode: off` | `tier2_disabled` |
| No endpoint | **the default deployment** | `tier2_no_endpoint` |
| Scored | an ML endpoint is attached | full classification + enforcement |

With ML attached it detects single-prompt attacks using novel evasion, and
multi-prompt single-session patterns (escalation, repetition, staged
exfiltration) using the last 5 turns of session context.

**Timing:** SQS delivery + Lambda + SageMaker invoke, typically under a second;
the Lambda timeout is 60 s. This is detection latency, not request latency — the
prompt has already been answered.

### Self-hosting the model

[docs/tier2-setup.md](tier2-setup.md) recommends **Llama Prompt Guard 2**
(86M, or 22M for high volume) rather than fine-tuning a general-purpose encoder.
It is purpose-built for injection and jailbreak detection and needs no training;
its positive-class label is already in the handler's `ATTACK_LABELS`, so it drops
in without a mapping layer. Note it ships under the Llama Community License, not
Apache 2.0 — check the acceptable-use terms before commercial deployment.

Because Tier 2 is asynchronous, a slower and more accurate model is usually the
better trade: latency here delays a kill, not the user's answer.

Note the **512-token limit** shared by these encoders — a long prompt is
truncated, so an attack in the tail of a large document is not seen unless you
chunk and score each window. The repo ships no deployment script; you create the
SageMaker endpoint yourself.

## Tier 3 — scheduled, cross-session

**Off by default** (`Tier3Enabled=false`). When enabled it runs every 5 minutes
(`Tier3Schedule`), 120 s timeout, up to 2,000 prompts per run.

It has **no signature set of its own** — see the note at the top of this
document. It also depends on Tier 2 running, since Tier 2 is what writes the
`PromptHistory` rows it reads.

Correlates across sessions within your scope: exact hash repeats, SimHash
near-duplicates (Hamming distance ≤ 3), normalized pattern bursts, category
bursts, and simultaneous session-risk spikes — for example several sessions
probing the same data source at once.

**Timing:** detection latency is *up to the 5-minute schedule interval plus
runtime*, not seconds. It is a batch job, not a request-path check.

The managed service extends this across scopes; self-hosted sees only its own.

## Enforcement and failure behavior

### What is on by default

| Control | Default | Effect |
|---|---|---|
| Tier 1 session kill | **on, not gated** | a Tier 1 `block` calls `StopRuntimeSession` in both modes |
| `Tier1Mode` | `sidecar` | the triggering prompt is passed through; the session still dies |
| `Tier3Enabled` | `false` | Tier 3 is not deployed |
| `Tier2KillEnabled` | `false` | Tier 2 never terminates |
| `Tier3KillEnabled` | `false` | Tier 3 never terminates |
| `GlobalKillEnabled` | `false` | master switch — both Tier 2 and Tier 3 kills require it |
| `tier2_mode` / `tier3_mode` | `shadow` | log what *would* have happened |
| Unrecognized mode value | falls back to `shadow` | an unknown mode is never read as `enforce` |

Tier 2 and Tier 3 enforcement requires **three** switches to align — mode
`enforce`, `GlobalKillEnabled`, and the per-tier flag — plus per-finding
confidence, evidence, and session-count guards. Out of the box the system
**detects and alerts; only Tier 1 terminates.**

### What is refused, and why

The distinction that matters is **attack-shaped input** versus **component
failure**. Attack-shaped input is refused in every configuration; a failure of
the security component itself is not allowed to take the agent down with it.

| Condition | Classified as | Behavior |
|---|---|---|
| Body too large or too deeply nested to inspect | attack (evasion by overflow) | **always refused**, both modes |
| No source identity established | attack (unattributable, unscopable) | **always refused**, both modes |
| Session already terminated | prior decision being enforced | **always refused** |
| Tier 1 detection | detection | session terminated; prompt refused only in `gate` mode |
| Detection engine raises / dependency down | failure | `DetectionFailurePolicy`, default `fail_open` — prompt passes, `DegradedComponents` alarm fires |
| Telemetry (SQS) send fails | failure | `TRANSPORT_FAILURE_POLICY`, default `allow_and_mark_degraded` |

Fail-open is only responsible because the silence is visible: the
`DegradedComponents` CloudWatch alarm publishes to the security SNS topic on any
degraded security function, and when detection cannot run it is the **only**
record that traffic went uninspected.

Tier 2 and Tier 3 have no fail-closed option at all: they run after the response
has been delivered. A Tier 2 failure sends the record to a dead-letter queue.

## Upgrading self-hosted to managed

This is a **redeploy, not a re-point.** The self-hosted stack hardcodes
`VARDOGER_TELEMETRY_MODE: local` with no parameter to flip it, so the managed
model is a separate template (`infra/managed-agent.yaml`) deploying the
dispatcher and alert Lambda only — no Tier 2/3, no control plane, no dashboard.

`POST /api/settings/managed-upgrade` (admin) records intent and returns switch
instructions. It does not migrate data. Because self-hosted records are
partitioned by `scope_id = "local"`, the managed service issues a new scope id
and existing history stays behind in your tables.

The managed template wires telemetry **outbound only**. There is no inbound path
for the managed backend to terminate a session in your account, so from your
side managed Tier 2/3 are detect-and-alert.
