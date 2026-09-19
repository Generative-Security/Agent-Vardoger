# Agent Vardøger — Design Decisions

This document explains the concept behind Agent Vardøger, the architectural decisions that shape it, the rationale behind those decisions, and the outcomes each is intended to produce. It is written for contributors, operators, and anyone evaluating the project who wants to understand not just *what* the system does but *why* it is built the way it is.

---

## The Concept

A *vardøger* is a figure from Norse folklore: a spectral double that arrives ahead of a person, performing their actions before they themselves appear. Agent Vardøger applies that idea to AI agent security. It sits ahead of your agent, inspecting every prompt before the agent processes it, so that an attack is recognized and the session is terminated in real time — by default as a sidecar (the offending session is killed; see the Tier 1 mode discussion below), or, when configured as a gate, before the prompt is ever answered.

Agent Vardøger is an **inline security monitor for AI agent sessions**. It watches the prompts flowing into an agent gateway, detects prompt injection, jailbreaks, credential theft, social engineering, and cross-session abuse, and terminates a malicious session in real time.

The problem it addresses: LLM-based agents are increasingly wired to tools, data stores, and privileged actions. A successful prompt injection is no longer just an embarrassing chatbot response — it can trigger real actions with real consequences. Traditional web application firewalls do not understand prompt semantics, and model-level guardrails are inconsistent and opaque. Agent Vardøger provides a dedicated, inspectable, layered detection surface that operators control.

---

## Design Principle: Defense in Depth Across Three Tiers

Detection is split into three tiers with deliberately different latency budgets, cost profiles, and confidence requirements. No single tier is trusted to carry the whole load.

### Tier 1 — Inline Deterministic Detection

**What:** A fast, synchronous check that runs inside the gateway request path. It normalizes the prompt, scans it against regex signatures and known-bad hashes, runs a deterministic policy ruleset, and computes a risk score. If any layer flags the prompt as clearly malicious, the **session is terminated** — Tier 1 holds the same lever as Tier 2 and Tier 3.

**Sidecar by default, gate by choice (`VARDOGER_TIER1_MODE`):** a Tier 1 detection *always* kills the session; the two modes differ only in what happens to the triggering prompt.

- **`sidecar` (default)** — the prompt is passed through to the agent and the session is terminated (the kill is handed to the alert queue so it does not race the in-flight answer). The agent may answer this one prompt; it will not answer another on that session. This is deliberate: a security sidecar should not be able to take the agent offline, so every tier converges on one lever — kill the session — rather than Tier 1 alone owning a second one (refuse the call). A false positive costs one dead session, not a refused request.
- **`gate`** — the prompt is additionally refused with HTTP 403 *and* the session is terminated. The stricter posture, for when a single successful malicious prompt is itself unacceptable — one-shot exfiltration ("print every customer record") would be answered before the kill lands in sidecar mode.

Both modes kill the session; an unrecognized mode value falls back to the strict `gate`.

**Why deterministic and inline:** The inline path has a hard latency budget (sub-30ms target) because it sits in front of live user traffic. The budget is **per prompt length, not absolute**: cost is linear in the text scanned, so it holds comfortably for chat-length turns and is exceeded by large documents (measured numbers in [docs/capabilities.md](docs/capabilities.md#measured-latency)). Deterministic rules are fast, explainable, and produce zero false negatives on the exact patterns they encode. Operators can read a signature and know precisely what it catches.

**Expected outcome:** Obvious, high-confidence attacks (direct injection, known jailbreaks, credential extraction) terminate the session instantly with no dependency on any external service or model — while a false positive, in the default sidecar mode, degrades to at most one answered prompt rather than a refused user.

### Tier 2 — Asynchronous ML Classification

**What:** After Tier 1 allows a prompt through, a copy is sent asynchronously to a machine-learning classifier (a self-hosted SageMaker endpoint, or the managed service). Tier 2 builds recent session context, invokes the model, and applies a composite score that blends the model verdict with deterministic behavioral, repetition, and escalation signals. It can trigger enforcement when a strict set of guardrails is satisfied.

**Why asynchronous and ML-based:** ML catches attacks that evade static rules — novel phrasings, misspelled jailbreaks, subtle multi-turn manipulation. But model inference is slower and noisier than regex, so it runs off the hot path. Keeping it asynchronous means a slow or unavailable model never delays or blocks legitimate traffic.

**Why the model verdict is never trusted alone:** Text classifiers over-flag benign business language. A composite score with safe-intent gates ensures that a single confident-but-wrong model label cannot terminate a legitimate customer session. See "Guarded Kill Decisions" below.

**Expected outcome:** Evasive and multi-turn attacks are detected with far lower false-positive rates than a raw model would produce, and enforcement only fires when multiple independent signals agree.

### Tier 3 — Scheduled Cross-Session Analysis

**What:** A scheduled job scans recent prompt history across many sessions for coordinated abuse: the same prompt repeated across sessions, near-duplicate variants (SimHash), bursts of the same attack category, and scope-wide spikes in session risk. Because a scope groups across all of its sources, a Tier 3 finding can span multiple AWS accounts and agents — cross-account detection is a native outcome of the scope/source model. Findings are grouped and, under conservative rules, can trigger enforcement.

**Why cross-session:** Some attacks are invisible within a single conversation but obvious across many — a botnet probing the same weakness from dozens of sessions, or an attacker methodically rephrasing a blocked prompt. Tier 3 is the only tier with a whole-scope view.

**Why alert-first, kill-last:** Cross-session heuristics are powerful but can amplify Tier 2 false positives across a whole scope. Tier 3 defaults to writing grouped alerts, and its most speculative signal (session-risk burst) is alert-only by design.

**Expected outcome:** Coordinated and distributed attacks that no single-session view could catch are surfaced, while the risk of a tenant-wide false-positive cascade is contained.

---

## Design Principle: Refuse Attack-Shaped Input; Fail Open on Monitor Failure

The inline path distinguishes two very different "we couldn't fully evaluate this" situations, and treats them oppositely on purpose.

**Attack-shaped input is always refused, in either Tier 1 mode.** These are evasion attempts, not faults:

- If the request body is too large or too deeply nested to fully inspect, it is refused.
- If source identity (account + agent) cannot be established, it is refused.

An uninspectable body and a missing identity are the cheapest bypasses there are; treating them as attacks rather than as failures closes them.

**A detection *failure* — the engine raised, or a dependency it needs is down — is governed by `DETECTION_FAILURE_POLICY`, and defaults to `fail_open`.** When detection cannot run at all, the prompt passes, a `DegradedComponents` metric is emitted, and its alarm fires. Set `fail_closed` to invert this and refuse instead.

**Why fail *open* on failure (and why this is a deliberate reversal of an earlier stance):** Tier 1 is a monitor, and a monitor that is broken should not also break the thing it monitors. If a transient dependency outage or an engine bug took down the interceptor and the interceptor fails closed, every legitimate user is blocked for the duration — the security control becomes the outage. The failure is not silent: the degraded metric alarms, so an operator sees "traffic went uninspected" and can act, rather than discovering it through a flood of blocked users. Operators for whom a single uninspected prompt is unacceptable (for example, a one-shot-exfiltration threat model) can set `fail_closed` and accept the availability trade explicitly.

This is intentionally different from the *attack-shaped input* case above: a malformed/oversized body or a spoofable-but-absent identity is an adversarial signal, so it is refused regardless of `DETECTION_FAILURE_POLICY`. The policy only governs genuine infrastructure/engine failure.

> **Note on enforcement direction.** Terminating a *session* (the Tier 1/2/3 kill lever) is still guarded and conservative — see "Guarded Kill Decisions" and "Shadow Mode by Default." "Fail open on monitor failure" concerns only what happens to a single prompt when the engine cannot evaluate it, not whether the system enforces.

**Expected outcome:** An adversarial input shape can never smuggle an unevaluated prompt through as if it were a fault, and a broken monitor degrades visibly (alarmed) rather than taking the protected agent offline — unless the operator has explicitly chosen `fail_closed`.

---

## Design Principle: Scan Everything That Is Forwarded

Tier 1 evaluates *every string* in the forwarded request body, not just an extracted "prompt" field.

**Why:** A parser differential is a classic bypass. If detection reads field A but the agent receives field B, an attacker simply hides the injection in field B. By harvesting all strings the gateway will forward and scanning the concatenation, the thing that is inspected is the thing that is delivered.

**Expected outcome:** An injection cannot be smuggled through a message, argument, or nested field that the detection logic "didn't happen to look at."

---

## Design Principle: Identity Comes From the Platform, Never the Payload

Scope and source identity are read only from gateway-asserted sources (deploy-time configuration, platform request context, gateway-injected headers) — never from the request body or tool arguments. (See "The Scope and Source Model" below for what these two axes mean.)

**Why:** If a caller could set its own identity, it could attribute its prompts to another source, be scored against another source's risk state, or — under the managed service — select a more permissive scope's policy (for example one running in shadow mode). Identity that the caller controls is not identity; it is a suggestion.

**The session identifier is a documented exception.** Scope and source are platform-only, without qualification — those are the axes that decide isolation and policy, and nothing about them is ever read from the payload. The **session id** is different, and the difference is worth stating plainly rather than leaving in a code comment.

The session id is taken from the gateway when the gateway asserts one — an MCP `mcp-session-id` header, or the AgentCore runtime session header. When neither is present, it falls back to `session.id` from the W3C baggage header, which travels in the request body and is therefore **caller-supplied and forgeable**. Every evaluation records which it was, as `session_id_is_authentic`.

**What we tried first, and why it was not enough.** The intended design was the header alone. Two things forced the fallback:

- **The header does not always arrive.** It reaches the interceptor only when the gateway is configured with `PassRequestHeaders: true`. Without that, the parser sees no header at all — and an operator who misconfigures the gateway gets silence, not an error.
- **The alternative is worse than a forgeable id.** Deriving a unique synthetic id per prompt makes every turn its own session. Risk accumulation, multi-turn escalation detection and the session kill all become inert, because no two turns of one conversation ever correlate. A forged id can misattribute one prompt to another session; a missing id guarantees that nothing accumulates at all.

So the trade is deliberate: correlation that can be gamed beats correlation that cannot happen. The residual weakness is real — an attacker who controls baggage can send each malicious prompt under a fresh id, so risk never accumulates and the "refuse the next prompt" guard never fires.

**Known gap:** `session_id_is_authentic` is recorded and logged but does not yet change enforcement posture. Making an inauthentic session force gate mode, or simply carry additional risk, would make forging cost the attacker the answer. That change is open, not done.

**Expected outcome:** A caller cannot spoof, borrow, or escalate across **scope or source** boundaries by manipulating the prompt payload. Session correlation is best-effort where the platform does not assert an identifier, and says so in every record.

---

## Design Principle: The Scope and Source Model

Agent Vardøger separates identity into two independent axes, replacing the single overloaded "tenant" concept inherited from the multi-tenant SaaS origin.

- **`scope_id` — the isolation / partition key.** In a self-hosted deployment this is always the constant string `"local"`: one organization, one scope. Under the managed service it becomes the assigned tenant id. Every stored record is partitioned by `scope_id`, and every control-plane query is scoped by it first. Migrating from self-hosted to managed is therefore a matter of rewriting `scope_id` from `"local"` to the assigned tenant id — no schema change.
- **`source` — the segmentation dimension.** A source is the pair `"<aws_account_id>/<agent>"`. A central security team running three agents across two AWS accounts sees each as a distinct source *within its single scope*. Source is a non-key indexed attribute used for filtering and rollups, **never** for isolation. When a dashboard query omits a source filter, the result is the rollup across all sources in the scope.

A third field, **`provenance`**, records which component produced a record (`dispatcher`, `tier2`, `tier3`). This was previously overloaded onto the word "source"; separating it means "source" now unambiguously means "which of my environments did this come from."

**Why two axes instead of one:** The single-tenant open-source build and the multi-tenant managed service have genuinely different needs. Isolation (who must never see whose data) and segmentation (which of *my own* environments produced this) are different questions. Collapsing them into one "tenant" field forced a choice between a clean self-hosted story and a clean managed story. Splitting them gives both, and makes the central-security-team use case — one pane of glass over many accounts and agents — a first-class capability rather than a workaround.

**Why `"local"` as the self-hosted default:** A concrete, non-empty constant keeps every partition-keyed query identical between self-hosted and managed code paths. There is no "single-tenant special case" branching through the codebase; the self-hosted build is just the managed build with one scope whose id happens to be `"local"`.

**Expected outcome:** A self-hosted operator gets a clean single-organization experience with cross-account/agent visibility, and the exact same records migrate into the managed multi-tenant service by reassigning `scope_id` — no data reshaping, no divergent code.

---

## Design Principle: Role-Based Access Control, Anchored in the Platform

The control plane enforces three roles of ascending privilege:

- **viewer** — read-only access to monitoring: dashboard, detections, prompt history, sources, evaluation.
- **operator** — everything a viewer can do, plus operational triage (acknowledging findings).
- **admin** — everything, plus the consequential controls: enforcement policy, custom signatures, premium/threat-feed subscription, and the managed-upgrade action.

Roles are read from a verified identity, never from the request body. Three authentication modes are supported via `VARDOGER_AUTH_MODE`:

- **`none`** — local development only. No auth; the caller is treated as an admin. This mode is the *only* configuration under which the open Lambda Function URL is provisioned; production stacks disable it.
- **`cognito`** — an Amazon Cognito user pool fronted by an API Gateway JWT authorizer verifies the token; the control plane reads the caller's role from the `cognito:groups` claim (groups `viewer` / `operator` / `admin` are provisioned by the stack).
- **`cognito+identity-center`** — the same, plus AWS IAM Identity Center federation so an organization can gate access with its existing AWS identities.

Enforcement is **backend-first**: `require_role` guards every protected endpoint server-side, and the UI merely mirrors those permissions. A hidden button is never the security boundary.

**Why:** The buyer is an organization building AI agents; it already has a security team that expects RBAC and will not accept a shared password or an open dashboard. Anchoring identity in Cognito (optionally federated through Identity Center) lets that team use the controls it already runs, and reading roles from a verified JWT — rather than a client-supplied field — means the same "identity from the platform, never the payload" principle that protects the data path also protects the control plane.

**Expected outcome:** A security team can grant read-only visibility broadly while restricting enforcement and subscription changes to a small set of admins, using its existing AWS identity infrastructure, with the guarantee that access control cannot be bypassed by calling the API directly.

---

## Design Principle: Guarded Kill Decisions

Terminating a session is treated as a high-consequence action gated behind multiple independent conditions. Tier 2 will only enforce a kill when *all* of the following hold:

- The scope is explicitly in `enforce` mode (not `shadow` or `off`).
- Global and tier-specific kill guards are enabled.
- An enforcement target is configured.
- Model confidence exceeds the tenant's threshold.
- The composite prompt score clears the kill bar.
- The category is specific (not "generic malicious").
- There is corroborating evidence — repeated malicious verdicts, extreme confidence, or accumulated session risk.
- The safe-intent gate does not classify the prompt as legitimate business intent.

**Why:** False positives in a security control erode trust until operators disable it — the worst possible outcome. Making a kill require agreement from several independent signals means one noisy component cannot cause a wrongful termination. The system is designed so that the *default* posture is to observe and score, and enforcement is something an operator deliberately opts into.

**Expected outcome:** Operators can run the system in shadow mode to build confidence, then enable enforcement knowing that kills reflect genuine, corroborated malice rather than a single model hiccup.

---

## Design Principle: Shadow Mode by Default

Tier 2 and Tier 3 default to `shadow` — they score, log, and record what they *would* have done, without taking enforcement action.

**Why:** No operator should deploy an automated session-killer into production traffic without first seeing how it behaves against their own data. Shadow mode produces a full record of would-have-killed decisions, feeding the outcome ledger so operators can measure precision and recall before flipping to enforce.

**Expected outcome:** Adoption is safe and gradual. Teams gain evidence-based confidence rather than being asked to trust the system blind.

---

## Design Principle: Safe-Intent Gates

Before any escalation, prompts are checked against a library of legitimate business intents — order status, returns, password resets for one's own account, product questions, honest mistakes. Matching prompts have their risk capped.

**Why:** The most damaging false positives are the ones that block a real customer doing something ordinary. A customer asking "I forgot my password, what's the normal reset process?" superficially resembles an account-takeover probe. The safe-intent gate encodes the difference between asking about a normal process and asking to bypass one.

**Expected outcome:** Legitimate customer service traffic flows unimpeded, and the false-positive rate stays low enough that operators trust the enforcement decisions.

---

## Design Principle: The Outcome Ledger

Every Tier 1/2/3 decision writes a row to an outcome ledger recording the predicted verdict, the action taken, and — when ground truth is known — whether it was a true/false positive/negative.

**Why:** A detection system you cannot measure is a detection system you cannot improve or trust. The ledger turns "I think it's working" into precision, recall, and false-positive rates broken down by tier, category, and model version. Rows are partitioned by `scope_id` and tagged with `source`, so a self-hosted operator sees only their own data (and can slice it by account/agent), while the managed service can aggregate across scopes for benchmarking.

**Expected outcome:** Detection quality is quantifiable and trendable, and regressions from new signatures or model versions are visible rather than silent.

---

## Design Principle: Platform Abstraction Through Adapters

The detection core knows nothing about AWS, AgentCore, or any specific gateway. Platform-specific concerns — event parsing, response formatting, session storage, enforcement, alerting — live behind adapter interfaces (`SessionStore`, `SignatureProvider`, `EnforcementAction`, `AlertSink`, `PromptTelemetry`).

**Why:** The detection logic is the durable, differentiated value. Gateways come and go. Keeping the core platform-agnostic means new integrations (other agent gateways, orchestration frameworks) are new adapters, not rewrites. It also keeps the core independently testable without any cloud dependency.

**Expected outcome:** The same detection engine can front multiple platforms, and contributors can add integrations without touching detection logic.

---

## Design Principle: Signatures as a Community Asset, Intelligence as a Product

The repository ships a solid base of community signatures — MITRE ATLAS patterns, named public jailbreaks, tokenizer injection, encoding attacks. The free tier can view every bundled signature and author its own custom signatures. Premium intelligence (curated social-engineering patterns, business-logic-abuse patterns, rapid-response updates, the tuned ML model) is delivered as a subscription.

**How premium is delivered — AWS Marketplace cross-account S3:** Rather than an in-app payment flow, premium is an **AWS Marketplace subscription**. When a customer subscribes, their AWS account is granted cross-account **read** access to an S3 bucket that holds the latest premium signatures. The scanner gains an optional S3 provider (`VARDOGER_PREMIUM_SIGNATURE_BUCKET`, with an optional `VARDOGER_PREMIUM_SIGNATURE_ROLE_ARN` to assume): when configured, it loads and validates premium signatures through the *same* pipeline as community ones (ReDoS screen, minimum-pattern floor, optional manifest-hash integrity check) and **appends** them. Premium is strictly additive and optional — if the bucket is unset or a load fails, the scanner degrades silently to the community-only set. The Signatures page surfaces premium status, a Marketplace link, and the customer's AWS account id; there is no in-app billing.

**Why premium cannot override community — the community floor:** Merging is **append-only**. A premium or custom signature may introduce a new id, but it may never replace a bundled community id; attempts are dropped and logged. This was a deliberate reversal of the original "premium wins" design.

The reason is that premium content arrives from a **remote bucket** and custom content from an operator's own table — neither is in the repository, and neither is reviewed by the people who review community signatures. If either could claim an existing id, a compromised feed, a bad publish or a careless custom rule could **silently disable a bundled detection** by shipping the same id with a weaker pattern. Nothing would fail; the scanner would simply stop catching something it used to catch.

Append-only means the bundled set is a floor that remote content can raise and never lower. It is the same instinct as the ReDoS screen and the minimum-pattern check: content from outside the repository is held at arm's length, and the safe failure is *more* detection, not less.

The cost is that a premium feed cannot fix a bad community signature in place — it has to ship a new id, and the community one has to be corrected by pull request. That is the right trade: correcting a bundled signature should be visible and reviewed, not delivered silently through a paid channel.

**Why this mechanism:** Marketplace handles billing, entitlement, and procurement through a channel enterprise buyers already trust, while a cross-account bucket policy is a simple, auditable grant that requires no secret-sharing and no bespoke license server. Reusing the community validation pipeline means premium content is held to the identical safety bar.

**Why the open/premium split at all:** Open-sourcing the framework and a strong baseline drives adoption, scrutiny, and community contribution — which improves everyone's security. Gating the continuously-maintained intelligence and the cross-scope analytics provides a sustainable reason for the project to keep being funded. The split is drawn at "things any competent team could reproduce" (open) versus "things that require ongoing curation and scale" (subscription).

**Expected outcome:** A healthy open-source project with real utility on its own, a contribution flywheel via signature submissions, and a commercial path — billed and entitled through AWS Marketplace — that funds continued development without hollowing out the free tier.

### Every Signature Is Screened for Safety

All signatures — bundled or contributed — pass a ReDoS (catastrophic backtracking) screen and a false-positive suite before they ship.

**Why:** A signature runs against every prompt for every user. A single pattern with catastrophic backtracking is a denial-of-service against the very agents the system protects. Because Python's regex engine offers no backtracking limit, unsafe patterns must be rejected *before* they are ever executed, using static analysis rather than timing.

**Expected outcome:** A malicious or careless signature contribution cannot degrade or take down detection for everyone.

---

## Design Principle: Two Deployment Models, One Codebase

**Model 1 — Self-Hosted:** An organization runs the entire stack in its own account, at scope `"local"`. Data never leaves its environment. All three tiers are available; the ML model is self-managed or omitted. Premium signatures are optional via an AWS Marketplace subscription (cross-account S3). A central security team can point multiple AWS accounts and agents at one self-hosted control plane — each is a distinct `source` within the single `"local"` scope.

**Model 2 — Managed Backend:** The organization runs only the lightweight agent-side components (dispatcher, enforcement) in its account and points telemetry at the managed service, which provides multi-scope segregation, hosted ML inference, premium intelligence, and cross-scope analytics.

**The migration path is deliberately frictionless.** Because self-hosted records are already partitioned by `scope_id = "local"`, moving to the managed service is a matter of reassigning that scope to the tenant id the managed service issues — the record shape does not change. The control plane exposes an informational **managed-upgrade** action (admin-only): it records the operator's intent and returns switch instructions, and telemetry is re-pointed by setting `VARDOGER_TELEMETRY_MODE=managed` and the managed intake endpoint. The upgrade is a handoff, not an automatic data migration.

**Why:** Different buyers have different constraints. Security-conscious and regulated organizations want full control and data residency. Smaller teams want the value without operating SageMaker endpoints and analytics pipelines. Serving both from one codebase avoids fragmentation and means both models benefit from the same core improvements.

**Expected outcome:** Broad addressable adoption without maintaining divergent products, and a genuinely low-friction upgrade path from self-hosted to managed that reuses the same data model.

---

## Design Principle: Cost Visibility Through Tagging, Not a Cost Page

Every taggable AWS resource the stack creates carries a consistent base tag set — `Application=AgentVardoger`, `ManagedBy=agent-vardoger`, `Scope=<scope_id>`, `DeploymentModel=self-hosted|managed-agent` — and the CloudFormation template accepts an optional customer-defined cost-allocation tag (`CostAllocationTagKey` / `CostAllocationTagValue`) that is applied to every resource alongside the base set.

**Why:** Operators repeatedly ask "what is this costing me?" The honest, durable answer is AWS's own billing tools. By tagging everything consistently, an operator can activate these tags as cost-allocation tags and see Agent Vardøger's spend broken out in Cost Explorer and on their bill — including by their own business dimension via the customer tag. This is more accurate and more trustworthy than an in-app cost estimate that would have to guess at per-request pricing, so the product deliberately ships tags instead of a cost page. (An earlier `Component` tag was dropped as noise; the four base tags plus the optional customer tag are enough to attribute and slice spend.)

**Expected outcome:** Customers can attribute and analyze the service's cost using native AWS billing, with no dependency on an in-app estimator, and can fold the spend into their own cost-allocation scheme through the customer-defined tag.

---

## Non-Goals and Known Limitations

Being explicit about what the system does *not* claim to do is part of the design.

- **It is not a model-level guardrail.** It inspects prompts entering the agent; it does not evaluate or constrain the model's outputs. Output filtering is a complementary control, not part of this system.
- **Detection is heuristic, not complete.** Signatures and scoring catch known and known-shaped attacks. A sufficiently novel attack may pass Tier 1 and be caught only by Tier 2/3, or not at all until a signature is added. This is why the tiers, the outcome ledger, and the contribution loop exist.
- **Tier 3 kill mode is conservative by design.** It will miss some coordinated attacks in exchange for not amplifying false positives tenant-wide. Operators who want more aggressive cross-session enforcement must opt in explicitly.
- **The self-hosted ML tier is a capable baseline, not a research-grade model.** Operators are encouraged to bring their own model; guidance is provided for doing so.

---

## Summary of Intended Outcomes

| Design decision | Intended outcome |
|-----------------|------------------|
| Three-tier detection | Fast blocking of obvious attacks; ML for evasive ones; cross-session view for coordinated ones |
| Refuse attack-shaped input; fail open on monitor failure | Adversarial input shapes are always refused; a broken monitor degrades visibly (alarmed) instead of blocking every user — invertible to fail-closed per deployment |
| Scan everything forwarded | No parser-differential bypass |
| Identity from platform only | No cross-scope or cross-source spoofing |
| Scope + source model | Clean single-org self-hosting with cross-account/agent visibility, and a no-reshape path to managed multi-tenancy |
| Role-based access control | Read-only visibility broadly, enforcement/subscription for admins, anchored in Cognito/Identity Center and enforced backend-first |
| Guarded kills | Enforcement reflects corroborated malice, not single-signal noise |
| Shadow by default | Safe, evidence-based path to enabling enforcement |
| Safe-intent gates | Low false-positive rate on legitimate traffic |
| Outcome ledger | Measurable, trendable detection quality, scoped to the operator's own data |
| Adapter abstraction | New platform integrations without core rewrites |
| Community + premium split | Sustainable open source with a contribution flywheel |
| Premium via AWS Marketplace (cross-account S3) | Enterprise-trusted billing/entitlement with no secret-sharing or in-app payment |
| Signature safety screening | One bad signature cannot break detection for everyone |
| Cost visibility via tagging | Native AWS billing attribution instead of an in-app estimator |
| Two deployment models | Serve control-focused and convenience-focused buyers from one codebase |
