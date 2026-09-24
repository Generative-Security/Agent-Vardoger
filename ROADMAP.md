# Agent Vardøger Roadmap

Agent Vardøger started from a simple observation: the most damaging attacks on conversational and agentic AI rarely fit inside a single prompt. They unfold across a conversation, across many conversations, and increasingly across chains of agents talking to each other.

The project's direction follows that observation in three steps:

1. **From prompts to sessions.** Judge the conversation, not the message. *(Shipping today: Tiers 1–3 and session termination.)*
2. **From sessions to patterns.** Recognize the shape of an attack spread across many sessions, even when no single session looks malicious and no two sessions can be tied to the same attacker.
3. **From inputs to outcomes.** Evaluate what the agent hands back and what it does, not only what it is asked, and contain the effects of a compromised session wherever they travel.

This document describes where Agent Vardøger is going. It is a statement of intended direction rather than a release schedule; the items below are grouped by theme, not by date. At any given point in time this list may change, and items may be worked on out of order. This document can also serve as a guide for those who want to contribute to the project.

For how the system works today, see [docs/capabilities.md](docs/capabilities.md). For why it is built the way it is, see [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md).

---

## What stays constant

Every roadmap item is built on the same principles as the current release. New capabilities extend these; they do not trade them away.

- **Sidecar first.** A security control must never become the outage. New detection runs beside the agent and fails open visibly, unless an operator explicitly chooses otherwise.
- **One lever: end the session.** Every tier, current and future, converges on terminating the session (and, as the roadmap progresses, the sessions downstream of it).
- **Identity from the platform, never the payload.** New correlation features key on what the platform asserts, not on what a caller claims.
- **Shadow before enforce.** Every new detection type ships able to record what it *would* have done, so operators can measure it against their own traffic first.
- **Signatures as a Community Asset, Intelligence as an add-on** The engines that run detection are open source in every tier. The continuously curated content that drives the most advanced detections is available by subscription, and operators can always author their own.

---

## 1. Cross-session pattern detection

Tier 3 today correlates coordinated campaigns: the same prompt repeated across sessions, near-duplicate rewordings, bursts of the same attack category, and sessions whose risk rises together. The next generation of Tier 3 recognizes attacks by the **shape of the activity**, not by the identity of the attacker.

### Actor-agnostic by design

Tying sessions to a single actor (by IP address, device, or claimed user) is attractive but easy to spoof, and attackers rotating infrastructure defeat it trivially. Agent Vardøger's cross-session detection is built on a different premise: **if the combined behavior of a set of sessions forms an attack, it is an attack, whether it comes from one actor or twenty.** Detection looks for complementary, coordinated patterns rather than a shared fingerprint.

### Distributed enumeration

The first pattern family in this direction is distributed enumeration: systematic extraction split across many sessions so that no single conversation looks unusual.

Consider a retail assistant that answers stock questions. One session binary-searches the availability of five products at one store. A second session does the same for five *different* products. Two more sessions repeat the exercise for the same (or other) products at a different store. Each session is polite, short, and indistinguishable from a real shopper. Together, they are mapping inventory, the kind of data that lets a competitor or trader estimate daily sales long before results are public.

Cross-session enumeration detection will recognize this by what the sessions have in common:

- **Query structure**, such as the same narrowing or binary-search shape applied to different targets.
- **Coverage**, such as how much of a catalog, location set, roster, or schedule a group of sessions has collectively touched within a window.
- **Complementarity**, where sessions divide a search space between them rather than repeating each other.

The same approach generalizes beyond inventory: staff schedules and coverage, pricing and discount thresholds, account-recovery flows probed field by field, and any business data that is harmless one answer at a time and sensitive in aggregate.

### Longer horizons

Low-and-slow extraction does not respect a five-minute window. Tier 3 will maintain rolling aggregates over longer horizons (hours and days) so that paced campaigns accumulate evidence the same way paced multi-turn attacks already accumulate session risk in Tier 2.

### Cross-session social engineering

Social engineering against AI often runs as a campaign: the same pretext tried with different authority claims, urgency framings rotated until one lands, or a recovery flow probed from many sessions to learn exactly what the agent will accept. Cross-session detection will recognize pretext rotation and coordinated manipulation, drawing on the Generative Security Social Engineering Abuse Case Library.

---

## 2. Cross-session rule packs: open engine, curated intelligence

The Tier 3 engine that runs these detections ships in the open-source release. What drives its most advanced detections is **content**: declarative cross-session rules describing what a pattern looks like, which categories it applies to, how much coverage or coordination is significant, and whether a finding is alert-only or kill-eligible.

- **Author your own.** Operators will be able to write cross-session rules for their own business, just as they author custom Tier 1 signatures today. A retailer knows which data is sensitive in aggregate better than anyone.
- **Curated rule packs by subscription.** Industry-specific rule packs for retail, financial services, healthcare, telecommunications and other sectors, covering distributed enumeration, business-logic abuse, and cross-session social engineering, will be delivered through the same AWS Marketplace subscription as premium signatures.
- **Same safety bar.** Rule packs load through the same validation pipeline as signatures, with integrity checks and the same **append-only** guarantee: remote content can add detection, never weaken what ships in the repository.
- **Richer categories flowing between tiers.** The attack categories carried by signatures matched in Tier 1 (community, custom, and premium) will flow through prompt history into Tier 3, so every signature you add sharpens cross-session correlation automatically.

In the managed service, rule packs run across scopes, so a pattern first seen against one organization can protect every subscriber.

---

## 3. Response monitoring and outcome-based security

Multi-turn and multi-session analysis move the system toward outcomes, because you cannot judge the trajectory of a conversation from one line of it. The next major step is to evaluate **what the agent gives back**.

- **Response monitoring.** Evaluate agent responses and tool results against the intent derived from the whole conversation, so "what did the agent just disclose?" becomes a signal alongside "what did the user ask?"
- **Cumulative disclosure tracking.** Measure how much sensitive or aggregate-sensitive information a session, or a group of sessions, has actually received, complementing the coverage analysis in cross-session detection.
- **Outcome-aware enforcement.** Feed response findings into the same session-risk model and the same guarded kill decisions, so a session that is extracting successfully accumulates risk faster than one that is being refused.
- **Safety breakers for high-stakes actions.** For tool calls that move money, change accounts, or release data, evaluate the likely consequence of the action before it executes, in deployments that opt into gating.

Response monitoring follows the same sidecar principle as inbound detection: it observes and terminates rather than rewriting the agent's output, and a failure in the monitor never blocks the agent.

---

## 4. Agent-to-agent containment

As agentic architectures grow, a single user request can fan out across many agents and tools, each with its own session. A session identified as malicious at one step may already have handed tainted context to the agents downstream of it.

Agent Vardøger will track the **session graph**: which agents communicate with which, over which sessions, through the gateway, MCP, and agent-to-agent protocols. That graph enables:

- **Downstream termination.** When a session is terminated, the sessions it initiated or fed can be terminated with it, cutting off the chain rather than a single link.
- **Risk propagation.** Risk accumulated in an upstream session can carry forward to the sessions it touches, so a downstream agent is evaluated with knowledge of where its input came from.
- **Blast-radius visibility.** Operators can see, for any detection, every agent and session that was reachable from it, which is the first question in any incident response.

This is the sidecar model carried to its conclusion: in container environments, security moved beside each workload and gained visibility across the whole mesh. Agent Vardøger aims to do the same for meshes of agents.

---

## 5. Stronger session identity

Session correlation is only as strong as the session identifier it relies on. Upcoming work makes authenticity a first-class input to enforcement:

- **Authenticity-aware risk.** Sessions whose identifier is asserted by the platform will be distinguished in scoring from those that are not, with operator-selectable posture (additional risk, or gate mode for unverified sessions).
- **Deployment guidance and checks** that help operators configure gateways so session identity is always platform-asserted.
- **Harness-managed runtimes.** As Amazon Bedrock AgentCore exposes session termination for harness-managed runtimes, Vardøger will adopt it so every runtime type receives the full session kill.

---

## 6. Detection quality and scale

- **Premium Tier 2 intelligence.** A tuned classifier and curated behavioral signals for Tier 2, available through the managed service and subscription, alongside the bring-your-own-model path.
- **Large-context inspection.** Windowed Tier 2 scoring for long documents and tool payloads, and latency-aware inline scanning for large requests, so document-heavy agents receive the same coverage as conversational ones.
- **Faster time-to-kill.** Shortening the path from detection to runtime termination in sidecar mode, from roughly a second toward a few hundred milliseconds, so the session is more often ended before the agent's response is delivered, without placing enforcement in the request path.
- **Semantic clustering.** Broader use of embedding-based similarity in Tier 3, so reworded variants of the same attack cluster together even when their surface text differs.
- **Evaluation and benchmarking.** Continued investment in the outcome ledger, including cross-scope benchmarking in the managed service, so detection quality is measurable per tier, category, rule pack, and model version.

---

## 7. More platforms

The detection core is platform-agnostic by design, and new platforms are new adapters rather than rewrites. Planned adapters include:

- **Google Agent Gateway**
- **LangGraph** and other orchestration frameworks
- Additional agent gateways as the ecosystem consolidates

---

## 8. The managed service

The managed backend brings the full roadmap to teams that would rather not operate it themselves:

- Hosted Tier 2 inference and premium intelligence
- Cross-scope Tier 3 correlation and rule packs, so patterns seen anywhere protect everyone
- Multi-tenant isolation built on the same scope and source model as the self-hosted release, so moving between the two never requires reshaping data

---

## Shaping the roadmap

The roadmap is influenced most by what operators see in the wild.

- **Contribute signatures and, as the format is published, cross-session rules.** See [CONTRIBUTING.md](CONTRIBUTING.md).
- **Open an issue** describing an attack pattern you have observed, a platform you need supported, or a detection you would prioritize.
- **Talk to us** at questions@generativesecurity.ai about industry-specific patterns you would like to see in curated rule packs.
