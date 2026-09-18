# Tier 2 ML Setup Guide

**ML classification** is optional. Agent Vardøger provides full Tier 1 protection (regex, hash, policy, risk scoring) without any ML model. Tier 2 adds asynchronous ML classification for prompts that pass Tier 1.

The Tier 2 **function** is deployed either way. It is the component that consumes the prompt queue and writes `PromptHistory`, which the dashboard's Prompt History page and Tier 3 cross-session analysis both read — so it runs in every deployment, and attaching a model endpoint is what adds classification.

## Option 1: Skip the ML model (default)

Leave `VARDOGER_ML_ENDPOINT` unset. You get Tier 1 detection, prompt history, and Tier 3 cross-session analysis; each prompt is recorded with a `tier2_no_endpoint` skip in the outcome ledger instead of an ML verdict, and no SageMaker permissions are granted to the function.

## Option 2: Self-Host a Model

### Model Requirements

Any text classifier that:
- Accepts `{"inputs": "text string"}` as request body
- Returns `[{"label": "LABEL_NAME", "score": 0.95}]` or `[[{"label": "...", "score": ...}]]`
- Labels include at least one attack label (INJECTION, MALICIOUS, JAILBREAK, ATTACK, LABEL_1, etc.)
- Responds within ~1 second for reasonable prompt lengths

### Recommended: Llama Prompt Guard 2

**Start with a model that was already trained for this task.** Fine-tuning a
general-purpose encoder such as `distilbert-base-uncased` means first sourcing
and labelling a prompt-injection corpus — by far the hardest part of the job,
and the part a generic base model does nothing to help with.

**Llama Prompt Guard 2** is purpose-built by Meta to classify prompt injection
and jailbreak attempts, and needs no training to be useful:

| Variant | Size | Pick it when |
|---|---|---|
| `meta-llama/Llama-Prompt-Guard-2-86M` | 86M | Default. Best accuracy of the two. |
| `meta-llama/Llama-Prompt-Guard-2-22M` | 22M | High prompt volume, or cost per invocation matters more than recall. |

It is a binary classifier (benign vs. malicious). Its positive-class label —
whether the endpoint emits `MALICIOUS`, `LABEL_1`, or `1` — is **already in the
handler's `ATTACK_LABELS` set**, so it is a drop-in with no mapping layer.
Confirm the label your deployed endpoint actually returns; the handler
uppercases before matching.

Licensing: Prompt Guard 2 is released under the **Llama Community License**.
Read its acceptable-use terms before deploying commercially — they are more
restrictive than Apache 2.0, and the redistribution and naming clauses matter if
you ship it as part of a product rather than running it yourself.

Because Tier 2 runs **asynchronously** — it is not in the request path, and its
lever is terminating the session rather than refusing a prompt — a slower, more
accurate model is usually the better trade. Latency here delays a kill by
milliseconds; it does not delay the user's answer.

#### Sequence length matters

Prompt Guard 2, like the BERT-family encoders it is built on, has a bounded
context window (512 tokens is typical — check the model card for the variant you
deploy). A longer prompt is silently truncated, so an attack placed in the tail
of a large document will not be seen. If your agent handles long documents,
chunk the prompt and score each window, taking the maximum.

Tier 1 has the opposite exposure: it scans everything, and pays for it in
latency (see [capabilities.md](capabilities.md) for measured numbers).

### Fine-tuning your own

Worth doing only once you have labelled, in-domain traffic — which, conveniently,
this system collects for you. `PromptHistory` plus the outcome ledger give you
prompts with Tier 1 verdicts and operator triage decisions attached. Fine-tune
from a purpose-built checkpoint rather than a bare base model, and keep the
original running in shadow mode until the replacement beats it on your own
traffic.

### Deployment

```bash
# Deploy to SageMaker
aws sagemaker create-model ...
aws sagemaker create-endpoint-config ...
aws sagemaker create-endpoint --endpoint-name your-model-name ...

# Configure Agent Vardøger, then redeploy
export VARDOGER_ML_ENDPOINT="your-model-name"
export VARDOGER_TIER2_KILL_ENABLED="false"   # shadow mode; this is the default
./scripts/deploy.sh
```

Those are the two that `deploy.sh` reads. Tier 2 starts in shadow mode on its
own — `VARDOGER_TIER2_KILL_ENABLED` defaults to `false`, so Tier 2 scores and
records without terminating anything until you set it to `true`.

> **Not `VARDOGER_ML_KILL_ENABLED`.** That name is the *Lambda's* environment
> variable, which the template sets from `VARDOGER_TIER2_KILL_ENABLED`.
> Exporting it before a deploy has no effect and is silently overwritten.
> `VARDOGER_ML_CONFIDENCE_THRESHOLD` (default `0.85`) is likewise not a deploy
> parameter — it is a code default, changeable only on the deployed function's
> configuration.

### Testing Your Model

The scoring pipeline applies several layers on top of the raw model output:
- Safe-intent gates reduce scores for obvious business questions
- Behaviour patterns increase scores for credential requests, bypasses, etc.
- Repetition scoring tracks same-category probing across turns
- Context escalation detects multi-turn movement toward abuse

Even a noisy model will produce useful results because the scoring pipeline caps and adjusts model-only labels.

## Option 3: Managed ML (Model 2)

Connect to the Agent Vardøger managed backend. ML inference is handled for you.

The self-hosted template pins telemetry to `local`, so this is not a variable you export — managed onboarding supplies a template configured for `managed` telemetry and the intake endpoint that goes with it. See [managed-setup.md](managed-setup.md).
