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

Ordered cheapest-first. Step 0 costs nothing and tells you whether a model will
help at all.

#### Step 0 — confirm the pipeline before paying for a model

Tier 2 already runs without an endpoint: it consumes the prompt queue and writes
`PromptHistory`. If rows are not appearing, attaching a model fixes nothing —
the queue, the function or its permissions are the problem.

```bash
aws dynamodb scan --table-name VardogerPromptHistory --region us-east-1 \
  --max-items 5 --output table \
  --query "Items[].{scope:scope_id.S,ts:session_timestamp.S,status:tier2_status.S}"
```

Rows appearing at all is the signal. With no endpoint attached, Tier 2 records
each prompt and marks it `tier2_no_endpoint` in the outcome ledger rather than
classifying it — that is Tier 2 working correctly, and it is the state a default
deploy is in. **No rows means the queue, the function or its permissions are
broken, and a model will not fix it.**

#### Step 1 — deploy the model to a **serverless** endpoint

Use [SageMaker Serverless Inference](https://docs.aws.amazon.com/sagemaker/latest/dg/serverless-endpoints.html),
not a real-time endpoint. A real-time endpoint bills for every hour it exists;
this one is invoked only when prompts arrive, and **nothing in the template
schedules a keep-alive**, so a real-time endpoint would sit idle and bill around
the clock.

The SageMaker Python SDK resolves the container image for you, which is the part
that is easy to get wrong by hand:

```python
# pip install sagemaker
from sagemaker.huggingface import HuggingFaceModel
from sagemaker.serverless import ServerlessInferenceConfig

model = HuggingFaceModel(
    env={
        # Ungated and Apache-2.0, so no HF token and no licence acceptance.
        "HF_MODEL_ID": "protectai/deberta-v3-base-prompt-injection-v2",
        "HF_TASK": "text-classification",
    },
    role="arn:aws:iam::<account>:role/<SageMakerExecutionRole>",
    transformers_version="4.37.0",   # confirm against the current DLC list
    pytorch_version="2.1.0",
    py_version="py310",
)

model.deploy(
    endpoint_name="vardoger-tier2",
    serverless_inference_config=ServerlessInferenceConfig(
        memory_size_in_mb=4096, max_concurrency=5,
    ),
)
```

**Which model.** [Llama Prompt Guard 2](#recommended-llama-prompt-guard-2) above
is the better choice for production. For a first integration test, the ProtectAI
DeBERTa classifier is easier: it is ungated, needs no Hugging Face token, and is
Apache-2.0, so there is no licence to read before you can see a label come back.
It returns `INJECTION` / `SAFE`, and `INJECTION` is already in `ATTACK_LABELS`.

**Version pins drift.** The `transformers_version` / `pytorch_version` pair must
match a published Deep Learning Container. If `deploy()` fails resolving an
image, check the
[available DLCs](https://github.com/aws/deep-learning-containers/blob/master/available_images.md)
and adjust.

#### Step 2 — point Vardøger at the endpoint

```bash
aws cloudformation update-stack --stack-name agent-vardoger --region us-east-1 \
  --use-previous-template --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=Tier2MlEndpoint,ParameterValue=vardoger-tier2 \
    $(aws cloudformation describe-stacks --stack-name agent-vardoger --region us-east-1 \
      --query "Stacks[0].Parameters[?ParameterKey!='Tier2MlEndpoint'].ParameterKey" \
      --output text | tr '\t' '\n' | sed 's/.*/ParameterKey=&,UsePreviousValue=true/')
```

A parameter update takes 2–3 minutes and skips repackaging the Lambdas and
rebuilding the frontend. `./scripts/deploy.sh` with `VARDOGER_ML_ENDPOINT` set
works too and is the right choice if you are also changing code.

> **The endpoint name is a deploy parameter, so it can be silently unset.**
> Running `deploy.sh` later *without* `VARDOGER_ML_ENDPOINT` exported re-applies
> the empty default, which disables Tier 2 classification and removes the
> SageMaker permission. Nothing fails; prompts simply go back to
> `tier2_no_endpoint`. Export it in any shell you deploy from.

Setting the endpoint is what grants `sagemaker:InvokeEndpoint`, scoped to exactly
that endpoint ARN. With no endpoint configured the permission is not granted at
all.

#### Step 3 — verify a real classification

Send a benign prompt and an attack through your gateway, then read the Tier 2
log:

```bash
aws logs tail /aws/lambda/vardoger-tier2-ml --since 5m --region us-east-1
```

You are looking for a label and a confidence. Then confirm it reached storage:

```bash
aws dynamodb scan --table-name VardogerPromptHistory --region us-east-1 \
  --max-items 5 --output table \
  --query "Items[].{label:tier2_label.S,conf:tier2_confidence.N,status:tier2_status.S,cat:tier2_category.S}"
```

`tier2_label` and `tier2_confidence` are the model's own output. `tier2_status`
and `tier2_category` are what the scoring pipeline made of it.

**A slow first classification is expected, not a fault.** Serverless endpoints
scale to zero and nothing keeps this one warm, so the first invocation after an
idle period pays a cold start. Tier 2 is asynchronous and its lever is ending the
session rather than refusing a prompt, so this delays a kill — it never delays a
user's answer.

**Keep kills off until the labels look right.** `VARDOGER_TIER2_KILL_ENABLED`
defaults to `false`, so Tier 2 scores and records without terminating anything.
Confirm the model is classifying your traffic sensibly before giving it the kill.

> **Not `VARDOGER_ML_KILL_ENABLED`.** That name is the *Lambda's* environment
> variable, which the template sets from `VARDOGER_TIER2_KILL_ENABLED`.
> Exporting it before a deploy has no effect and is silently overwritten.
> `VARDOGER_ML_CONFIDENCE_THRESHOLD` (default `0.85`) is likewise not a deploy
> parameter — it is a code default, changeable only on the deployed function's
> configuration.

#### If the label never matches

The handler uppercases the label and checks it against `ATTACK_LABELS`
(`INJECTION`, `JAILBREAK`, `PROMPT_INJECTION`, `MALICIOUS`, `ATTACK`, `LABEL_1`,
`1`, and the abuse families). A model whose positive class is none of those
scores as benign, silently.

A response shape the handler cannot parse does **not** raise. It degrades to
`SAFE` with score `0` and reports a degraded component, because an external
endpoint returning something unexpected must not turn into retry-to-DLQ churn.
So "everything is SAFE" has two causes worth separating: the model says so, or
the handler could not read the answer. Check for the degraded report before
concluding the model is quiet.

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
