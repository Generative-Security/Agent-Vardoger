# Managed Backend Setup (Model 2)

Deploy the agent-side components in your account while pointing analytics and ML inference to the managed Agent Vardøger service.

## What You Deploy

- Dispatcher Lambda (inline on your AgentCore Gateway)
- Session Registry (DynamoDB in your account)
- Enforcement Lambda (session termination in your account)
- Alert Queue + SNS (your account)

## What the Managed Service Provides

- Multi-scope prompt history and analytics
- Premium signature intelligence
- Hosted Tier 2 ML inference (no SageMaker to manage)
- Cross-scope Tier 3 benchmarking
- Evaluation dashboard (TP/TN/FP/FN across your environment)

## How the Upgrade Works

Moving from self-hosted to managed is a **handoff, not an automatic data migration**. Because self-hosted records are already partitioned by `scope_id = "local"`, the managed service issues you a scope id and you re-point telemetry to it. The control plane exposes an informational **managed-upgrade** action (admin-only, `POST /api/settings/managed-upgrade`) that records your intent and returns switch instructions; it does not move data for you.

## Setup

1. Complete the managed intake to receive your scope id and intake endpoint. (The intake URL is environment-driven — no endpoint is hardcoded in this repository.)
2. Deploy the agent-side stack with telemetry pointed at the managed intake:

```bash
# Values below come from your managed onboarding; none are hardcoded in the repo.
export VARDOGER_MANAGED_INTAKE_URL="<your-managed-intake-endpoint>"

aws cloudformation deploy \
    --template-file infra/managed-agent.yaml \
    --stack-name agent-vardoger \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
        GatewayArn=$YOUR_GATEWAY_ARN \
        AgentRuntimeArn=$YOUR_RUNTIME_ARN \
        ManagedIntakeUrl=$VARDOGER_MANAGED_INTAKE_URL
```

3. Set `VARDOGER_TELEMETRY_MODE=managed` so the dispatcher forwards telemetry to the managed intake.
4. Access the managed dashboard using the URL provided during onboarding.

## Data Privacy

- Prompt text is sent to the managed backend for ML classification and Tier 3 analysis
- You control retention via your subscription settings
- Prompts are encrypted in transit (TLS). At rest on the agent side, blocked-prompt
  evidence and the SessionRegistry are encrypted with a customer-managed KMS key
  (CMK); the managed backend applies its own at-rest encryption per your
  subscription terms. Prompt telemetry in transit to the backend travels over
  SQS/TLS.
- You can switch back to self-hosted at any time without losing local detection capability
