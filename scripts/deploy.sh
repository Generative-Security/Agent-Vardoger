#!/usr/bin/env bash
set -euo pipefail

# Agent Vardøger — Self-Hosted Deployment Script
# Usage: ./scripts/deploy.sh [region] [stack-name]

REGION="${1:-${AWS_REGION:-us-east-1}}"
STACK_NAME="${2:-agent-vardoger}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Build a self-contained test gateway instead of attaching to an existing one.
NEW_HARNESS="${VARDOGER_NEW_HARNESS:-false}"
DEMO_RUNTIME="${VARDOGER_DEMO_RUNTIME:-false}"          # self-managed demo agent
# The runtime ARN actually passed to CloudFormation. Starts as whatever the
# operator supplied; with the test harness the stack creates its own runtime
# and this is overwritten from the outputs before the second pass.
AGENT_RUNTIME_ARN_EFFECTIVE="${VARDOGER_AGENT_RUNTIME_ARN:-}"

if [ "$NEW_HARNESS" != "true" ] && [ -z "${VARDOGER_GATEWAY_ARN:-}" ]; then
    echo "ERROR: VARDOGER_GATEWAY_ARN is required"
    echo "Usage: export VARDOGER_GATEWAY_ARN='arn:aws:bedrock-agentcore:...' && $0"
    echo ""
    echo "  No gateway yet? Build one with the stack instead:"
    echo "    export VARDOGER_NEW_HARNESS=true"
    echo "  See docs/test-harness.md."
    exit 1
fi

# Authoritative for StopRuntimeSession, so it is required whenever a real
# agent is being protected. The test harness has no runtime of its own: its
# gateway fronts an echo Lambda, and there is no session to terminate.
if [ "$NEW_HARNESS" != "true" ] && [ -z "${VARDOGER_AGENT_RUNTIME_ARN:-}" ]; then
    echo "ERROR: VARDOGER_AGENT_RUNTIME_ARN is required"
    echo "  (not required when VARDOGER_NEW_HARNESS=true)"
    exit 1
fi

# Resolve a Python interpreter once. Windows installs commonly provide only
# `python`, while POSIX systems usually provide `python3`.
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "ERROR: python3 (or python) is required to package the Lambda code."
    exit 1
fi

# Fail early with a clear message rather than midway through the deploy.
# On Windows this script runs under Git Bash, whose PATH is NOT PowerShell's —
# a tool installed for PowerShell may be invisible here. Name only the tool that
# is actually missing so the operator knows what to install.
for _tool in aws pip3; do
    if ! command -v "$_tool" >/dev/null 2>&1; then
        echo "ERROR: '$_tool' not found on PATH."
        case "$_tool" in
            aws)  echo "  Install the AWS CLI: https://aws.amazon.com/cli/" ;;
            pip3) echo "  pip3 ships with Python 3.12+; try 'python -m ensurepip --upgrade'." ;;
        esac
        echo "  (On Windows, confirm it resolves inside Git Bash, not just PowerShell.)"
        exit 1
    fi
done

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="agent-vardoger-${ACCOUNT_ID}-${REGION}"
ALERT_EMAIL="${VARDOGER_ALERT_EMAIL:-}"
TIER2_ENDPOINT="${VARDOGER_ML_ENDPOINT:-}"
# Auth mode. Default "token" = single-operator self-host with a shared bearer
# secret over the Function URL. "none" is DEV ONLY (open). "cognito" adds team
# RBAC behind an API Gateway JWT authorizer.
AUTH_MODE="${VARDOGER_AUTH_MODE:-token}"

# Behavioral / enforcement toggles. Each maps a VARDOGER_* env var to the
# CloudFormation parameter of the same concept, defaulting to the template's own
# default so an unset var leaves the documented default in place. These are
# passed on BOTH deploy passes below; omitting them from the second pass would
# silently reset them to defaults. See docs/capabilities.md for what each does.
TIER1_MODE="${VARDOGER_TIER1_MODE:-sidecar}"              # sidecar | gate
LOG_LEVEL="${VARDOGER_LOG_LEVEL:-INFO}"                    # DEBUG | INFO | WARNING | ERROR
DETECTION_FAILURE_POLICY="${VARDOGER_DETECTION_FAILURE_POLICY:-fail_open}"  # fail_open | fail_closed
TIER2_KILL_ENABLED="${VARDOGER_TIER2_KILL_ENABLED:-false}"
TIER3_ENABLED="${VARDOGER_TIER3_ENABLED:-false}"
TIER3_KILL_ENABLED="${VARDOGER_TIER3_KILL_ENABLED:-false}"
GLOBAL_KILL_ENABLED="${VARDOGER_GLOBAL_KILL_ENABLED:-false}"

# Premium signature feed (AWS Marketplace subscription). Documented in
# docs/quickstart.md and docs/signatures.md as values you "set", so they must
# actually be forwarded. Exporting them previously did nothing: the Lambda reads
# VARDOGER_PREMIUM_SIGNATURE_*, but the template only sets those from these
# CloudFormation parameters, which nothing passed -- so a subscriber following
# the docs silently kept the community-only signature set.
PREMIUM_SIGNATURE_BUCKET="${VARDOGER_PREMIUM_SIGNATURE_BUCKET:-}"
PREMIUM_SIGNATURE_PREFIX="${VARDOGER_PREMIUM_SIGNATURE_PREFIX:-premium/}"
PREMIUM_SIGNATURE_ROLE_ARN="${VARDOGER_PREMIUM_SIGNATURE_ROLE_ARN:-}"

# Does the stack already exist? (Determines create vs update behavior below.)
if aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" >/dev/null 2>&1; then
    STACK_EXISTS=1
else
    STACK_EXISTS=0
fi

# Token-mode secret handling.
#  - Operator supplied VARDOGER_AUTH_SECRET  -> use it (set or rotate).
#  - First create, none supplied             -> generate one and print it.
#  - Update, none supplied                    -> DO NOT rotate: keep the value
#    already in the stack (CloudFormation UsePreviousValue). Rotating on every
#    redeploy would silently lock the operator out.
AUTH_SECRET="${VARDOGER_AUTH_SECRET:-}"
AUTH_SECRET_GENERATED=0
AUTH_SECRET_USE_PREVIOUS=0
if [ "$AUTH_MODE" = "token" ] && [ -z "$AUTH_SECRET" ]; then
    if [ "$STACK_EXISTS" = "1" ]; then
        AUTH_SECRET_USE_PREVIOUS=1
    else
        # Reuse the interpreter resolved above; `openssl` is not reliably
        # present on Windows either, so do not depend on it.
        AUTH_SECRET="$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(32))')"
        AUTH_SECRET_GENERATED=1
    fi
fi

# `aws cloudformation deploy` retains the current value of any parameter that
# is NOT listed in --parameter-overrides (as long as it has no default that
# would override, which AuthSecret's "" default does NOT, since deploy keeps the
# existing value). So when keeping the previous secret we simply omit the
# override; otherwise we pass the value.
AUTH_SECRET_OVERRIDE=("AuthSecret=$AUTH_SECRET")
if [ "$AUTH_SECRET_USE_PREVIOUS" = "1" ]; then
    AUTH_SECRET_OVERRIDE=()
fi

# The dashboard is served via CloudFront (HTTPS), whose domain is only known
# after the stack exists. We deploy once with localhost dev origins, then read
# the CloudFront domain and re-apply CORS to include it (a cheap second pass;
# CloudFormation no-ops if nothing else changed).
CORS_ORIGINS="http://localhost:5173,http://localhost:3000"

echo "=== Agent Vardøger Deployment ==="
echo "Account:      $ACCOUNT_ID"
echo "Region:       $REGION"
echo "Stack:        $STACK_NAME"
echo "Auth mode:    $AUTH_MODE"
echo "Tier 1 mode:  $TIER1_MODE"
echo "Log level:   $LOG_LEVEL"
echo "Demo runtime: $DEMO_RUNTIME"
echo "Detect fail:  $DETECTION_FAILURE_POLICY"
echo "Tier 2 ML:    ${TIER2_ENDPOINT:-disabled}"
echo "Tier 3:       $TIER3_ENABLED"
echo "Test harness: $NEW_HARNESS"
echo "Premium sigs: ${PREMIUM_SIGNATURE_BUCKET:-disabled}"
echo "Kills:        global=$GLOBAL_KILL_ENABLED tier2=$TIER2_KILL_ENABLED tier3=$TIER3_KILL_ENABLED"
echo ""
# Tier 2/3 enforcement requires THREE switches aligned — the per-scope mode set
# to "enforce" (a control-plane setting, not a deploy parameter), GlobalKill,
# and the per-tier kill flag — plus per-finding guards. Setting a kill flag here
# alone does not enable kills; it is necessary, not sufficient.
if [ "$GLOBAL_KILL_ENABLED" = "true" ] || [ "$TIER2_KILL_ENABLED" = "true" ] || [ "$TIER3_KILL_ENABLED" = "true" ]; then
    echo "NOTE: Tier 2/3 kills also require the scope policy in 'enforce' mode"
    echo "      (set in the dashboard, default 'shadow') and pass per-finding"
    echo "      confidence/evidence guards. These flags are necessary, not"
    echo "      sufficient. See docs/capabilities.md."
    echo ""
fi
if [ "$AUTH_MODE" = "cognito" ] || [ "$AUTH_MODE" = "cognito+identity-center" ]; then
    echo "NOTE: Auth is enabled ($AUTH_MODE). After deploy, create a Cognito user"
    echo "      and add them to a viewer/operator/admin group before signing in."
    echo "      See docs/quickstart.md (\"Authentication\")."
    echo ""
elif [ "$AUTH_MODE" = "none" ]; then
    echo "WARNING: AuthMode=none exposes an UNAUTHENTICATED admin API over the"
    echo "         Function URL. Use only for local/dev, never on the internet."
    echo ""
fi

# 1. Create S3 bucket if needed
echo "[1/6] Checking S3 bucket..."
if aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
    echo "  Bucket exists."
else
    echo "  Creating bucket..."
    if [ "$REGION" = "us-east-1" ]; then
        aws s3api create-bucket --bucket "$BUCKET_NAME"
    else
        aws s3api create-bucket --bucket "$BUCKET_NAME" \
            --create-bucket-configuration "LocationConstraint=$REGION"
    fi
    aws s3api put-bucket-versioning --bucket "$BUCKET_NAME" \
        --versioning-configuration Status=Enabled
fi

# 2. Package Lambda code
echo "[2/6] Packaging Lambda code..."
BUILD_DIR=$(mktemp -d)
# Install for the Lambda runtime platform, not the host. Building on
# macOS/Windows/ARM otherwise ships incompatible native wheels (cryptography,
# pydantic-core) that ImportError at cold start. --only-binary=:all: forces
# prebuilt wheels; the command fails hard (no "|| true") so a bad build is
# caught here instead of in production.
pip3 install \
    --target "$BUILD_DIR/python" \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python-version 3.14 \
    --only-binary=:all: \
    --upgrade \
    -r "$PROJECT_ROOT/scripts/requirements-lambda.txt"
# Copy project source
cp -r "$PROJECT_ROOT/vardoger" "$BUILD_DIR/python/"
cp -r "$PROJECT_ROOT/adapters" "$BUILD_DIR/python/"
cp -r "$PROJECT_ROOT/control_plane" "$BUILD_DIR/python/"
cp -r "$PROJECT_ROOT/signatures" "$BUILD_DIR/python/"
# Zip with Python's stdlib rather than the `zip` binary. Python 3.12+ is
# already a prerequisite, while `zip` is NOT present in Git Bash on Windows —
# shelling out to it made the packaging step fail for every Windows user.
"$PYTHON_BIN" - "$BUILD_DIR/python" "$BUILD_DIR/lambda.zip" <<'PYZIP'
import os, sys, zipfile

src, out = sys.argv[1], sys.argv[2]
skip_dirs = {"__pycache__"}
skip_suffix = (".pyc", ".pyo")

with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
        for name in files:
            if name.endswith(skip_suffix):
                continue
            path = os.path.join(root, name)
            zf.write(path, os.path.relpath(path, src))
print(f"  Package ready: {os.path.getsize(out) / 1_048_576:.1f} MB")
PYZIP

# 3. Upload to S3
echo "[3/6] Uploading Lambda code to S3..."
# Use a CONTENT-HASHED S3 key, not a fixed name. CloudFormation only updates the
# Lambda's code when a property it tracks (CodeS3Key) changes. With a fixed key
# like "vardoger-lambda.zip" the key never changes, so `cloudformation deploy`
# sees no diff and SKIPS the code update — the new zip lands in S3 but the
# running function keeps the old code. Hashing the zip into the key makes every
# code change produce a new key, forcing CFN to redeploy the function.
CODE_HASH=$("$PYTHON_BIN" - "$BUILD_DIR/lambda.zip" <<'PYHASH'
import hashlib, sys
with open(sys.argv[1], "rb") as f:
    print(hashlib.sha256(f.read()).hexdigest()[:16])
PYHASH
)
CODE_S3_KEY="vardoger-lambda-${CODE_HASH}.zip"
aws s3 cp "$BUILD_DIR/lambda.zip" "s3://$BUCKET_NAME/$CODE_S3_KEY" --quiet
rm -rf "$BUILD_DIR"
echo "  Uploaded $CODE_S3_KEY"

# The demo agent is a SELF-MANAGED AgentCore Runtime, which is the only shape on
# which the session kill can be demonstrated: AgentCore refuses
# StopRuntimeSession on a harness-managed runtime. One dependency-free file, so
# the package is just that file zipped -- no pip install and no arm64 wheels.
DEMO_AGENT_S3_KEY="vardoger-demo-agent.zip"
if [ "$DEMO_RUNTIME" = "true" ]; then
    "$PYTHON_BIN" - "$PROJECT_ROOT/infra/demo_agent/main.py" "$BUILD_DIR/demo-agent.zip" <<'PYZIPDEMO'
import sys, zipfile
src, out = sys.argv[1], sys.argv[2]
# main.py must sit at the ROOT of the archive: AgentCore resolves the entrypoint
# relative to where the zip is unpacked (/var/task), so a nested path is simply
# not found and the runtime never starts.
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    zf.write(src, "main.py")
PYZIPDEMO
    DEMO_HASH=$("$PYTHON_BIN" - "$BUILD_DIR/demo-agent.zip" <<'PYHASHDEMO'
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()[:16])
PYHASHDEMO
)
    # Hashed key, for the same reason the Lambda package uses one: a fixed key
    # means CloudFormation sees no change and keeps running the old code.
    DEMO_AGENT_S3_KEY="vardoger-demo-agent-${DEMO_HASH}.zip"
    aws s3 cp "$BUILD_DIR/demo-agent.zip" "s3://$BUCKET_NAME/$DEMO_AGENT_S3_KEY" --quiet
    echo "  Uploaded $DEMO_AGENT_S3_KEY (demo agent)"
fi

# 4. Deploy CloudFormation
echo "[4/6] Deploying CloudFormation stack..."
aws cloudformation deploy \
    --template-file "$PROJECT_ROOT/infra/self-hosted.yaml" \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --capabilities CAPABILITY_NAMED_IAM \
    --s3-bucket "$BUCKET_NAME" \
    --s3-prefix cfn-templates \
    --parameter-overrides \
        "ExistingGatewayArn=${VARDOGER_GATEWAY_ARN:-}" \
        "AgentRuntimeArn=$AGENT_RUNTIME_ARN_EFFECTIVE" \
        "AlertEmail=$ALERT_EMAIL" \
        "CodeS3Bucket=$BUCKET_NAME" \
        "CodeS3Key=$CODE_S3_KEY" \
        "AuthMode=$AUTH_MODE" \
        ${AUTH_SECRET_OVERRIDE[@]+"${AUTH_SECRET_OVERRIDE[@]}"} \
        "Tier1Mode=$TIER1_MODE" \
        "LogLevel=$LOG_LEVEL" \
        "DeployDemoRuntime=$DEMO_RUNTIME" \
        "DemoAgentS3Key=$DEMO_AGENT_S3_KEY" \
        "DetectionFailurePolicy=$DETECTION_FAILURE_POLICY" \
        "Tier2MlEndpoint=$TIER2_ENDPOINT" \
        "Tier2KillEnabled=$TIER2_KILL_ENABLED" \
        "Tier3Enabled=$TIER3_ENABLED" \
        "Tier3KillEnabled=$TIER3_KILL_ENABLED" \
        "GlobalKillEnabled=$GLOBAL_KILL_ENABLED" \
        "DeployTestHarness=$NEW_HARNESS" \
        "PremiumSignatureBucket=$PREMIUM_SIGNATURE_BUCKET" \
        "PremiumSignaturePrefix=$PREMIUM_SIGNATURE_PREFIX" \
        "PremiumSignatureRoleArn=$PREMIUM_SIGNATURE_ROLE_ARN" \
        "CorsAllowOrigins=$CORS_ORIGINS" \
    --no-fail-on-empty-changeset

# Show outputs
echo ""
echo "=== Stack Outputs ==="
# Render as an aligned key: value list rather than `--output table`. The table
# format stretches to the width of the longest Description cell (one output has
# a full sentence), producing an unreadable wall of dashes in most terminals.
# This shows every output — key, value, and description — narrowly. Tab-
# delimited from the CLI so values with spaces stay intact.
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[].[OutputKey,OutputValue,Description]' \
    --output text | sort | while IFS=$'\t' read -r _key _value _desc; do
        printf '  %-26s %s\n' "$_key" "$_value"
        # Print the description as an indented sub-line only when present
        # (AWS emits "None" for outputs without one).
        if [ -n "$_desc" ] && [ "$_desc" != "None" ]; then
            printf '  %-26s   ↳ %s\n' "" "$_desc"
        fi
    done

DISPATCHER_ARN=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`DispatcherFunctionArn`].OutputValue' \
    --output text)

# The control-plane URL depends on the auth mode: none/token emit
# ControlPlaneFunctionUrl (Lambda Function URL; token mode gates it with the
# bearer secret); cognito modes emit ControlPlaneApiUrl (API Gateway behind the
# JWT authorizer).
if [ "$AUTH_MODE" = "none" ] || [ "$AUTH_MODE" = "token" ]; then
    CONTROL_PLANE_OUTPUT_KEY="ControlPlaneFunctionUrl"
else
    CONTROL_PLANE_OUTPUT_KEY="ControlPlaneApiUrl"
fi
CONTROL_PLANE_URL=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='${CONTROL_PLANE_OUTPUT_KEY}'].OutputValue" \
    --output text)

UI_BUCKET=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`UiBucketName`].OutputValue' \
    --output text)

DASHBOARD_URL=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`DashboardUrl`].OutputValue' \
    --output text)

DISTRIBUTION_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`DashboardDistributionId`].OutputValue' \
    --output text 2>/dev/null || true)

# With the test harness the agent runtime is created by this stack, so its ARN
# cannot be a template input: Gateway needs Dispatcher, Harness needs Gateway,
# and Dispatcher would need Harness. The second pass breaks that cycle by
# supplying the ARN once it exists, narrowing the StopRuntimeSession grant from
# "any runtime in this account" to exactly this one.
# The demo runtime takes precedence when both are deployed: it is the only one
# StopRuntimeSession can actually stop, so scoping the kill grant to it is what
# makes enforcement demonstrable. A harness-managed runtime refuses the call.
if [ "$DEMO_RUNTIME" = "true" ]; then
    DEMO_RUNTIME_ARN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`DemoAgentRuntimeArn`].OutputValue' --output text 2>/dev/null || true)
    if [ -n "$DEMO_RUNTIME_ARN" ] && [ "$DEMO_RUNTIME_ARN" != "None" ]; then
        AGENT_RUNTIME_ARN_EFFECTIVE="$DEMO_RUNTIME_ARN"
        echo ""
        echo "  Demo runtime: $DEMO_RUNTIME_ARN"
    fi
fi

if [ "$NEW_HARNESS" = "true" ]; then
    HARNESS_RUNTIME_ARN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestHarnessAgentRuntimeArn`].OutputValue' --output text 2>/dev/null || true)
    if [ -n "$HARNESS_RUNTIME_ARN" ] && [ "$HARNESS_RUNTIME_ARN" != "None" ]; then
        AGENT_RUNTIME_ARN_EFFECTIVE="$HARNESS_RUNTIME_ARN"
        echo ""
        echo "  Test harness runtime: $HARNESS_RUNTIME_ARN"
    fi
fi

# 5. Second pass: now that CloudFront exists, add the dashboard origin to CORS
# so the SPA (served from CloudFront over HTTPS) can call the control plane. In
# cognito mode, also register the dashboard origin as the OAuth callback URL.
if [ -n "$DASHBOARD_URL" ] && [ "$DASHBOARD_URL" != "None" ]; then
    FULL_CORS="${DASHBOARD_URL},http://localhost:5173,http://localhost:3000"
    CALLBACK_URLS="${DASHBOARD_URL},http://localhost:5173"
    echo ""
    echo "[5/6] Adding dashboard origin to CORS: $DASHBOARD_URL"
    aws cloudformation deploy \
        --template-file "$PROJECT_ROOT/infra/self-hosted.yaml" \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --capabilities CAPABILITY_NAMED_IAM \
        --s3-bucket "$BUCKET_NAME" \
        --s3-prefix cfn-templates \
        --parameter-overrides \
            "ExistingGatewayArn=${VARDOGER_GATEWAY_ARN:-}" \
            "AgentRuntimeArn=$AGENT_RUNTIME_ARN_EFFECTIVE" \
            "AlertEmail=$ALERT_EMAIL" \
            "CodeS3Bucket=$BUCKET_NAME" \
            "CodeS3Key=$CODE_S3_KEY" \
            "AuthMode=$AUTH_MODE" \
            ${AUTH_SECRET_OVERRIDE[@]+"${AUTH_SECRET_OVERRIDE[@]}"} \
            "Tier1Mode=$TIER1_MODE" \
        "LogLevel=$LOG_LEVEL" \
        "DeployDemoRuntime=$DEMO_RUNTIME" \
        "DemoAgentS3Key=$DEMO_AGENT_S3_KEY" \
            "DetectionFailurePolicy=$DETECTION_FAILURE_POLICY" \
            "Tier2MlEndpoint=$TIER2_ENDPOINT" \
            "Tier2KillEnabled=$TIER2_KILL_ENABLED" \
            "Tier3Enabled=$TIER3_ENABLED" \
            "Tier3KillEnabled=$TIER3_KILL_ENABLED" \
            "GlobalKillEnabled=$GLOBAL_KILL_ENABLED" \
            "DeployTestHarness=$NEW_HARNESS" \
            "PremiumSignatureBucket=$PREMIUM_SIGNATURE_BUCKET" \
            "PremiumSignaturePrefix=$PREMIUM_SIGNATURE_PREFIX" \
            "PremiumSignatureRoleArn=$PREMIUM_SIGNATURE_ROLE_ARN" \
            "CorsAllowOrigins=$FULL_CORS" \
            "CognitoCallbackUrls=$CALLBACK_URLS" \
        --no-fail-on-empty-changeset
else
    # Step 5 is conditional. Without this branch the operator sees
    # 1,2,3,4,6 and reasonably wonders what happened to 5.
    echo ""
    echo "[5/6] No dashboard URL in stack outputs; skipping the CORS second pass."
fi

# Read Cognito outputs (present only in cognito modes) for the frontend build.
COGNITO_DOMAIN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`CognitoHostedUiDomain`].OutputValue' --output text 2>/dev/null || true)
COGNITO_CLIENT_ID=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`CognitoAppClientId`].OutputValue' --output text 2>/dev/null || true)

# 6. Build and upload the frontend (skip with --skip-frontend)
if [ "${SKIP_FRONTEND:-}" != "1" ] && command -v npm >/dev/null 2>&1; then
    echo ""
    echo "[6/6] Building and uploading dashboard..."
    API_BASE="${CONTROL_PLANE_URL%/}/api"
    (
        cd "$PROJECT_ROOT/frontend"
        npm install --silent
        VITE_API_BASE_URL="$API_BASE" \
        VITE_AUTH_MODE="$AUTH_MODE" \
        VITE_COGNITO_DOMAIN="${COGNITO_DOMAIN:-}" \
        VITE_COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-}" \
        VITE_COGNITO_REDIRECT_URI="${DASHBOARD_URL:-}" \
            npm run build
    )
    # index.html must not be cached; hashed assets can be cached forever.
    aws s3 sync "$PROJECT_ROOT/frontend/dist/" "s3://$UI_BUCKET/" \
        --region "$REGION" --delete \
        --cache-control "public, max-age=31536000, immutable" \
        --exclude "index.html"
    aws s3 cp "$PROJECT_ROOT/frontend/dist/index.html" "s3://$UI_BUCKET/index.html" \
        --region "$REGION" --cache-control "no-cache"
    # Invalidate CloudFront so the new build is served immediately.
    if [ -n "$DISTRIBUTION_ID" ] && [ "$DISTRIBUTION_ID" != "None" ]; then
        aws cloudfront create-invalidation \
            --distribution-id "$DISTRIBUTION_ID" \
            --paths "/*" >/dev/null || true
    fi
    echo "  Dashboard uploaded."
else
    echo ""
    echo "[6/6] Skipping frontend build (npm not found or SKIP_FRONTEND=1)."
    echo "  To build manually:"
    echo "    cd frontend && VITE_API_BASE_URL='${CONTROL_PLANE_URL%/}/api' npm install && npm run build"
    echo "    aws s3 sync dist/ s3://$UI_BUCKET/"
fi

echo ""
echo "=== Deploy Complete ==="
echo ""
echo "Dashboard:   $DASHBOARD_URL"
echo "Control API: ${CONTROL_PLANE_URL%/}/api"
echo ""
if [ "$AUTH_MODE" = "token" ]; then
    echo "Auth: token mode. Every API request must send:"
    echo "    Authorization: Bearer <secret>"
    if [ "$AUTH_SECRET_GENERATED" = "1" ]; then
        echo ""
        echo "  A secret was generated for you. SAVE IT NOW — it is not shown again:"
        echo ""
        echo "    $AUTH_SECRET"
        echo ""
        echo "  Open the dashboard and paste it into the access-token screen."
        echo "  Rotate later by redeploying with VARDOGER_AUTH_SECRET set."
    elif [ "$AUTH_SECRET_USE_PREVIOUS" = "1" ]; then
        echo "  Kept the existing secret (stack update). It was not rotated."
        echo "  To rotate, redeploy with VARDOGER_AUTH_SECRET set to a new value."
    else
        echo "  Using the VARDOGER_AUTH_SECRET you supplied."
    fi
    echo ""
fi
if [ "$DEMO_RUNTIME" = "true" ]; then
    DEMO_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`DemoGatewayUrl`].OutputValue' --output text 2>/dev/null || true)
    echo "=== Demo runtime (self-managed) ==="
    echo ""
    echo "A protocol-less gateway sits IN FRONT of a self-managed agent runtime,"
    echo "with the dispatcher already attached as a REQUEST interceptor."
    echo ""
    echo "  Prompt endpoint: ${DEMO_URL%/}/agent/invocations"
    echo "  Test Console:    paste that URL with the tool name LEFT EMPTY."
    echo ""
    echo "  Unlike the test harness, this runtime CAN be stopped, so the session"
    echo "  kill is demonstrable here. AgentCore refuses StopRuntimeSession on a"
    echo "  harness-managed runtime."
    echo ""
fi
if [ "$NEW_HARNESS" = "true" ]; then
    TH_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestHarnessGatewayUrl`].OutputValue' --output text 2>/dev/null || true)
    TH_POOL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestHarnessUserPoolId`].OutputValue' --output text 2>/dev/null || true)
    TH_CLIENT=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestHarnessClientId`].OutputValue' --output text 2>/dev/null || true)
    TH_TOKEN_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestHarnessTokenEndpoint`].OutputValue' --output text 2>/dev/null || true)
    echo "=== Test harness ==="
    echo ""
    echo "A test gateway was created and the dispatcher is ALREADY attached as a"
    echo "REQUEST interceptor - no manual wiring needed."
    echo ""
    echo "  Gateway URL:  ${TH_URL}"
    TH_TOOL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestHarnessToolName`].OutputValue' --output text 2>/dev/null || true)
    echo "  Test Console: paste ${TH_URL}  with tool name  ${TH_TOOL}"
    echo ""
    echo "  Get a bearer token for the Test Console:"
    echo ""
    echo "    SECRET=\$(aws cognito-idp describe-user-pool-client --region $REGION \\"
    echo "      --user-pool-id ${TH_POOL} --client-id ${TH_CLIENT} \\"
    echo "      --query 'UserPoolClient.ClientSecret' --output text)"
    echo "    curl -s -X POST '${TH_TOKEN_URL}' \\"
    echo "      -H 'Content-Type: application/x-www-form-urlencoded' \\"
    echo "      -d \"grant_type=client_credentials&client_id=${TH_CLIENT}&client_secret=\$SECRET&scope=vardoger-gateway/invoke\""
    echo ""
    echo "  Tokens expire (typically 1 hour). See docs/test-harness.md."
    echo ""
    exit 0
fi

echo "Next step: Configure this Lambda ARN as a REQUEST interceptor on your Gateway:"
echo ""
echo "  $DISPATCHER_ARN"
echo ""
