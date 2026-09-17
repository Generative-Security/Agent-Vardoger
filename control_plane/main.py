"""FastAPI application setup — Agent Vardøger control plane."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from control_plane import config
from control_plane.routers import (
    chat,
    dashboard,
    evaluation,
    health,
    policy,
    prompt_history,
    signatures,
    sources,
)
from control_plane.routers import (
    settings as settings_router,
)

app = FastAPI(title="Agent Vardøger", version="0.1.0")

# --- CORS ---
# CORS is applied by exactly ONE layer, chosen by deployment mode:
#
#   none / token  -> the Lambda Function URL owns CORS. Its Cors config lives in
#                    infra/self-hosted.yaml (resource ControlPlaneUrl.Cors),
#                    populated from the CorsAllowOrigins stack parameter that
#                    scripts/deploy.sh sets (localhost + the CloudFront origin).
#                    We must NOT also add CORSMiddleware here, or every response
#                    carries Access-Control-Allow-Origin TWICE and the browser
#                    rejects it ("header contains multiple values").
#
#   cognito(+idc) -> the API Gateway HTTP API in front of the control plane is
#                    deliberately configured WITHOUT CorsConfiguration, so the
#                    app must add CORS -- CORSMiddleware is enabled. Both layers
#                    were configured at once for a while, which duplicated
#                    Access-Control-Allow-Origin and broke the dashboard; the
#                    template now carries a comment saying why it must not.
#                    The app also answers CORS preflights, which reach it via an
#                    OPTIONS route that carries no authorizer.
#
# So the app-layer middleware is added only when NOT behind a Function URL.
if not config.uses_function_url():
    allowed_origins = [
        origin.strip()
        for origin in config.CORS_ALLOW_ORIGINS.split(",")
        if origin.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(health.router)
app.include_router(dashboard.router)
app.include_router(prompt_history.router)
app.include_router(settings_router.router)
app.include_router(sources.router)
app.include_router(policy.router)
app.include_router(signatures.router)
app.include_router(evaluation.router)
app.include_router(chat.router)
