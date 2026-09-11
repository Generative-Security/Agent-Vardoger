"""Test Console chat request/response models.

The Test Console sends a prompt to a Bedrock AgentCore Gateway (via the MCP
`tools/call` method) so an operator can watch the interceptor evaluate live
traffic. The gateway URL and tool name are supplied by the caller (or from
env defaults) — never hardcoded to a specific deployment, account, or SaaS URL.
"""
from __future__ import annotations

import os

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str
    session_id: str
    # Empty defaults: the operator supplies these in the UI, or an operator sets
    # env defaults for their own deployment. No deployment-specific values ship
    # in the repository.
    gateway_url: str = Field(default_factory=lambda: os.environ.get("VARDOGER_TEST_CONSOLE_GATEWAY_URL", ""))
    tool_name: str = Field(default_factory=lambda: os.environ.get("VARDOGER_TEST_CONSOLE_TOOL_NAME", ""))
    # AgentCore Gateways enforce their own INBOUND auth (an OAuth bearer token
    # from the gateway's identity provider — distinct from Vardoger's own auth).
    # Without it the gateway returns JSON-RPC -32001 "Missing Bearer token"
    # before the interceptor even runs. The token defaults from a server-side
    # env var (keeps the secret out of the browser); an operator may override it
    # per request. Empty means "send no Authorization header" (open gateway).
    gateway_token: str = Field(default_factory=lambda: os.environ.get("VARDOGER_TEST_CONSOLE_GATEWAY_TOKEN", ""))
    user_id: str = "vardoger-ui-user"


class ChatResponse(BaseModel):
    status: str
    response: str = ""
    session_id: str
    message_count: int | None = None
    model: str = ""
    raw: dict = Field(default_factory=dict)
