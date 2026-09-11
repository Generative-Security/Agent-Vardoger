"""Test Console chat endpoint.

Operator/admin only — sends a prompt through a Bedrock AgentCore Gateway so the
operator can watch the interceptor evaluate live traffic.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from control_plane.dependencies import require_role
from control_plane.schemas.chat import ChatRequest, ChatResponse
from control_plane.services.gateway_chat import send_message

router = APIRouter(
    prefix="/api/chat",
    tags=["chat"],
    dependencies=[Depends(require_role("operator"))],
)


@router.post("/message")
def message(req: ChatRequest) -> ChatResponse:
    """Forward a chat message to the configured Bedrock AgentCore gateway."""
    return send_message(req)
