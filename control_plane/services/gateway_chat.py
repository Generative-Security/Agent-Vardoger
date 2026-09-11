"""Forward a Test Console prompt to a Bedrock AgentCore Gateway over MCP.

This backs the Test Console: it issues an MCP ``tools/call`` against the
operator-supplied gateway URL so the request flows through the same interceptor
that protects production traffic, then returns the tool's response. The gateway
URL and tool name are caller/env supplied; nothing deployment-specific is baked
in here.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import uuid
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from control_plane.schemas.chat import ChatRequest, ChatResponse

logger = logging.getLogger(__name__)

# Keep this comfortably under the control-plane Lambda's 28s timeout so a slow
# gateway surfaces as a handled error rather than a Lambda timeout.
_GATEWAY_TIMEOUT_SECONDS = 20
# Cap the response we read from the (caller-supplied) gateway.
_MAX_RESPONSE_BYTES = 1_000_000

# Default host allowlist for Bedrock AgentCore gateways. Real endpoints are
# REGIONAL: <id>.gateway.bedrock-agentcore.<region>.amazonaws.com — the region
# sits between "bedrock-agentcore" and "amazonaws.com", so a fixed suffix like
# ".gateway.bedrock-agentcore.amazonaws.com" can never match. We match the full
# shape with a regex instead.
# MCP protocol version advertised to the gateway. A gateway rejects a version
# outside its own supportedVersions list, and the previous hardcoded
# "2025-06-18" was absent from a live gateway advertising
# ["2026-07-28", "2025-11-25"] — so the Test Console could not have negotiated
# with it regardless of auth. Overridable, because that list moves over time and
# a pinned constant fails silently against a newer gateway.
#
# Check yours with:
#   aws bedrock-agentcore-control get-gateway --gateway-identifier <id>
#     --query 'protocolConfiguration.mcp.supportedVersions'
MCP_PROTOCOL_VERSION = os.environ.get("VARDOGER_MCP_PROTOCOL_VERSION", "2025-11-25").strip() or "2025-11-25"

_DEFAULT_GATEWAY_HOST_RE = re.compile(
    r"^[a-z0-9][a-z0-9-]*\.gateway\.bedrock-agentcore\.[a-z0-9-]+\.amazonaws\.com$"
)


class GatewayUrlError(ValueError):
    """Raised when a caller-supplied gateway URL fails SSRF validation."""


class _NoRedirect(request.HTTPRedirectHandler):
    """Refuse HTTP redirects.

    Validation only covers the initial URL, so following a 3xx to an
    attacker-chosen Location would reopen the SSRF hole (an allowlisted host
    could redirect to an internal IP). MCP gateways answer in-band, so a
    redirect is not expected; treat one as an error.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GatewayUrlError(f"Gateway attempted a redirect to {newurl!r}; refusing")


_opener = request.build_opener(_NoRedirect)


def _host_allowed(host: str) -> bool:
    """Return True when the host is permitted by the allowlist.

    Behavior is controlled by VARDOGER_TEST_CONSOLE_ALLOWED_HOSTS:
      - unset  -> the default AgentCore regional gateway pattern must match.
      - "*"    -> host allowlisting disabled (scheme + private-range checks
                  in validate_gateway_url still apply).
      - other  -> comma-separated list of exact hosts or ".suffix" entries;
                  the host must equal an exact entry or end with a suffix.
    """
    raw = os.environ.get("VARDOGER_TEST_CONSOLE_ALLOWED_HOSTS", "").strip()
    if not raw:
        return bool(_DEFAULT_GATEWAY_HOST_RE.match(host))
    entries = [s.strip().lower() for s in raw.split(",") if s.strip()]
    if entries == ["*"]:
        return True
    for entry in entries:
        if entry.startswith("."):
            if host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


def _is_disallowed_ip(ip_str: str) -> bool:
    """Return True for loopback/private/link-local/reserved addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_gateway_url(url: str) -> None:
    """Validate a caller-supplied gateway URL against SSRF risks.

    Enforces HTTPS, an optional host allowlist, and rejects URLs that resolve to
    private/loopback/link-local/reserved IP ranges (checked after DNS
    resolution, so a public hostname pointing at an internal IP is caught).
    Raises :class:`GatewayUrlError` on any violation.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise GatewayUrlError("Gateway URL must use https://")
    host = (parsed.hostname or "").lower()
    if not host:
        raise GatewayUrlError("Gateway URL has no host")

    if not _host_allowed(host):
        raise GatewayUrlError("Gateway host is not in the allowlist")

    # Resolve and reject internal ranges. A literal IP host is checked directly.
    try:
        resolved = {info[4][0] for info in socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)}
    except socket.gaierror as exc:
        raise GatewayUrlError(f"Gateway host does not resolve: {exc}") from exc
    if not resolved:
        raise GatewayUrlError("Gateway host did not resolve to any address")
    for ip_str in resolved:
        if _is_disallowed_ip(ip_str):
            raise GatewayUrlError("Gateway host resolves to a disallowed (internal) address")


def _parse_mcp_body(body: str) -> dict:
    """Parse an MCP response body (handles SSE ``data:`` framing or plain JSON)."""
    for line in body.splitlines():
        if line.startswith("data:"):
            payload = line.split(":", 1)[1].strip()
            if payload and payload != "[DONE]":
                return json.loads(payload)
    return json.loads(body)


def _extract_tool_payload(mcp_response: dict) -> dict:
    """Pull the tool result out of an MCP response envelope.

    A JSON-RPC *error* must surface as an error. Previously an error envelope
    has no ``result``, so this fell through to ``return result`` -- an empty
    dict -- and the caller then read ``status`` as its "success" default with a
    blank ``response``. The gateway's own diagnosis ("Tool not found",
    "Missing Bearer token") was discarded, and the operator saw only the UI's
    "No response body returned." fallback: a real, explained failure rendered
    as a successful call that happened to say nothing.
    """
    error = mcp_response.get("error")
    if isinstance(error, dict):
        message = str(error.get("message") or "unspecified error")
        data = error.get("data")
        if data:
            message = f"{message} ({data})"
        code = error.get("code")
        prefix = f"Gateway error {code}" if code is not None else "Gateway error"
        return {"status": "error", "response": f"{prefix}: {message}"}

    result = mcp_response.get("result")
    if not isinstance(result, dict):
        return {"status": "error", "response": "Gateway returned no result object."}

    for item in result.get("content") or []:
        if not isinstance(item, dict) or item.get("type") != "text":
            continue
        text = item.get("text") or ""
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {"status": "success", "response": text}
        # A tool may return a bare JSON string or list; only a dict can carry
        # our status/response contract.
        return parsed if isinstance(parsed, dict) else {"status": "success", "response": text}

    # MCP signals a tool-level failure with isError on the result itself.
    if result.get("isError"):
        return {"status": "error", "response": "The tool reported an error but returned no text content."}

    if result:
        return result
    return {"status": "error", "response": "Gateway returned an empty result."}


def send_message(req: ChatRequest) -> ChatResponse:
    """Forward a chat message to the configured Bedrock AgentCore gateway."""
    if not req.gateway_url or not req.tool_name:
        return ChatResponse(
            status="error",
            response=(
                "Test Console is not configured. Provide a gateway URL and tool "
                "name in the console (or set VARDOGER_TEST_CONSOLE_GATEWAY_URL / "
                "VARDOGER_TEST_CONSOLE_TOOL_NAME)."
            ),
            session_id=req.session_id,
            raw={"http_status": 400},
        )

    # SSRF guard: the gateway URL is caller-supplied. Validate scheme, host
    # allowlist, and resolved IP ranges before making any outbound request.
    try:
        validate_gateway_url(req.gateway_url)
    except GatewayUrlError as exc:
        logger.warning("Rejected Test Console gateway URL: %s", exc)
        return ChatResponse(
            status="error",
            response=f"Gateway URL rejected: {exc}",
            session_id=req.session_id,
            raw={"http_status": 400},
        )

    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {
            "name": req.tool_name,
            "arguments": {
                "prompt": req.prompt,
                "session_id": req.session_id,
                "user_id": req.user_id,
            },
        },
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    }
    # AgentCore Gateways require an inbound OAuth bearer token; without it the
    # gateway rejects the MCP call with -32001 "Missing Bearer token". The token
    # comes from the gateway's own identity provider (not Vardoger's auth) and is
    # supplied server-side (VARDOGER_TEST_CONSOLE_GATEWAY_TOKEN) or per request.
    # Sent only when present so an open/dev gateway still works without one.
    gateway_token = (req.gateway_token or "").strip()
    if gateway_token:
        headers["Authorization"] = f"Bearer {gateway_token}"
    http_req = request.Request(
        req.gateway_url,
        data=data,
        method="POST",
        headers=headers,
    )
    try:
        # Use the no-redirect opener so a validated host cannot 3xx to an
        # internal target after the check.
        with _opener.open(http_req, timeout=_GATEWAY_TIMEOUT_SECONDS) as resp:
            raw_bytes = resp.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw_bytes) > _MAX_RESPONSE_BYTES:
                return ChatResponse(
                    status="error",
                    response="Gateway response exceeded the size limit.",
                    session_id=req.session_id,
                    raw={"http_status": 502},
                )
            mcp = _parse_mcp_body(raw_bytes.decode("utf-8", errors="replace"))
    except GatewayUrlError as exc:
        # Raised by the no-redirect handler when the gateway attempts a 3xx.
        logger.warning("Test Console gateway redirect refused: %s", exc)
        return ChatResponse(
            status="error",
            response=f"Gateway URL rejected: {exc}",
            session_id=req.session_id,
            raw={"http_status": 400},
        )
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return ChatResponse(
            status="error",
            response=body or str(exc),
            session_id=req.session_id,
            raw={"http_status": exc.code},
        )
    except (URLError, TimeoutError, OSError) as exc:
        logger.warning("Test Console gateway call failed: %s", exc)
        return ChatResponse(
            status="error",
            response=f"Gateway connection failed: {exc}",
            session_id=req.session_id,
            raw={"http_status": 502},
        )

    tool_payload = _extract_tool_payload(mcp)
    return ChatResponse(
        status=tool_payload.get("status", "success"),
        response=tool_payload.get("response", ""),
        session_id=tool_payload.get("session_id", req.session_id),
        message_count=tool_payload.get("message_count"),
        model=tool_payload.get("model", ""),
        raw=mcp,
    )
