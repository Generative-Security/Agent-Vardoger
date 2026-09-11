"""SSRF-hardening tests for the Test Console gateway URL validator."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from control_plane.services import gateway_chat
from control_plane.services.gateway_chat import GatewayUrlError, validate_gateway_url


def _resolve_to(ip: str):
    """Patch socket.getaddrinfo to resolve any host to a fixed IP."""
    return patch(
        "control_plane.services.gateway_chat.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", (ip, 443))],
    )


# A REAL Bedrock AgentCore gateway endpoint is regional:
#   <id>.gateway.bedrock-agentcore.<region>.amazonaws.com
# Tests must use this shape so the default allowlist is validated against the
# real format (a region-less host would let a broken allowlist pass CI).
_REAL_GATEWAY = "https://mygw-abc123.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"


class TestValidateGatewayUrl:
    def test_rejects_http(self):
        with pytest.raises(GatewayUrlError):
            validate_gateway_url("http://mygw.gateway.bedrock-agentcore.us-east-1.amazonaws.com/x")

    def test_rejects_host_not_in_allowlist(self):
        with _resolve_to("203.0.113.10"), pytest.raises(GatewayUrlError):
            validate_gateway_url("https://evil.example.com/x")

    def test_accepts_real_regional_gateway_host(self):
        # The default allowlist MUST accept a real regional endpoint.
        with _resolve_to("52.10.20.30"):
            validate_gateway_url(_REAL_GATEWAY)

    def test_rejects_regionless_gateway_host(self):
        # A region-less host is NOT a real endpoint and must not match the
        # default pattern.
        with _resolve_to("52.10.20.30"), pytest.raises(GatewayUrlError):
            validate_gateway_url("https://foo.gateway.bedrock-agentcore.amazonaws.com/x")

    def test_rejects_private_ip_even_for_allowed_host(self):
        # Real allowed host that resolves to an internal address.
        with _resolve_to("169.254.169.254"), pytest.raises(GatewayUrlError):
            validate_gateway_url(_REAL_GATEWAY)

    def test_rejects_loopback(self):
        with patch.dict("os.environ", {"VARDOGER_TEST_CONSOLE_ALLOWED_HOSTS": "*"}), _resolve_to("127.0.0.1"):
            with pytest.raises(GatewayUrlError):
                validate_gateway_url("https://localhost/x")

    def test_allows_public_ip_on_real_host(self):
        with _resolve_to("52.10.20.30"):
            validate_gateway_url(_REAL_GATEWAY)

    def test_allowlist_disabled_allows_public_host(self):
        with patch.dict("os.environ", {"VARDOGER_TEST_CONSOLE_ALLOWED_HOSTS": "*"}), _resolve_to("52.10.20.30"):
            validate_gateway_url("https://api.example.com/x")

    def test_explicit_allowlist_suffix_entry(self):
        with patch.dict("os.environ", {"VARDOGER_TEST_CONSOLE_ALLOWED_HOSTS": ".example.com"}):
            with _resolve_to("52.10.20.30"):
                validate_gateway_url("https://api.example.com/x")
                with pytest.raises(GatewayUrlError):
                    validate_gateway_url("https://api.other.com/x")


class TestSendMessageRejects:
    def test_send_message_rejects_bad_url_without_request(self):
        from control_plane.schemas.chat import ChatRequest

        req = ChatRequest(
            prompt="hi",
            session_id="s1",
            gateway_url="http://169.254.169.254/latest/meta-data",
            tool_name="chat",
        )
        # The outbound opener must never be called for a rejected URL.
        with patch("control_plane.services.gateway_chat._opener.open") as mock_open:
            resp = gateway_chat.send_message(req)
        assert resp.status == "error"
        assert resp.raw.get("http_status") == 400
        mock_open.assert_not_called()

    def test_redirect_is_refused(self):
        # A redirect raised by the no-redirect opener is surfaced as a 400.
        from control_plane.schemas.chat import ChatRequest

        req = ChatRequest(
            prompt="hi",
            session_id="s1",
            gateway_url=_REAL_GATEWAY,
            tool_name="chat",
        )
        with _resolve_to("52.10.20.30"), \
                patch("control_plane.services.gateway_chat._opener.open",
                      side_effect=GatewayUrlError("Gateway attempted a redirect")):
            resp = gateway_chat.send_message(req)
        assert resp.status == "error"
        assert resp.raw.get("http_status") == 400
