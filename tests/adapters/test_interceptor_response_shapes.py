"""The interceptor must reply in the envelope the gateway sent.

Shapes here were established by testing candidate responses against a live
protocol-less gateway, not inferred from documentation:

    accepted   http.transformedGatewayRequest = {body}
    accepted   http.transformedGatewayRequest = {body, headers}
    REJECTED   http.transformedGatewayRequest = {body, headers, path, httpMethod}
    accepted   http.transformedGatewayResponse = {statusCode, body}

A reply in the wrong envelope yields "Received invalid response from
interceptor". That refuses the request, so it fails closed — but by accident
rather than by design, and it presents as an outage rather than as a block. The
sidecar posture depends on passthrough actually passing through.
"""
from __future__ import annotations

import base64
import json

from adapters.agentcore.dispatcher import _passthrough_response, _terminate_response

ENCODED = base64.b64encode(b'{"prompt":"hello"}').decode()


def _http_event(body: str = ENCODED) -> dict:
    return {"interceptorInputVersion": "1.0",
            "http": {"gatewayRequest": {"path": "/t/invocations",
                                        "httpMethod": "POST",
                                        "headers": {"Content-Type": "application/json"},
                                        "body": body},
                     "gatewayResponse": None}}


def _mcp_event(request_id: int = 7) -> dict:
    return {"mcp": {"gatewayRequest": {"body": {"jsonrpc": "2.0", "id": request_id,
                                                "method": "tools/call"}}}}


class TestHttpPassthrough:
    def test_it_replies_in_the_http_envelope(self) -> None:
        assert "http" in _passthrough_response(_http_event())

    def test_it_carries_the_body_and_nothing_else(self) -> None:
        """path and httpMethod here are rejected by the gateway."""
        request = _passthrough_response(_http_event())["http"]["transformedGatewayRequest"]
        assert set(request) == {"body"}, f"only body is accepted, got {sorted(request)}"

    def test_the_body_is_echoed_verbatim(self) -> None:
        """Still base64. Decoding it here would corrupt the forwarded request."""
        request = _passthrough_response(_http_event())["http"]["transformedGatewayRequest"]
        assert request["body"] == ENCODED

    def test_a_missing_body_does_not_raise(self) -> None:
        response = _passthrough_response({"http": {"gatewayRequest": {}}})
        assert response["http"]["transformedGatewayRequest"]["body"] == ""


class TestHttpBlock:
    def test_it_returns_403_in_the_http_envelope(self) -> None:
        response = _terminate_response(_http_event())["http"]["transformedGatewayResponse"]
        assert response["statusCode"] == 403

    def test_the_body_is_base64_like_the_inbound_one(self) -> None:
        response = _terminate_response(_http_event())["http"]["transformedGatewayResponse"]
        decoded = json.loads(base64.b64decode(response["body"]).decode())
        assert decoded["error"]

    def test_the_refusal_names_no_signature(self) -> None:
        """A block is not a place to tell an attacker what tripped it."""
        response = _terminate_response(_http_event())["http"]["transformedGatewayResponse"]
        decoded = base64.b64decode(response["body"]).decode().lower()
        for leak in ("sig-", "regex", "pattern", "score", "tier"):
            assert leak not in decoded


class TestMcpPathIsUnchanged:
    def test_passthrough_still_uses_the_mcp_envelope(self) -> None:
        response = _passthrough_response(_mcp_event())
        assert response["mcp"]["transformedGatewayRequest"]["body"]["id"] == 7

    def test_the_mcp_body_is_not_base64_encoded(self) -> None:
        """Only the http path encodes; an MCP body is structured JSON."""
        body = _passthrough_response(_mcp_event())["mcp"]["transformedGatewayRequest"]["body"]
        assert isinstance(body, dict)

    def test_block_echoes_the_jsonrpc_request_id(self) -> None:
        """A JSON-RPC client correlates the error by id."""
        response = _terminate_response(_mcp_event(42))["mcp"]["transformedGatewayResponse"]
        assert response["statusCode"] == 403
        assert response["body"]["id"] == 42
        assert response["body"]["error"]["code"] == -32600


class TestUnknownEnvelope:
    def test_it_falls_back_to_mcp_rather_than_emitting_nothing(self) -> None:
        """An envelope-less event reaching here means the guard changed.

        Emitting a malformed reply would fail the request with no explanation;
        the mcp shape at least remains well-formed.
        """
        for response in (_passthrough_response({}), _terminate_response({})):
            assert "mcp" in response
            assert response["interceptorOutputVersion"] == "1.0"
