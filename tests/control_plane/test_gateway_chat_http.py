"""The Test Console must reach BOTH gateway placements, not just the MCP one.

Vardoger attaches to two topologies and the interceptor already handles both:

    gateway BEHIND the agent   MCP protocol, exposes tools, prompt arrives as
                               ``tools/call`` -> ``params.arguments``
    gateway IN FRONT of it     protocol-less, no MCP layer, no tools at all,
                               prompt arrives as a raw POST body

The console only ever spoke the first. Because a tool name was mandatory, the
in-front topology — the one that sees real end-user prompts, and the one the
product's prompt-injection claim rests on — could not be exercised from the
dashboard at all. The operator's only signal was ``tools/list`` returning
``[]``, which reads as a broken deployment rather than as a question that does
not apply to that gateway.

Also covered: MCP protocol-version negotiation. Two different hardcoded
versions have now been wrong against a live gateway, each presenting as a total
failure of the console. The rejection names the versions the gateway accepts,
so a wrong default should cost one retry rather than a support ticket.
"""
from __future__ import annotations

import json
from unittest.mock import patch

from control_plane.schemas.chat import ChatRequest
from control_plane.services import gateway_chat
from control_plane.services.gateway_chat import (
    _extract_http_payload,
    _negotiated_version,
)

# Regional shape, so the default host allowlist is genuinely exercised.
_HOST = "https://gw-abc123.gateway.bedrock-agentcore.us-east-1.amazonaws.com"
_HTTP_URL = f"{_HOST}/selfmanaged/invocations"
_MCP_URL = f"{_HOST}/mcp"
_SESSION = "test-console-00000000-0000-0000-0000-000000000001"


def _resolve_to(ip: str = "52.10.20.30"):
    return patch(
        "control_plane.services.gateway_chat.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", (ip, 443))],
    )


def _capture(*responses: tuple[str, int]):
    """Patch _post, returning each response in turn. Records every call."""
    calls: list[dict] = []
    remaining = list(responses)

    def fake_post(url, data, headers):
        calls.append({"url": url, "data": data, "headers": dict(headers)})
        body, status = remaining.pop(0) if remaining else ("{}", 200)
        return body, status, None

    return patch.object(gateway_chat, "_post", side_effect=fake_post), calls


class TestHttpBranchIsReachable:
    def test_a_prompt_sends_without_a_tool_name(self):
        """The whole point: no tool name, no MCP, still a working request."""
        sender, calls = _capture(('{"result": "echo: hello"}', 200))
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_HTTP_URL, tool_name="")
        with _resolve_to(), sender:
            resp = gateway_chat.send_message(req)
        assert resp.status == "success"
        assert resp.response == "echo: hello"
        assert len(calls) == 1

    def test_the_body_is_the_raw_prompt_not_a_jsonrpc_envelope(self):
        sender, calls = _capture(('{"result": "ok"}', 200))
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_HTTP_URL, tool_name="")
        with _resolve_to(), sender:
            gateway_chat.send_message(req)
        body = json.loads(calls[0]["data"].decode())
        assert body["prompt"] == "hello"
        assert "jsonrpc" not in body, "a protocol-less gateway has no JSON-RPC layer"

    def test_the_runtime_session_header_is_sent(self):
        """Without it every prompt lands on its own derived session.

        Session risk accumulation and the terminated-session check both key off
        this, so omitting it would silently defeat multi-turn detection while
        each individual prompt still appeared to work.
        """
        sender, calls = _capture(('{"result": "ok"}', 200))
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_HTTP_URL, tool_name="")
        with _resolve_to(), sender:
            gateway_chat.send_message(req)
        headers = {k.lower(): v for k, v in calls[0]["headers"].items()}
        assert headers.get("x-amzn-bedrock-agentcore-runtime-session-id") == _SESSION

    def test_no_mcp_protocol_header_is_sent(self):
        """It is meaningless here, and a gateway may reject an unknown version."""
        sender, calls = _capture(('{"result": "ok"}', 200))
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_HTTP_URL, tool_name="")
        with _resolve_to(), sender:
            gateway_chat.send_message(req)
        assert not any(k.lower() == "mcp-protocol-version" for k in calls[0]["headers"])

    def test_the_bearer_token_is_still_sent(self):
        sender, calls = _capture(('{"result": "ok"}', 200))
        req = ChatRequest(prompt="hello", session_id=_SESSION, gateway_url=_HTTP_URL,
                          tool_name="", gateway_token="tok123")
        with _resolve_to(), sender:
            gateway_chat.send_message(req)
        assert calls[0]["headers"]["Authorization"] == "Bearer tok123"

    def test_a_missing_gateway_url_still_errors(self):
        resp = gateway_chat.send_message(
            ChatRequest(prompt="hi", session_id=_SESSION, gateway_url="", tool_name="")
        )
        assert resp.status == "error"
        assert "gateway url" in resp.response.lower()

    def test_the_ssrf_guard_still_runs_on_the_http_branch(self):
        """The new branch must not become a way around URL validation."""
        req = ChatRequest(prompt="hi", session_id=_SESSION,
                          gateway_url="http://169.254.169.254/latest/meta-data",
                          tool_name="")
        with patch.object(gateway_chat, "_post") as posted:
            resp = gateway_chat.send_message(req)
        assert resp.status == "error"
        assert resp.raw.get("http_status") == 400
        posted.assert_not_called()


class TestHttpBlockIsDisplayed:
    """A Vardoger block arrives as 403 + ``{"error": ...}``, confirmed live."""

    def test_a_refusal_reports_as_an_error_with_its_message(self):
        sender, _ = _capture(('{"error": "Session terminated by security monitor"}', 403))
        req = ChatRequest(prompt="attack", session_id=_SESSION,
                          gateway_url=_HTTP_URL, tool_name="")
        with _resolve_to(), sender:
            resp = gateway_chat.send_message(req)
        assert resp.status == "error"
        assert resp.response == "Session terminated by security monitor"

    def test_the_session_id_survives_a_block(self):
        """The operator needs it to find the session in the dashboard."""
        sender, _ = _capture(('{"error": "blocked"}', 403))
        req = ChatRequest(prompt="attack", session_id=_SESSION,
                          gateway_url=_HTTP_URL, tool_name="")
        with _resolve_to(), sender:
            resp = gateway_chat.send_message(req)
        assert resp.session_id == _SESSION


class TestHttpPayloadExtraction:
    """No MCP envelope means no agreed schema; never render a blank reply."""

    def test_common_answer_fields_are_read(self):
        for key in ("result", "response", "output", "completion", "text", "message"):
            payload = _extract_http_payload(json.dumps({key: "the answer"}))
            assert payload["response"] == "the answer", key

    def test_an_unrecognised_shape_shows_the_document_rather_than_nothing(self):
        """A blank console is indistinguishable from a silent failure."""
        payload = _extract_http_payload('{"unexpected": {"nested": 1}}')
        assert "unexpected" in payload["response"]

    def test_non_json_is_shown_as_text(self):
        payload = _extract_http_payload("plain text reply")
        assert payload["response"] == "plain text reply"

    def test_an_empty_answer_field_does_not_win_over_a_later_one(self):
        payload = _extract_http_payload('{"result": "", "response": "real answer"}')
        assert payload["response"] == "real answer"


class TestProtocolVersionNegotiation:
    # The live rejection, verbatim.
    _REJECTION = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": -32600,
                  "message": "Unsupported protocol version: 2025-11-25",
                  "data": {"requested": "2025-11-25", "supported": ["2025-03-26"]}},
    })

    def test_the_supported_version_is_read_from_the_rejection(self):
        assert _negotiated_version(json.loads(self._REJECTION)) == "2025-03-26"

    def test_the_newest_supported_version_is_chosen(self):
        assert _negotiated_version({"error": {
            "message": "Unsupported protocol version: x",
            "data": {"supported": ["2024-11-05", "2025-03-26", "2025-01-01"]},
        }}) == "2025-03-26"

    def test_unrelated_errors_do_not_trigger_a_retry(self):
        """Retrying a "Tool not found" would double every failed call."""
        for envelope in (
            {"error": {"code": -32601, "message": "Tool not found"}},
            {"error": {"message": "Unsupported protocol version: x"}},  # no data
            {"error": "not-a-dict"},
            {"result": {"content": []}},
            {},
        ):
            assert _negotiated_version(envelope) == ""

    def test_a_rejected_version_is_retried_on_the_gateway_s_terms(self):
        """The operator's live failure: a wrong configured version.

        VARDOGER_MCP_PROTOCOL_VERSION was set to 2025-11-25 and every call to
        the console failed outright, with the gateway naming 2025-03-26 in the
        rejection the whole time.
        """
        sender, calls = _capture(
            (self._REJECTION, 200),
            ('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}}', 200),
        )
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_MCP_URL, tool_name="echo")
        with _resolve_to(), sender,                 patch.object(gateway_chat, "MCP_PROTOCOL_VERSION", "2025-11-25"):
            resp = gateway_chat.send_message(req)
        assert len(calls) == 2, "the rejection should have been retried"
        assert calls[0]["headers"]["MCP-Protocol-Version"] == "2025-11-25"
        assert calls[1]["headers"]["MCP-Protocol-Version"] == "2025-03-26"
        assert resp.status == "success"

    def test_a_gateway_naming_the_version_we_sent_is_not_retried(self):
        """Otherwise a confused gateway would double every single call.

        The retry is only worth making when the named version DIFFERS from the
        one just refused; naming it back is a contradiction, not an instruction.
        """
        sender, calls = _capture((json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32600,
                      "message": "Unsupported protocol version: 2025-03-26",
                      "data": {"supported": ["2025-03-26"]}},
        }), 200))
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_MCP_URL, tool_name="echo")
        with _resolve_to(), sender:
            gateway_chat.send_message(req)
        assert len(calls) == 1

    def test_a_successful_first_call_is_not_repeated(self):
        sender, calls = _capture(
            ('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}}', 200),
        )
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_MCP_URL, tool_name="echo")
        with _resolve_to(), sender:
            gateway_chat.send_message(req)
        assert len(calls) == 1

    def test_the_default_version_is_one_a_gateway_actually_accepts(self):
        """Guards the value itself, which has twice been wrong in the repo."""
        assert gateway_chat._DEFAULT_MCP_PROTOCOL_VERSION == "2025-03-26"


class TestMcpBranchIsUnchanged:
    def test_a_tool_name_still_produces_a_tools_call(self):
        sender, calls = _capture(
            ('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}}', 200),
        )
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_MCP_URL, tool_name="echo")
        with _resolve_to(), sender:
            resp = gateway_chat.send_message(req)
        body = json.loads(calls[0]["data"].decode())
        assert body["method"] == "tools/call"
        assert body["params"]["name"] == "echo"
        assert body["params"]["arguments"]["prompt"] == "hello"
        assert resp.response == "hi"

    def test_a_whitespace_only_tool_name_takes_the_http_branch(self):
        """A stray space in the UI field must not send a nameless tools/call."""
        sender, calls = _capture(('{"result": "ok"}', 200))
        req = ChatRequest(prompt="hello", session_id=_SESSION,
                          gateway_url=_HTTP_URL, tool_name="   ")
        with _resolve_to(), sender:
            gateway_chat.send_message(req)
        assert "jsonrpc" not in json.loads(calls[0]["data"].decode())
