"""A monitor failure must not become a caller-facing outage.

The dispatcher is a REQUEST interceptor. When it raises, the gateway returns
**500 to the caller** — so an exception here is not a monitoring gap, it is an
outage of the agent the monitor was supposed to protect. That inverts the
stated design: a sidecar failure should not risk the resilience of the larger
system.

`DETECTION_FAILURE_POLICY` covered the detection block, but `parse_gateway_event`
ran outside the try, so anything it raised escaped unhandled. The parse touches
every attacker-influenced field on the event — bodies, headers, base64 payloads,
nested JSON — which makes it the likeliest place to throw on a hostile or merely
unfamiliar request, and the least acceptable place to take the agent down.

Note what is NOT covered here: a well-formed response the gateway rejects still
produces a 500, and no amount of exception handling changes that. These tests
constrain what the dispatcher *does*, not what the gateway accepts.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from adapters.agentcore import dispatcher
from vardoger import config


def _mcp_event(method: str = "tools/call") -> dict:
    return {"mcp": {"gatewayRequest": {
        "headers": {},
        "body": {"jsonrpc": "2.0", "id": 1, "method": method,
                 "params": {"name": "echo", "arguments": {"prompt": "hello"}}},
    }}}


def _http_event() -> dict:
    return {"http": {"gatewayRequest": {"path": "/t/invocations",
                                        "httpMethod": "POST",
                                        "headers": {},
                                        "body": "eyJwcm9tcHQiOiJoaSJ9"}}}


def _exploding_parse(*_args, **_kwargs):
    raise RuntimeError("parser blew up on a hostile body")


class TestAParseFailureDoesNotEscape:
    """Left unhandled, each of these is a 500 for the end user."""

    @pytest.mark.parametrize("event", [_mcp_event(), _http_event()],
                             ids=["mcp", "http"])
    def test_fail_open_passes_the_prompt_through(self, event, monkeypatch) -> None:
        monkeypatch.setattr(config, "DETECTION_FAILURE_POLICY", "fail_open")
        with patch.object(dispatcher, "parse_gateway_event", _exploding_parse):
            response = dispatcher.lambda_handler(event, None)
        assert "transformedGatewayRequest" in next(iter(
            v for k, v in response.items() if k in ("mcp", "http")
        )), "fail_open must forward the request, not refuse it"

    @pytest.mark.parametrize("event", [_mcp_event(), _http_event()],
                             ids=["mcp", "http"])
    def test_fail_closed_refuses_rather_than_raising(self, event, monkeypatch) -> None:
        """Still a REFUSAL, which is a 403 — not an unhandled 500."""
        monkeypatch.setattr(config, "DETECTION_FAILURE_POLICY", "fail_closed")
        with patch.object(dispatcher, "parse_gateway_event", _exploding_parse):
            response = dispatcher.lambda_handler(event, None)
        envelope = next(v for k, v in response.items() if k in ("mcp", "http"))
        assert envelope["transformedGatewayResponse"]["statusCode"] == 403

    def test_the_failure_is_recorded_as_degraded(self, monkeypatch) -> None:
        """Silent fail-open is indistinguishable from a clean prompt.

        The degraded metric is the only record that traffic went uninspected,
        and it is what the DegradedComponents alarm fires on.
        """
        monkeypatch.setattr(config, "DETECTION_FAILURE_POLICY", "fail_open")
        with patch.object(dispatcher, "parse_gateway_event", _exploding_parse), \
                patch.object(dispatcher, "report_degraded") as reported:
            dispatcher.lambda_handler(_mcp_event(), None)
        assert reported.called, "a parse failure must report the component degraded"
        assert "parse" in reported.call_args.args[1].lower()

    def test_the_reply_still_uses_the_senders_envelope(self, monkeypatch) -> None:
        """A reply in the wrong envelope is rejected, which is another 500."""
        monkeypatch.setattr(config, "DETECTION_FAILURE_POLICY", "fail_open")
        with patch.object(dispatcher, "parse_gateway_event", _exploding_parse):
            assert "http" in dispatcher.lambda_handler(_http_event(), None)
            assert "mcp" in dispatcher.lambda_handler(_mcp_event(), None)


class TestAnEnvelopeLessEventIsStillRejected:
    """The one case that SHOULD raise, so the guard is not blanket-swallowing.

    An event with no envelope is not gateway traffic at all — an enforcement
    payload mis-routed here, or a malformed invoke. Harvesting its fields as a
    prompt would write bogus session and detection records, so it must fail
    loudly rather than be passed through.
    """

    @pytest.mark.parametrize("junk", [{}, {"Records": []}, {"mcp": "not-a-dict"}])
    def test_it_raises(self, junk) -> None:
        with pytest.raises(ValueError):
            dispatcher.lambda_handler(junk, None)


class TestControlFramesStillPassCleanly:
    """The handshake must survive, or no MCP client can connect at all."""

    @pytest.mark.parametrize("method", ["initialize", "tools/list", "ping",
                                        "notifications/initialized"])
    def test_a_control_frame_is_forwarded_unchanged(self, method) -> None:
        event = _mcp_event(method)
        response = dispatcher.lambda_handler(event, None)
        forwarded = response["mcp"]["transformedGatewayRequest"]["body"]
        assert forwarded == event["mcp"]["gatewayRequest"]["body"]

    def test_no_detection_record_is_created_for_a_handshake(self) -> None:
        """A handshake is not a prompt; recording one pollutes the history."""
        with patch.object(dispatcher, "record_session_evaluation") as recorded:
            dispatcher.lambda_handler(_mcp_event("initialize"), None)
        recorded.assert_not_called()
