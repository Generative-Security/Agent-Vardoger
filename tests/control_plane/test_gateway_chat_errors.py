"""A failed gateway call must not be reported as a successful empty one.

Found live: the Test Console showed "No response body returned." for every
failure. An MCP error envelope has no ``result``, so payload extraction fell
through to returning an empty dict; the caller then read ``status`` as its
"success" default with a blank ``response``, and the UI rendered its own
empty-body fallback.

The gateway had in fact explained the problem — "Tool not found",
"Missing Bearer token" — and that explanation was thrown away. The operator was
left debugging a blank screen while the answer sat in the discarded envelope.

This is the same defect shape as the green-bordered error box and the
``stored: false`` HTTP 200: a real failure wearing a success-shaped signal.
"""
from __future__ import annotations

import json

from control_plane.services.gateway_chat import _extract_tool_payload


def _status(payload: dict) -> str:
    """Read status the way send_message does — default 'success' when absent."""
    return payload.get("status", "success")


class TestJsonRpcErrorsSurface:
    def test_tool_not_found_reports_the_gateway_message(self):
        """The real failure from a gateway id pasted into the tool-name field."""
        payload = _extract_tool_payload({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32602,
                      "message": "Tool not found: gateway-quick-start-351e4d-ybguznwwgo"},
        })
        assert _status(payload) == "error"
        assert "Tool not found" in payload["response"]
        assert "-32602" in payload["response"]

    def test_missing_bearer_token_reports_the_gateway_message(self):
        payload = _extract_tool_payload({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32001, "message": "Missing Bearer token"},
        })
        assert _status(payload) == "error"
        assert "Missing Bearer token" in payload["response"]

    def test_error_data_is_included_when_present(self):
        payload = _extract_tool_payload({
            "error": {"code": -32603, "message": "Internal error", "data": "upstream timeout"},
        })
        assert "upstream timeout" in payload["response"]

    def test_an_error_without_a_code_still_reports(self):
        payload = _extract_tool_payload({"error": {"message": "something broke"}})
        assert _status(payload) == "error"
        assert "something broke" in payload["response"]


class TestEmptyAndMalformedResults:
    def test_empty_result_is_an_error_not_a_blank_success(self):
        payload = _extract_tool_payload({"jsonrpc": "2.0", "result": {}})
        assert _status(payload) == "error"
        assert payload["response"]

    def test_missing_result_is_an_error(self):
        payload = _extract_tool_payload({"jsonrpc": "2.0", "id": 1})
        assert _status(payload) == "error"

    def test_tool_level_is_error_flag_is_honoured(self):
        """MCP marks tool failures with isError on the result, not an envelope error."""
        payload = _extract_tool_payload({"result": {"isError": True, "content": []}})
        assert _status(payload) == "error"

    def test_non_dict_json_text_does_not_crash(self):
        """A tool returning a bare JSON list must not break payload reading.

        The previous code returned json.loads(text) directly, so a list reached
        the caller and .get() raised AttributeError.
        """
        payload = _extract_tool_payload({
            "result": {"content": [{"type": "text", "text": '["a", "b"]'}]},
        })
        assert _status(payload) == "success"
        assert payload["response"] == '["a", "b"]'


class TestSuccessStillWorks:
    def test_plain_text_response(self):
        payload = _extract_tool_payload({
            "result": {"content": [{"type": "text", "text": "hello there"}]},
        })
        assert _status(payload) == "success"
        assert payload["response"] == "hello there"

    def test_structured_json_response_is_passed_through(self):
        payload = _extract_tool_payload({
            "result": {"content": [{"type": "text",
                                    "text": '{"status":"success","response":"hi","model":"m"}'}]},
        })
        assert payload["response"] == "hi"
        assert payload["model"] == "m"

    def test_non_text_content_items_are_skipped(self):
        payload = _extract_tool_payload({
            "result": {"content": [{"type": "image", "data": "..."},
                                   {"type": "text", "text": "after the image"}]},
        })
        assert payload["response"] == "after the image"


class TestAToolWithItsOwnSchemaIsNotRenderedBlank:
    """A tool returns whatever it returns; it owes us no {status,response}.

    The echo target returns ``{"result": "echo: ..."}``. That parsed cleanly as
    a dict, so it was handed back verbatim as the payload — and the caller then
    read a missing ``response`` key as ``""`` with ``status`` defaulting to
    "success". A working tool call rendered as an empty box in the Test
    Console, while a BLOCKED prompt displayed its reason correctly.

    That asymmetry is the tell: the failure path was fine and the success path
    was silent. Same defect shape this module already guards one level up.
    """

    def _text(self, payload: dict) -> dict:
        return _extract_tool_payload(
            {"jsonrpc": "2.0", "id": 1,
             "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}}
        )

    def test_the_echo_targets_own_shape_is_displayed(self):
        """Verbatim from the shipped test harness echo Lambda."""
        payload = self._text({"result": "echo: {\"prompt\": \"hello\"}"})
        assert payload["response"], "a successful tool call rendered as nothing"
        assert "hello" in payload["response"]
        assert _status(payload) == "success"

    def test_our_own_contract_still_wins_when_present(self):
        payload = self._text({"status": "success", "response": "the answer",
                              "session_id": "s1", "model": "m"})
        assert payload["response"] == "the answer"
        assert payload["session_id"] == "s1"

    def test_an_error_status_from_the_tool_is_preserved(self):
        """A tool reporting its own failure must not read as success."""
        payload = self._text({"status": "error", "result": "it broke"})
        assert _status(payload) == "error"

    def test_other_common_answer_fields_are_read(self):
        for key in ("result", "output", "completion", "text", "message"):
            payload = self._text({key: "the answer"})
            assert payload["response"] == "the answer", key

    def test_an_unrecognised_shape_shows_the_document_rather_than_nothing(self):
        """Blank is indistinguishable from a silent failure; raw JSON is not."""
        payload = self._text({"totally": {"unexpected": 1}})
        assert "unexpected" in payload["response"]

    def test_plain_text_is_unaffected(self):
        payload = _extract_tool_payload(
            {"result": {"content": [{"type": "text", "text": "just words"}]}}
        )
        assert payload["response"] == "just words"
