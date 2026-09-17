from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from vardoger import config
from vardoger.identity import make_source

logger = logging.getLogger(__name__)

# Maximum recursion depth when harvesting strings from a request body. Bounds
# work done on hostile input; deeper structures are truncated, and truncation
# is surfaced via InterceptorEvent.truncated so the caller can fail closed.
_MAX_DEPTH = 12

# Maximum total characters of harvested text handed to the detection engine.
_MAX_INSPECTABLE_CHARS = 256_000

# Keys whose values are protocol scaffolding rather than user-supplied text.
# Kept deliberately small: anything not listed here IS scanned, so a field we
# have never seen before is inspected rather than silently ignored.
_STRUCTURAL_KEYS = frozenset(
    {
        "jsonrpc",
        "id",
        "method",
        "mimetype",
        "type",
        "role",
    }
)


@dataclass
class InterceptorEvent:
    """Parsed fields extracted from a raw MCP gateway interceptor event."""

    session_id: str
    agent_runtime_arn: str
    prompt: str
    # Isolation scope. Always "local" in self-hosted; managed injects a tenant.
    scope_id: str
    # Segmentation dimension: AWS account id + agent, derived from the
    # gateway-asserted account and the deploy-time agent. Never from the body.
    source: str
    # The gateway-asserted AWS account id this request originated from.
    account_id: str
    raw_event: dict[str, Any]
    # Every string the gateway will forward to the agent, concatenated. This is
    # what detection scans -- not `prompt`, which is only the best-effort
    # human-readable extract used for logging and prompt history.
    inspectable_text: str = ""
    # True when a session identifier was asserted by the gateway rather than
    # derived locally. A derived id still permits detection but cannot be
    # correlated across requests.
    session_id_is_authentic: bool = False
    # True when the body was too deep or too large to harvest completely.
    truncated: bool = False

    @property
    def has_inspectable_text(self) -> bool:
        """Return true when there is any caller-supplied text to evaluate."""
        return bool(self.inspectable_text.strip())


def _iter_strings(node: Any, depth: int = 0) -> Iterator[str]:
    """Yield every string in a nested structure, skipping protocol scaffolding.

    Raises no exceptions on malformed input; unknown types are ignored.
    """
    if depth > _MAX_DEPTH:
        return
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key.lower() in _STRUCTURAL_KEYS and isinstance(value, str):
                continue
            yield from _iter_strings(value, depth + 1)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _iter_strings(item, depth + 1)


def _depth_exceeds(node: Any, limit: int = _MAX_DEPTH, depth: int = 0) -> bool:
    """Return true when a structure nests deeper than ``limit``."""
    if depth > limit:
        return True
    if isinstance(node, dict):
        return any(_depth_exceeds(value, limit, depth + 1) for value in node.values())
    if isinstance(node, (list, tuple)):
        return any(_depth_exceeds(item, limit, depth + 1) for item in node)
    return False


# JSON-RPC methods that carry no caller-authored content: handshake and
# discovery frames the client sends before and between real calls. An MCP
# `initialize` body is {clientInfo:{name,version}, protocolVersion}, which
# harvested as "mcp 0.1.0 2025-11-25" and was recorded as a user prompt.
#
# Everything NOT listed here -- tools/call, prompts/get, and any method we do
# not recognise -- is still scanned in full, so an unknown or newly added
# method fails SAFE (inspected) rather than passing unexamined.
_CONTROL_METHODS = frozenset({
    "initialize",
    "ping",
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/templates/list",
    "logging/setLevel",
})


def _is_control_frame(request_body: Any) -> bool:
    """True when the body is a protocol frame rather than caller content."""
    if not isinstance(request_body, dict):
        return False
    method = str(request_body.get("method") or "").strip()
    if not method:
        return False
    # Notifications are one-way protocol signals and never carry a prompt.
    return method in _CONTROL_METHODS or method.startswith("notifications/")


def _harvest_inspectable_text(request_body: Any) -> tuple[str, bool]:
    """Collect every caller-supplied string the gateway would forward.

    Returns:
        (text, truncated): the concatenated text, and whether limits were hit.

    Scanning the whole forwarded body -- rather than one extracted prompt field
    -- is what prevents a parser differential, where detection reads one part of
    the request and the agent receives another.
    """
    truncated = _depth_exceeds(request_body)
    parts: list[str] = []
    total = 0
    for value in _iter_strings(request_body):
        stripped = value.strip()
        if not stripped:
            continue
        remaining = _MAX_INSPECTABLE_CHARS - total
        if remaining <= 0:
            truncated = True
            break
        if len(stripped) > remaining:
            parts.append(stripped[:remaining])
            total = _MAX_INSPECTABLE_CHARS
            truncated = True
            break
        parts.append(stripped)
        total += len(stripped)
    return "\n".join(parts), truncated


def _extract_display_prompt(request_body: Any, arguments: dict[str, Any]) -> str:
    """Best-effort human-readable prompt for logging and prompt history.

    This is NOT the detection input -- see ``inspectable_text``. Unlike the
    previous implementation it reads every message, not just the last one, so
    the stored record matches what was actually sent.
    """
    if not isinstance(request_body, dict):
        return ""

    direct = arguments.get("prompt") or arguments.get("message") or ""
    input_text = request_body.get("inputText")
    if isinstance(input_text, str) and input_text.strip():
        return input_text
    if isinstance(direct, str) and direct.strip():
        return direct

    messages = request_body.get("messages")
    if not isinstance(messages, list):
        return ""

    collected: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content", "")
        if isinstance(content, list):
            for chunk in content:
                if isinstance(chunk, dict):
                    text = chunk.get("text")
                    if isinstance(text, str) and text.strip():
                        collected.append(text)
                elif isinstance(chunk, str) and chunk.strip():
                    collected.append(chunk)
        elif isinstance(content, str) and content.strip():
            collected.append(content)
    return "\n".join(collected)


# session.id inside the W3C baggage header the gateway forwards in
# params._meta. Anchored so "x-session.id=" cannot satisfy it.
_BAGGAGE_SESSION_RE = re.compile(r"(?:^|,)\s*session\.id=([^,\s]+)")


def _account_from_arn(arn: str) -> str:
    """Return the account id from any AWS ARN, or "".

    ARNs are arn:partition:service:region:ACCOUNT:resource, so the account is
    always field 4 when there are enough fields and it looks like an account.
    """
    parts = (arn or "").split(":")
    if len(parts) > 5 and parts[4].strip().isdigit():
        return parts[4].strip()
    return ""


def _account_from_principal_arn(arn: str) -> str:
    """Return the account id from an IAM principal ARN, or "".

    ``arn:aws:iam::701364614161:role/Foo`` -> ``701364614161``. The ARN comes
    from ``mcp.gatewayRequest.context.identity``, which the GATEWAY populates —
    it is absent from ``rawGatewayRequest.body``, so a caller cannot set it.
    That is what makes it safe to attribute on, unlike anything in the body.
    """
    parts = (arn or "").split(":")
    if len(parts) > 5 and parts[4].strip().isdigit():
        return parts[4].strip()
    return ""


def _baggage_keys(params: Any) -> list[str]:
    """Return the key names present in params._meta.baggage, sorted.

    Diagnostic only. `_session_from_baggage` reads exactly one key,
    `session.id`, so any other correlation identifier the caller propagates --
    including, possibly, the AgentCore runtime session id that
    StopRuntimeSession actually needs -- arrives and is discarded unseen.

    Names only. Baggage is caller-authored, so its VALUES are untrusted content
    that does not belong in a log group; the names are enough to decide what is
    worth parsing.
    """
    meta = params.get("_meta") if isinstance(params, dict) else None
    baggage = meta.get("baggage") if isinstance(meta, dict) else None
    if not baggage:
        return []
    keys = []
    for pair in str(baggage).split(","):
        name, _, _value = pair.partition("=")
        name = name.strip()
        if name:
            keys.append(name)
    return sorted(set(keys))


def _session_from_baggage(params: Any) -> str:
    """Return session.id from params._meta.baggage, or "".

    CALLER-SUPPLIED: ``_meta`` travels in the request body, so this value is
    forgeable and is recorded with ``session_id_is_authentic=False``. It is used
    anyway because the alternative is worse — without it every prompt derives a
    unique synthetic id, so no two turns of the same conversation ever correlate
    and session risk accumulation, escalation detection and the session kill all
    become inert. A forged id can misattribute a prompt to another session; a
    missing one guarantees nothing accumulates at all.
    """
    meta = params.get("_meta") if isinstance(params, dict) else None
    baggage = meta.get("baggage") if isinstance(meta, dict) else None
    match = _BAGGAGE_SESSION_RE.search(str(baggage or ""))
    return match.group(1).strip() if match else ""


# Envelope keys an interceptor event may arrive under. "mcp" is an MCP-protocol
# gateway sitting BEHIND an agent (it forwards the agent's tool calls); "http" is
# a protocol-less gateway sitting IN FRONT of an agent runtime (it forwards the
# caller's request). Detected per event rather than configured, so one
# deployment can do both.
_ENVELOPE_KEYS = ("mcp", "http")


def envelope_of(event: dict[str, Any]) -> str:
    """Return the envelope key present on the event, or "" when none is."""
    if not isinstance(event, dict):
        return ""
    for key in _ENVELOPE_KEYS:
        if isinstance(event.get(key), dict):
            return key
    return ""


def _decode_http_body(body: Any) -> Any:
    """Decode an http-envelope body into something inspectable.

    The gateway sends the caller's raw body base64-encoded. Left encoded it
    would be harvested as one meaningless token: every signature would miss,
    detection would report clean, and the failure would be invisible.

    Returns parsed JSON when the payload is JSON (the usual case), the decoded
    text when it is not, and the original value when it is neither base64 nor a
    string — never raising, because a body we cannot decode must still reach the
    scanner as *something* rather than silently becoming empty.
    """
    if not isinstance(body, str) or not body:
        return body
    try:
        raw = base64.b64decode(body, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        # Not base64, or not text: treat it as the literal body. A gateway that
        # stops encoding bodies must not silently stop being inspected.
        return body
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _derive_session_id(event: dict[str, Any], request_body: Any) -> str:
    """Derive a stable synthetic session id when the gateway asserted none.

    Detection must still run for such requests, so rather than passing them
    through unevaluated we key them to a deterministic id. It cannot be
    correlated across requests, which is recorded via
    ``session_id_is_authentic=False``.
    """
    request_context = event.get("requestContext") or {}
    seed = json.dumps(
        {
            "account": request_context.get("accountId", ""),
            "request_id": request_context.get("requestId", ""),
            "body": request_body if isinstance(request_body, (dict, list)) else str(request_body),
        },
        sort_keys=True,
        default=str,
    )
    return "derived-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def parse_gateway_event(event: dict[str, Any]) -> InterceptorEvent:
    """Extract identity and inspectable text from an MCP gateway interceptor event.

    Identity fields (``source``, ``session_id``) are read ONLY from sources the
    gateway asserts, plus deploy-time config. They are never read from the
    request body: a caller who could set its own account or agent could have its
    prompts attributed to, scored against, and rolled up under another source.

    ``scope_id`` is a deploy-time constant (``"local"`` self-hosted), never
    caller-influenced. ``source`` is the AWS account id (gateway-asserted) plus
    the deploy-time agent.
    """
    envelope_key = envelope_of(event)
    envelope = event.get(envelope_key, {}) if envelope_key else {}
    if not isinstance(envelope, dict):
        envelope = {}
    gateway_request = (
        envelope.get("gatewayRequest", {})
        if isinstance(envelope.get("gatewayRequest"), dict)
        else {}
    )
    gateway_headers = gateway_request.get("headers", {})
    if not isinstance(gateway_headers, dict):
        gateway_headers = {}
    # Header lookups are case-insensitive; gateways vary in casing.
    headers_ci = {str(k).lower(): v for k, v in gateway_headers.items()}
    request_context = event.get("requestContext", {})
    if not isinstance(request_context, dict):
        request_context = {}

    request_body = gateway_request.get("body")
    if envelope_key == "http":
        # Base64 on this path; see _decode_http_body for why leaving it encoded
        # silently defeats every signature.
        request_body = _decode_http_body(request_body)
    if request_body is None:
        request_body = event.get("requestBody")
    if request_body is None:
        # Deliberately NOT a fallback to the whole event. The event carries
        # platform metadata the caller never wrote -- X-Ray trace ids
        # (Self=1-...;Root=...;Parent=...;Sampled=1), W3C traceparent, harness
        # and session ids -- and harvesting those as "prompt" text wrote strings
        # into prompt history that no user ever sent, and fed our own headers to
        # the detection engine as if they were caller input.
        request_body = {}
    params = request_body.get("params", {}) if isinstance(request_body, dict) else {}
    arguments = params.get("arguments", {}) if isinstance(params, dict) else {}
    if not isinstance(arguments, dict):
        arguments = {}

    # --- Identity: deploy-time config and platform-set sources only ---
    # `requestContext.accountId` is set by the platform and cannot be forged by
    # the caller. We deliberately do NOT fall back to the `x-amz-account-id`
    # header: if the gateway forwards client headers, a caller could set it and
    # misattribute their prompts to another account. Neither the request body
    # nor `arguments` is consulted at any point.
    account_id = str(request_context.get("accountId") or "").strip()
    if not account_id:
        # Real AgentCore interceptor events carry no `requestContext`; identity
        # arrives as a principal ARN under mcp.gatewayRequest.context.identity.
        # Without this the account half of `source` was always empty, so every
        # record collapsed to agent-only and the <account>/<agent> model — the
        # whole basis of multi-account rollups — never engaged.
        gateway_context = gateway_request.get("context")
        identity = gateway_context.get("identity") if isinstance(gateway_context, dict) else None
        principal_arn = str((identity or {}).get("awsPrincipalArn") or "").strip()
        account_id = _account_from_principal_arn(principal_arn)

    if not account_id:
        # The http envelope carries no identity block at all, so neither source
        # above applies and `source` would lose its account half entirely —
        # which silently disables the <account>/<agent> rollup the source model
        # exists for. The configured agent runtime ARN contains the account and
        # is deploy-time config, so it cannot be influenced by a caller.
        account_id = _account_from_arn(config.AGENT_RUNTIME_ARN)

    # Which headers the gateway actually forwards is not documented and varies
    # by protocol type. NAMES ONLY, never values: these carry bearer tokens.
    # Reachable with VARDOGER_LOG_LEVEL=DEBUG when session ids come through as
    # non-authentic and you need to know whether the header arrived at all.
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Gateway forwarded headers: %s", ",".join(sorted(headers_ci)) or "(none)")
        logger.debug("Baggage keys: %s", ",".join(_baggage_keys(params)) or "(none)")

    asserted_session_id = str(headers_ci.get("mcp-session-id") or "").strip()
    session_id = asserted_session_id
    session_id_is_authentic = bool(asserted_session_id)
    if not session_id:
        # The http path carries the runtime session id as a header rather than
        # in _meta. Gateway-set, so unlike baggage it is not caller-forgeable.
        runtime_session = str(
            headers_ci.get("x-amzn-bedrock-agentcore-runtime-session-id") or ""
        ).strip()
        if runtime_session:
            session_id = runtime_session
            session_id_is_authentic = True
    if not session_id:
        # Second choice: the gateway's baggage header. Caller-supplied, so it is
        # NOT authentic — but it is a real conversation id, which the derived
        # fallback below can never be.
        baggage_session = _session_from_baggage(params)
        if baggage_session:
            session_id = baggage_session
            session_id_is_authentic = False

    # The agent runtime ARN scopes StopRuntimeSession, so deploy-time config is
    # AUTHORITATIVE. A caller-influenceable `x-agent-runtime-arn` header must not
    # be able to retarget or evade kills. The header is only consulted when no
    # ARN is configured (single-agent deploys always set config.AGENT_RUNTIME_ARN).
    agent_runtime_arn = str(
        config.AGENT_RUNTIME_ARN
        or event.get("agentRuntimeArn")
        or headers_ci.get("x-agent-runtime-arn")
        or ""
    ).strip()

    # scope_id is a deploy-time constant, never caller-influenced.
    scope = config.SCOPE_ID or "local"
    # source = account + agent (friendly alias preferred, else the ARN).
    agent_for_source = config.AGENT_ALIAS or agent_runtime_arn
    source = make_source(account_id, agent_for_source)

    # --- Content: scan everything that will be forwarded ------------------
    # A control frame yields no inspectable text, so the dispatcher passes it
    # through without creating a session, a detection event, or a history row.
    if _is_control_frame(request_body):
        inspectable_text, truncated = "", False
    else:
        inspectable_text, truncated = _harvest_inspectable_text(request_body)
    prompt = _extract_display_prompt(request_body, arguments)
    if not prompt.strip() and inspectable_text.strip():
        # Unknown body shape: keep the harvested text as the record so history
        # reflects what was actually evaluated.
        prompt = inspectable_text

    if not session_id and inspectable_text.strip():
        session_id = _derive_session_id(event, request_body)

    return InterceptorEvent(
        session_id=session_id,
        agent_runtime_arn=agent_runtime_arn,
        prompt=prompt,
        scope_id=scope,
        source=source,
        account_id=account_id,
        raw_event=event,
        inspectable_text=inspectable_text,
        session_id_is_authentic=session_id_is_authentic,
        truncated=truncated,
    )
