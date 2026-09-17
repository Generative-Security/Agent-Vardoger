"""Demo agent for AgentCore Runtime — a self-managed echo target.

Deployed by the stack when ``VARDOGER_DEMO_RUNTIME=true``. Its whole job is to
be a *self-managed* runtime that Vardoger can sit in front of, because the
bundled test harness cannot demonstrate the session kill: AgentCore refuses
StopRuntimeSession on a harness-managed runtime with

    ValidationException: ... is managed by a harness and cannot be invoked
    directly

so the one claim that matters most is unprovable there.

**Deliberately dependency-free.** AgentCore's direct code deployment accepts a
zip whose entrypoint either uses the bedrock_agentcore SDK's ``@app.entrypoint``
decorator or implements the two HTTP endpoints itself. Implementing them means
the deployment package is this single file: no pip install, no arm64 wheel
building, no uv, nothing to drift or to rebuild on a different architecture.
The runtime contract is small enough that the SDK earns nothing here.

The service contract AgentCore requires:

    GET  /ping         liveness. Must answer 200 or the runtime is torn down.
    POST /invocations  the prompt. Answer with JSON.

Echo, not a model. A demo target should make it obvious what Vardoger did to a
prompt, and a model's answer only obscures that — the point is to see the
prompt arrive, be judged, and be allowed or refused.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# AgentCore always talks to the container on 8080. PORT is honoured only so the
# file can be run locally on another port while testing.
PORT = int(os.environ.get("PORT", "8080"))

# A caller-supplied body should never be able to exhaust memory here. AgentCore
# enforces its own limits upstream; this is the last line, not the first.
MAX_BODY_BYTES = 1024 * 1024


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 so the runtime can keep the connection alive between turns.
    protocol_version = "HTTP/1.1"

    def _respond(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/ping":
            # Healthy means "this process can answer", nothing more. Reporting
            # anything richer here would let a downstream problem take the
            # runtime down, and AgentCore tears down a runtime that fails ping.
            self._respond(200, {"status": "healthy"})
            return
        self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/invocations":
            self._respond(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            # Refused WITHOUT reading the body: buffering it is the very thing
            # being prevented. The connection is then closed rather than reused,
            # because the unread body would otherwise be parsed as the start of
            # the next request on a keep-alive connection. A client mid-upload
            # may see the close before the response, which is expected.
            self.close_connection = True
            self._respond(413, {"error": "request body too large"})
            return

        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            # Echo it back as text rather than failing. A malformed body is a
            # perfectly good thing to send a security monitor on purpose, and
            # this target exists to be sent things on purpose.
            self._respond(200, {"result": f"echo: {raw[:500]!r}"})
            return

        prompt = ""
        if isinstance(payload, dict):
            for key in ("prompt", "input", "text", "message"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    prompt = value
                    break
            if not prompt:
                prompt = json.dumps(payload)[:500]
        else:
            prompt = str(payload)[:500]

        # The session id AgentCore assigns, echoed back so a human testing by
        # hand can correlate this turn with the dispatcher log and the session
        # registry without digging through CloudWatch.
        session_id = self.headers.get("X-Amzn-Bedrock-AgentCore-Runtime-Session-Id", "")
        self._respond(200, {"result": f"echo: {prompt}", "session_id": session_id})

    def log_message(self, fmt: str, *args) -> None:
        """Log to stdout so the lines reach CloudWatch.

        BaseHTTPRequestHandler writes to stderr by default, which AgentCore
        also captures -- but keeping request logs on stdout leaves stderr
        meaning "something went wrong", which is worth more than tidiness.
        """
        print("agent %s" % (fmt % args), flush=True)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), _Handler)
    print(f"demo agent listening on :{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
