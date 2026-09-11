import { FormEvent, useEffect, useMemo, useState } from "react";
import { chatApi, dashboardApi, promptHistoryApi, type PromptHistoryRecord, type SessionInfo } from "../api/client";
import { getSelectedSource } from "../sourceSelection";
import SourcePicker from "../components/shared/SourcePicker";

type ChatTurn = {
  role: "user" | "assistant" | "system";
  text: string;
  meta?: string;
};

// Gateway URL and tool name are configuration, never hardcoded to a specific
// deployment. A default gateway URL may be supplied via env; otherwise the
// operator enters it. No account IDs or SaaS URLs are embedded.
const DEFAULT_GATEWAY_URL = import.meta.env.VITE_TEST_CONSOLE_GATEWAY_URL || "";
const DEFAULT_TOOL_NAME = import.meta.env.VITE_TEST_CONSOLE_TOOL_NAME || "";
// Optional: prefill the gateway bearer token from the build env. Usually left
// blank and pasted by the operator — the token is not persisted.
const DEFAULT_GATEWAY_TOKEN = import.meta.env.VITE_TEST_CONSOLE_GATEWAY_TOKEN || "";

// The AWS console lists a gateway's URL WITHOUT the /mcp path, so the value an
// operator copies from it posts to the bare host and never reaches the MCP
// handler. Append the path when none was given, and show what will actually be
// sent rather than silently rewriting the field.
function mcpEndpoint(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  try {
    const url = new URL(trimmed);
    if (url.pathname === "" || url.pathname === "/") {
      url.pathname = "/mcp";
      return url.toString();
    }
    return trimmed;
  } catch {
    // Not parseable — leave it alone and let the server report why.
    return trimmed;
  }
}

function newSessionId() {
  const id =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `test-console-${id}`;
}

function shortId(id: string) {
  return id.length > 22 ? `${id.slice(0, 18)}...` : id || "-";
}

// TestConsolePage: Operator/admin-only live chat against the gateway, with
// recorded prompt telemetry for the selected session. Ported from the sandbox
// live-chat page, single-scope and source-aware.
export default function TestConsolePage() {
  const [source, setSource] = useState(getSelectedSource());
  const [gatewayUrl, setGatewayUrl] = useState(DEFAULT_GATEWAY_URL);
  const [toolName, setToolName] = useState(DEFAULT_TOOL_NAME);
  const [gatewayToken, setGatewayToken] = useState(DEFAULT_GATEWAY_TOKEN);
  // Shown under the fields so the two values that actually trip people up are
  // visible before a request fails, not after.
  const effectiveGatewayUrl = mcpEndpoint(gatewayUrl);
  const urlNeedsMcpPath = effectiveGatewayUrl !== gatewayUrl.trim() && effectiveGatewayUrl !== "";
  const toolNameLooksLikeGatewayId = (() => {
    const name = toolName.trim();
    if (!name || !effectiveGatewayUrl) return false;
    try {
      // e.g. host "my-gw-abc123.gateway.bedrock-agentcore..." vs name "my-gw-abc123"
      return new URL(effectiveGatewayUrl).hostname.startsWith(`${name}.`);
    } catch {
      return false;
    }
  })();
  const [sessionId, setSessionId] = useState(newSessionId);
  const [prompt, setPrompt] = useState("");
  const [sending, setSending] = useState(false);
  const [activeSessions, setActiveSessions] = useState<SessionInfo[]>([]);
  const [terminatedSessions, setTerminatedSessions] = useState<SessionInfo[]>([]);
  const [sessionPrompts, setSessionPrompts] = useState<PromptHistoryRecord[]>([]);
  const [turnsBySession, setTurnsBySession] = useState<Record<string, ChatTurn[]>>({});
  const [loadingSessions, setLoadingSessions] = useState(true);

  const turns = turnsBySession[sessionId] || [];
  const selectedSessionPrompts = useMemo(
    () => sessionPrompts.filter((item) => item.session_id === sessionId),
    [sessionPrompts, sessionId],
  );

  async function loadSessions() {
    setLoadingSessions(true);
    try {
      const [sessionsResponse, promptsResponse] = await Promise.all([
        dashboardApi.sessions(source),
        promptHistoryApi.search({ hours: 24, limit: 200, source }),
      ]);
      setActiveSessions(sessionsResponse.data.active_sessions || []);
      setTerminatedSessions(sessionsResponse.data.terminated_sessions || []);
      setSessionPrompts(promptsResponse.data.records || []);
    } finally {
      setLoadingSessions(false);
    }
  }

  useEffect(() => {
    void loadSessions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source]);

  function appendTurn(turn: ChatTurn) {
    setTurnsBySession((current) => ({
      ...current,
      [sessionId]: [...(current[sessionId] || []), turn],
    }));
  }

  async function send(event: FormEvent) {
    event.preventDefault();
    const text = prompt.trim();
    if (!text || sending) return;
    setPrompt("");
    setSending(true);
    appendTurn({ role: "user", text });
    try {
      const response = await chatApi.message({
        prompt: text,
        session_id: sessionId,
        gateway_url: mcpEndpoint(gatewayUrl),
        tool_name: toolName,
        gateway_token: gatewayToken,
      });
      appendTurn({
        role: response.data.status === "success" ? "assistant" : "system",
        text: response.data.response || "No response body returned.",
        meta: [response.data.model, response.data.message_count ? `${response.data.message_count} messages` : ""]
          .filter(Boolean)
          .join(" · "),
      });
      setTimeout(() => void loadSessions(), 900);
    } catch (error: any) {
      appendTurn({
        role: "system",
        text: error.response?.data?.detail || error.message || "Chat request failed.",
      });
    } finally {
      setSending(false);
    }
  }

  function startNewSession() {
    setSessionId(newSessionId());
    setPrompt("");
  }

  const allSessions = [
    ...activeSessions.map((session) => ({ ...session, listStatus: "active" })),
    ...terminatedSessions.map((session) => ({ ...session, listStatus: "terminated" })),
  ];

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm font-medium text-slate-500">Security console</p>
        <h1 className="mt-1 text-3xl font-semibold text-slate-950">Test Console</h1>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Send test prompts through the gateway and inspect recorded prompt telemetry for active or terminated sessions.
        </p>
      </div>

      <SourcePicker onSourceChange={setSource} />

      <div className="grid min-h-[650px] gap-5 xl:grid-cols-[340px_1fr]">
        <aside className="space-y-4">
          <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-950">Sessions</h2>
                <p className="mt-1 text-xs text-slate-500">
                  {activeSessions.length} active · {terminatedSessions.length} terminated
                </p>
              </div>
              <button onClick={loadSessions} className="rounded-md border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-600">
                Refresh
              </button>
            </div>
            <button onClick={startNewSession} className="mt-4 w-full rounded-md bg-slate-950 px-3 py-2 text-sm font-semibold text-white">
              New Session
            </button>
            <div className="mt-4 max-h-80 space-y-2 overflow-y-auto">
              {loadingSessions ? (
                <p className="text-sm text-slate-500">Loading sessions...</p>
              ) : allSessions.length === 0 ? (
                <p className="text-sm text-slate-500">No recorded sessions yet. Start a chat to create one.</p>
              ) : (
                allSessions.map((session) => (
                  <button
                    key={`${session.listStatus}-${session.session_id}`}
                    onClick={() => setSessionId(session.session_id)}
                    className={`w-full rounded-md border px-3 py-2 text-left text-sm ${
                      session.session_id === sessionId
                        ? "border-slate-950 bg-slate-950 text-white"
                        : "border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300"
                    }`}
                  >
                    <div className="font-mono text-xs">{shortId(session.session_id)}</div>
                    <div className="mt-1 text-xs opacity-75">
                      {session.listStatus} · risk {session.last_risk_score || 0}
                    </div>
                  </button>
                ))
              )}
            </div>
          </section>

          <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
            <label className="block">
              <span className="text-xs font-semibold text-slate-500">Session ID</span>
              <input
                value={sessionId}
                onChange={(event) => setSessionId(event.target.value)}
                className="mt-1 w-full rounded-md border border-slate-200 px-3 py-2 font-mono text-xs text-slate-700"
              />
            </label>
            <label className="mt-3 block">
              <span className="text-xs font-semibold text-slate-500">Gateway URL</span>
              <textarea
                value={gatewayUrl}
                onChange={(event) => setGatewayUrl(event.target.value)}
                rows={4}
                placeholder="https://your-gateway.example.com/mcp"
                className="mt-1 w-full rounded-md border border-slate-200 px-3 py-2 font-mono text-xs text-slate-700"
              />
              <span className="mt-1 block text-[11px] text-slate-400">
                The gateway's <strong>MCP endpoint</strong>, which ends in <code>/mcp</code>. The AWS
                console shows the gateway URL without that path — paste it as-is and the path is added.
              </span>
              {urlNeedsMcpPath && (
                <span className="mt-1 block text-[11px] font-semibold text-amber-700">
                  Will post to {effectiveGatewayUrl}
                </span>
              )}
            </label>
            <label className="mt-3 block">
              <span className="text-xs font-semibold text-slate-500">Tool name</span>
              <input
                value={toolName}
                onChange={(event) => setToolName(event.target.value)}
                placeholder="exact name from tools/list"
                className="mt-1 w-full rounded-md border border-slate-200 px-3 py-2 font-mono text-xs text-slate-700"
              />
              <span className="mt-1 block text-[11px] text-slate-400">
                A <strong>tool on</strong> the gateway, not the gateway itself. Use the exact string the
                gateway advertises — an MCP <code>tools/list</code> call returns them verbatim. An empty
                list means the gateway exposes no tools yet, so nothing can be called through it.
              </span>
              {toolNameLooksLikeGatewayId && (
                <span className="mt-1 block text-[11px] font-semibold text-amber-700">
                  This matches the gateway's own hostname, so it is the gateway id rather than a tool
                  name — the gateway will return "Unknown tool".
                </span>
              )}
            </label>
            <label className="mt-3 block">
              <span className="text-xs font-semibold text-slate-500">Gateway bearer token</span>
              <input
                type="password"
                value={gatewayToken}
                onChange={(event) => setGatewayToken(event.target.value)}
                placeholder="OAuth access token (if the gateway requires one)"
                className="mt-1 w-full rounded-md border border-slate-200 px-3 py-2 font-mono text-xs text-slate-700"
              />
              <span className="mt-1 block text-[11px] text-slate-400">
                Sent as Authorization: Bearer to the gateway. Required if the gateway enforces inbound OAuth.
              </span>
            </label>
          </section>
        </aside>

        <section className="flex min-w-0 flex-col rounded-lg border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 px-5 py-4">
            <p className="font-mono text-sm font-semibold text-slate-950">{shortId(sessionId)}</p>
            <p className="mt-1 text-xs text-slate-500">
              Chatbot responses are only visible for this browser session. Prompt telemetry below is loaded from prompt history.
            </p>
          </div>

          <div className="grid flex-1 gap-0 lg:grid-cols-[1fr_360px]">
            <div className="flex min-h-[520px] flex-col">
              <div className="flex-1 space-y-3 overflow-y-auto bg-slate-50/70 p-5">
                {turns.length === 0 ? (
                  <div className="flex h-full items-center justify-center text-sm text-slate-400">
                    Send a prompt or select a session with local chat turns.
                  </div>
                ) : (
                  turns.map((turn, index) => (
                    <div
                      key={index}
                      className={`max-w-[78%] rounded-lg border px-4 py-3 text-sm ${
                        turn.role === "user"
                          ? "ml-auto border-slate-900 bg-slate-950 text-white"
                          : turn.role === "assistant"
                            ? "border-slate-200 bg-white text-slate-800"
                            : "border-red-200 bg-red-50 text-red-700"
                      }`}
                    >
                      <div>{turn.text}</div>
                      {turn.meta && <div className="mt-2 text-xs opacity-60">{turn.meta}</div>}
                    </div>
                  ))
                )}
              </div>
              <form onSubmit={send} className="flex gap-3 border-t border-slate-200 p-4">
                <input
                  value={prompt}
                  onChange={(event) => setPrompt(event.target.value)}
                  placeholder="Ask the target chatbot..."
                  className="min-w-0 flex-1 rounded-md border border-slate-200 px-4 py-3 text-sm outline-none focus:border-slate-400"
                />
                <button
                  disabled={sending || !prompt.trim()}
                  className="rounded-md bg-slate-950 px-5 py-3 text-sm font-semibold text-white disabled:opacity-40"
                >
                  {sending ? "Sending" : "Send"}
                </button>
              </form>
            </div>

            <div className="border-l border-slate-200 bg-white p-4">
              <h3 className="text-sm font-semibold text-slate-950">Recorded prompts</h3>
              <p className="mt-1 text-xs text-slate-500">From prompt history for the selected session.</p>
              <div className="mt-4 max-h-[570px] space-y-3 overflow-y-auto">
                {selectedSessionPrompts.length === 0 ? (
                  <p className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-500">
                    No prompt telemetry found for this session yet.
                  </p>
                ) : (
                  selectedSessionPrompts.map((record) => (
                    <div key={`${record.prompt_id}-${record.timestamp}`} className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-xs text-slate-500">{record.timestamp}</span>
                        <span className="rounded-full bg-slate-200 px-2 py-0.5 text-xs font-semibold text-slate-700">
                          {record.tier2_ml_verdict || record.decision || "recorded"}
                        </span>
                      </div>
                      <p className="mt-2 text-slate-800">{record.prompt || "Prompt text unavailable for this storage mode."}</p>
                      <p className="mt-2 text-xs text-slate-500">
                        Tier 2 score {record.tier2_prompt_score || record.tier2_risk_score || 0} · session {record.tier2_session_score_after || 0}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
