import { FormEvent, useEffect, useMemo, useState } from "react";
import { promptHistoryApi, type PromptHistoryFilters, type PromptHistoryRecord } from "../api/client";
import { getSelectedSource } from "../sourceSelection";
import SourcePicker from "../components/shared/SourcePicker";
import { categoryLabel, describeSignature, formatDateTime, riskSeverity } from "../components/dashboard/dashboardFormat";

const TIME_WINDOWS = [
  { label: "Last 1 hour", value: 1 },
  { label: "Last 6 hours", value: 6 },
  { label: "Last 1 day", value: 24 },
  { label: "Last 7 days", value: 168 },
  { label: "Last 1 month", value: 720 },
  { label: "Last 1 year", value: 8760 },
];

// maskPrompt: Helper for mask prompt.
function maskPrompt(prompt: string) {
  if (!prompt) return "Prompt text unavailable for this storage mode.";
  return prompt.length > 420 ? `${prompt.slice(0, 420)}...` : prompt;
}

// shortArn: Helper for short arn.
function shortArn(arn: string) {
  if (!arn) return "-";
  const tail = arn.split("/").pop() || arn;
  return tail.length > 34 ? `${tail.slice(0, 34)}...` : tail;
}

// signalFor: Helper for signal for.
function signalFor(record: PromptHistoryRecord) {
  const first = record.matched_signatures?.[0] || record.attack_intents?.[0] || record.decision || "unknown";
  return categoryLabel(first);
}

// tier2Tone: Keeps watch/suspicious/high-risk states amber or orange unless a kill actually happened.
function tier2Tone(record: PromptHistoryRecord) {
  const verdict = record.tier2_ml_verdict || record.tier2_status;
  if (record.tier2_action_taken === "kill" || verdict === "malicious") return "font-semibold text-red-700";
  if (verdict === "high_risk") return "font-semibold text-orange-700";
  if (verdict === "suspicious") return "font-semibold text-amber-700";
  if (verdict === "watch") return "font-semibold text-blue-700";
  return "font-medium text-emerald-700";
}

// riskPercent: Formats stored Tier 2 0-100 risk values.
function riskPercent(value: number) {
  if (!value) return "0%";
  return `${Math.round(value)}%`;
}

// PromptHistoryPage: Renders the prompt history page UI section.
export default function PromptHistoryPage() {
  const [source, setSource] = useState(getSelectedSource());
  const [filters, setFilters] = useState<PromptHistoryFilters>({
    hours: 24,
    limit: 100,
    min_risk: 0,
  });
  const [records, setRecords] = useState<PromptHistoryRecord[]>([]);
  const [warning, setWarning] = useState("");
  const [scannedCount, setScannedCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<PromptHistoryRecord | null>(null);

  const blockedCount = useMemo(() => records.filter((r) => r.decision === "block").length, [records]);
  const highestRisk = useMemo(() => records.reduce((max, r) => Math.max(max, r.risk_score || 0), 0), [records]);
  const sessions = useMemo(() => new Set(records.map((r) => r.session_id).filter(Boolean)).size, [records]);
  const tier2Reviewed = useMemo(() => records.filter((r) => r.tier2_status).length, [records]);

  async function runSearch(nextFilters = filters, nextSource = source) {
    setLoading(true);
    setError("");
    setWarning("");
    try {
      const response = await promptHistoryApi.search({ ...nextFilters, source: nextSource });
      setRecords(response.data.records);
      setScannedCount(response.data.scanned_count);
      setWarning(response.data.warning || "");
      setSelected(response.data.records[0] || null);
    } catch {
      setError("Prompt history search failed. Check the prompt-history table and API permissions.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void runSearch(filters, source);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source]);

  // submit: Helper for submit.
  function submit(event: FormEvent) {
    event.preventDefault();
    void runSearch();
  }

  // update: Helper for update.
  function update<K extends keyof PromptHistoryFilters>(key: K, value: PromptHistoryFilters[K]) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Security analyst workspace</p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight text-slate-950">Prompt History</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Search prompt records by source, session, decision, risk, and prompt text.
          </p>
        </div>
        <button
          type="button"
          onClick={() => runSearch()}
          className="rounded-md bg-slate-950 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
        >
          Refresh
        </button>
      </div>

      <SourcePicker onSourceChange={setSource} />

      <form onSubmit={submit} className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <div className="grid gap-3 md:grid-cols-4">
          <label className="space-y-1 text-sm font-medium text-slate-600">
            Session
            <input
              value={filters.session_id || ""}
              onChange={(e) => update("session_id", e.target.value)}
              placeholder="session id"
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-950 outline-none focus:border-slate-500"
            />
          </label>
          <label className="space-y-1 text-sm font-medium text-slate-600">
            Prompt text
            <input
              value={filters.keyword || ""}
              onChange={(e) => update("keyword", e.target.value)}
              placeholder="password, ignore, secret..."
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-950 outline-none focus:border-slate-500"
            />
          </label>
          <label className="space-y-1 text-sm font-medium text-slate-600">
            Decision
            <select
              value={filters.decision || ""}
              onChange={(e) => update("decision", e.target.value)}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-950 outline-none focus:border-slate-500"
            >
              <option value="">All decisions</option>
              <option value="allow">Allowed</option>
              <option value="block">Blocked</option>
            </select>
          </label>
          <label className="space-y-1 text-sm font-medium text-slate-600">
            Minimum risk
            <input
              type="number"
              min={0}
              value={filters.min_risk || 0}
              onChange={(e) => update("min_risk", Number(e.target.value))}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-950 outline-none focus:border-slate-500"
            />
          </label>
          <label className="space-y-1 text-sm font-medium text-slate-600">
            Time window
            <select
              value={filters.hours || 24}
              onChange={(e) => update("hours", Number(e.target.value))}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-950 outline-none focus:border-slate-500"
            >
              {TIME_WINDOWS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <label className="space-y-1 text-sm font-medium text-slate-600">
            Result limit
            <input
              type="number"
              min={1}
              max={500}
              value={filters.limit || 100}
              onChange={(e) => update("limit", Number(e.target.value))}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-950 outline-none focus:border-slate-500"
            />
          </label>
        </div>
        <div className="mt-4 flex items-center justify-between">
          <p className="text-xs text-slate-500">
            Searches are scoped to the current scope. The source picker narrows results to one "&lt;account&gt;/&lt;agent&gt;".
          </p>
          <button
            type="submit"
            disabled={loading}
            className="rounded-md bg-slate-950 px-5 py-2 text-sm font-semibold text-white disabled:bg-slate-300"
          >
            {loading ? "Searching..." : "Search"}
          </button>
        </div>
      </form>

      {warning && <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">{warning}</div>}
      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}

      <div className="grid gap-4 md:grid-cols-5">
        <Metric label="Records" value={records.length.toLocaleString()} detail={`${scannedCount.toLocaleString()} scanned`} />
        <Metric label="Blocked" value={blockedCount.toLocaleString()} detail="Matched block decisions" tone="red" />
        <Metric label="Sessions" value={sessions.toLocaleString()} detail="Unique sessions in results" />
        <Metric label="Highest Risk" value={highestRisk.toLocaleString()} detail={riskSeverity(highestRisk).label} tone="amber" />
        <Metric label="Tier 2 Reviewed" value={tier2Reviewed.toLocaleString()} detail="Async ML decisions" />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.75fr)]">
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 px-4 py-3">
            <h2 className="text-base font-semibold text-slate-950">Search Results</h2>
            <p className="text-sm text-slate-500">Prompt records with analyst-ready risk context.</p>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Session</th>
                  <th className="px-4 py-3">Decision</th>
                  <th className="px-4 py-3">Signal</th>
                  <th className="px-4 py-3">Tier 2</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Prompt</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {records.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                      {loading ? "Searching prompt history..." : "No prompt records matched the current filters."}
                    </td>
                  </tr>
                ) : records.map((record) => (
                  <tr
                    key={`${record.source}-${record.session_id}-${record.timestamp}`}
                    onClick={() => setSelected(record)}
                    className={`cursor-pointer hover:bg-slate-50 ${selected === record ? "bg-slate-50" : ""}`}
                  >
                    <td className="whitespace-nowrap px-4 py-3 text-slate-500">{formatDateTime(record.timestamp)}</td>
                    <td className="px-4 py-3">
                      <p className="font-mono text-slate-700">{record.session_id}</p>
                      {record.prompt_id && <p className="mt-1 font-mono text-xs text-slate-400">{record.prompt_id}</p>}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full px-2 py-1 text-xs font-semibold ${
                        record.decision === "block" ? "bg-red-50 text-red-700 ring-1 ring-red-200" : "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200"
                      }`}>
                        {record.decision || "unknown"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-700">
                      <p>{signalFor(record)}</p>
                      {record.matched_signatures?.length > 0 && (
                        <p className="mt-1 font-mono text-xs text-slate-400">{record.matched_signatures.slice(0, 2).join(", ")}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-600">
                      {record.tier2_status ? (
                        <span className={tier2Tone(record)}>
                          {record.tier2_ml_verdict || record.tier2_status} · {record.tier2_category || "uncategorized"}
                        </span>
                      ) : (
                        <span className="text-slate-400">pending</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-700">
                      <p className="font-semibold text-slate-950">{record.risk_score}</p>
                      <p className="mt-1 text-xs text-slate-500">
                        T2 {riskPercent(record.tier2_prompt_score || record.tier2_risk_score)} / session{" "}
                        {riskPercent(record.tier2_session_score_after)}
                      </p>
                    </td>
                    <td className="max-w-md px-4 py-3 text-slate-600">{maskPrompt(record.prompt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <aside className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <h2 className="text-base font-semibold text-slate-950">Record Detail</h2>
          {!selected ? (
            <p className="mt-8 text-sm text-slate-500">Select a prompt record to inspect session and detection details.</p>
          ) : (
            <div className="mt-4 space-y-4">
              <Detail label="Source" value={selected.source || "all sources"} mono />
              <Detail label="Scope" value={selected.scope_id || "-"} mono />
              <Detail label="Session" value={selected.session_id || "-"} mono />
              <Detail label="Prompt ID" value={selected.prompt_id || "-"} mono />
              <Detail label="Runtime" value={shortArn(selected.agent_runtime_arn)} mono />
              <Detail label="Decision" value={selected.decision || "-"} />
              <Detail label="Risk" value={`${selected.risk_score} (${riskSeverity(selected.risk_score).label})`} />
              {selected.tier2_status && (
                <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
                  <p className="mb-2 text-xs font-semibold uppercase text-slate-400">Tier 2 ML</p>
                  <div className="grid gap-2 text-sm text-slate-700">
                    <Detail label="Status" value={selected.tier2_status} />
                    <Detail label="ML Verdict" value={selected.tier2_ml_verdict || selected.tier2_status || "-"} />
                    <Detail label="Action Taken" value={selected.tier2_action_taken || "-"} />
                    <Detail label="Category" value={selected.tier2_category || "-"} />
                    <Detail label="Label" value={`${selected.tier2_label || "-"} (${Math.round((selected.tier2_confidence || 0) * 100)}%)`} />
                    <Detail label="Prompt Risk" value={riskPercent(selected.tier2_risk_score)} />
                    <Detail label="Prompt Score" value={riskPercent(selected.tier2_prompt_score || selected.tier2_risk_score)} />
                    <Detail label="Session Risk After" value={riskPercent(selected.tier2_session_score_after)} />
                    <Detail label="Threshold" value={selected.tier2_threshold_used || "none"} />
                    <Detail label="Safe Intent" value={selected.tier2_safe_intent_reason || "-"} />
                    <Detail label="Kill Triggered" value={selected.tier2_kill_triggered ? "Yes" : "No"} />
                    {selected.tier2_error && <Detail label="Error" value={selected.tier2_error} />}
                  </div>
                </div>
              )}
              <Detail label="Prompt Length" value={`${selected.prompt_length || selected.prompt.length} characters`} />
              <div>
                <p className="mb-1 text-xs font-semibold uppercase text-slate-400">Matched Signatures</p>
                <div className="space-y-2">
                  {selected.matched_signatures.length === 0 ? (
                    <p className="text-sm text-slate-500">No signatures recorded.</p>
                  ) : selected.matched_signatures.map((sig) => (
                    <div key={sig} className="rounded-md bg-slate-50 p-2">
                      <p className="font-mono text-sm text-slate-800">{sig}</p>
                      <p className="mt-1 text-xs text-slate-500">{describeSignature(sig)}</p>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <p className="mb-1 text-xs font-semibold uppercase text-slate-400">Prompt Text</p>
                <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 text-sm leading-6 text-slate-800">
                  {selected.prompt || "No prompt text stored"}
                </pre>
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

// Metric: Renders the metric UI section.
function Metric({ label, value, detail, tone = "blue" }: { label: string; value: string; detail: string; tone?: "blue" | "red" | "amber" }) {
  const color = tone === "red" ? "text-red-600" : tone === "amber" ? "text-amber-600" : "text-blue-600";
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-semibold ${color}`}>{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </div>
  );
}

// Detail: Renders the detail UI section.
function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="mb-1 text-xs font-semibold uppercase text-slate-400">{label}</p>
      <p className={`${mono ? "font-mono" : ""} break-words text-sm text-slate-800`}>{value}</p>
    </div>
  );
}
