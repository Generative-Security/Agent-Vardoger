import { useEffect, useMemo, useState } from "react";
import { dashboardApi, promptHistoryApi, type DetectionEvent, type PromptHistoryRecord, type Tier3Finding } from "../api/client";
import { getSelectedSource } from "../sourceSelection";
import SourcePicker from "../components/shared/SourcePicker";

type WindowKey = "24" | "168" | "720";

const WINDOWS: { label: string; value: WindowKey }[] = [
  { label: "24h", value: "24" },
  { label: "7d", value: "168" },
  { label: "30d", value: "720" },
];

function severityFor(record: PromptHistoryRecord | DetectionEvent | Tier3Finding) {
  const text = JSON.stringify(record).toLowerCase();
  if (text.includes("kill") || text.includes("malicious") || text.includes("block")) return "critical";
  if (text.includes("high_risk") || text.includes("high risk")) return "high";
  if (text.includes("suspicious") || text.includes("watch")) return "medium";
  return "low";
}

function categoryFor(record: PromptHistoryRecord | DetectionEvent | Tier3Finding) {
  if ("tier2_category" in record && record.tier2_category) return record.tier2_category;
  if ("category" in record && record.category) return record.category;
  if ("attack_intents" in record && record.attack_intents?.[0]) return record.attack_intents[0];
  return "uncategorized";
}

function badgeClass(severity: string) {
  if (severity === "critical") return "bg-red-50 text-red-700 ring-red-200";
  if (severity === "high") return "bg-orange-50 text-orange-700 ring-orange-200";
  if (severity === "medium") return "bg-amber-50 text-amber-700 ring-amber-200";
  return "bg-emerald-50 text-emerald-700 ring-emerald-200";
}

// DetectionsPage: Reviews Layer 1 blocks, Tier 2 verdicts, and Tier 3 grouped findings across the selected source.
export default function DetectionsPage() {
  const [source, setSource] = useState(getSelectedSource());
  const [windowHours, setWindowHours] = useState<WindowKey>("168");
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [layer1, setLayer1] = useState<PromptHistoryRecord[]>([]);
  const [tier2, setTier2] = useState<PromptHistoryRecord[]>([]);
  const [events, setEvents] = useState<DetectionEvent[]>([]);
  const [tier3, setTier3] = useState<Tier3Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const hours = Number(windowHours);
      const [historyResponse, eventsResponse, tier3Response] = await Promise.allSettled([
        promptHistoryApi.search({ hours, limit: 500, source }),
        dashboardApi.detections(hours, source),
        dashboardApi.tier3Findings(hours, source),
      ]);
      const failures: string[] = [];
      const items = historyResponse.status === "fulfilled" ? historyResponse.value.data.records || [] : [];
      if (historyResponse.status === "rejected") failures.push("prompt history");
      if (eventsResponse.status === "rejected") failures.push("Layer 1 event feed");
      if (tier3Response.status === "rejected") failures.push("Tier 3 findings");
      setLayer1(items.filter((item) => item.decision === "block" || item.matched_signatures?.length));
      setTier2(items.filter((item) => item.tier2_status || item.tier2_ml_verdict || item.tier2_action_taken));
      setEvents(eventsResponse.status === "fulfilled" ? eventsResponse.value.data || [] : []);
      setTier3(tier3Response.status === "fulfilled" ? tier3Response.value.data || [] : []);
      if (failures.length) setError(`Loaded partial detections. Could not load: ${failures.join(", ")}.`);
    } catch {
      setError("Could not load detections.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [windowHours, source]);

  const allRows = useMemo(() => {
    const rows = [
      ...layer1.map((item) => ({ layer: "Layer 1", id: item.prompt_id || item.timestamp, session: item.session_id, category: categoryFor(item), severity: severityFor(item), summary: item.prompt || "Blocked prompt evidence", timestamp: item.timestamp })),
      ...tier2.map((item) => ({ layer: "Tier 2", id: `${item.prompt_id}-tier2`, session: item.session_id, category: categoryFor(item), severity: severityFor(item), summary: item.prompt || "Tier 2 verdict", timestamp: item.timestamp })),
      ...tier3.map((item) => ({ layer: "Tier 3", id: item.event_id, session: item.affected_sessions?.join(", ") || item.burst_id, category: categoryFor(item), severity: item.kill_triggered ? "critical" : "medium", summary: `${item.attack_style || "Grouped finding"} · ${item.affected_session_count} sessions · ${item.action_taken}`, timestamp: item.timestamp })),
      ...events.map((item) => ({ layer: "Detection Event", id: `${item.session_id}-${item.timestamp}`, session: item.session_id, category: categoryFor(item), severity: severityFor(item), summary: item.attack_intents?.join(", ") || item.decision, timestamp: item.timestamp })),
    ];
    return rows.filter((row) => (severity === "all" || row.severity === severity) && (category === "all" || row.category === category));
  }, [layer1, tier2, tier3, events, severity, category]);

  const categories = useMemo(() => [...new Set([...layer1, ...tier2, ...tier3, ...events].map(categoryFor))].sort(), [layer1, tier2, tier3, events]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Security console</p>
          <h1 className="mt-1 text-3xl font-semibold text-slate-950">Detections</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-600">
            Review Layer 1 blocks, Tier 2 verdicts, and Tier 3 grouped findings across the selected source.
          </p>
        </div>
        <button onClick={load} className="rounded-md bg-slate-950 px-4 py-2 text-sm font-semibold text-white">Refresh</button>
      </div>

      <SourcePicker onSourceChange={setSource} />

      <div className="grid gap-3 rounded-lg border border-slate-200 bg-white p-4 shadow-sm md:grid-cols-4">
        <Select label="Window" value={windowHours} onChange={(v) => setWindowHours(v as WindowKey)} options={WINDOWS} />
        <Select label="Severity" value={severity} onChange={setSeverity} options={[
          { label: "All severities", value: "all" },
          { label: "Critical", value: "critical" },
          { label: "High", value: "high" },
          { label: "Medium", value: "medium" },
          { label: "Low", value: "low" },
        ]} />
        <Select label="Category" value={category} onChange={setCategory} options={[
          { label: "All categories", value: "all" },
          ...categories.map((item) => ({ label: item, value: item })),
        ]} />
        <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Visible rows</p>
          <p className="mt-1 text-2xl font-semibold text-slate-950">{allRows.length}</p>
        </div>
      </div>

      {error && <div className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>}
      {loading ? (
        <div className="rounded-lg border border-slate-200 bg-white p-8 text-sm text-slate-500 shadow-sm">Loading detections...</div>
      ) : (
        <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
          {/* Scrolls rather than pushing the card's own border off-screen. The
              Summary column carries the raw prompt, which has no length bound. */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Layer</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Session</th>
                  <th className="px-4 py-3">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {allRows.length === 0 ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-slate-500">No detections found for this filter.</td></tr>
                ) : allRows.map((row) => (
                  <tr key={row.id} className="align-top">
                    <td className="px-4 py-3 text-slate-500">{row.timestamp}</td>
                    <td className="px-4 py-3 font-semibold text-slate-800">{row.layer}</td>
                    <td className="px-4 py-3"><span className={`rounded-full px-2 py-1 text-xs font-semibold ring-1 ${badgeClass(row.severity)}`}>{row.severity}</span></td>
                    <td className="px-4 py-3 text-slate-700">{row.category}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-500">
                      <div className="max-w-[14rem] truncate" title={row.session}>{row.session}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-700">
                      <div className="max-w-md whitespace-pre-wrap break-words" title={row.summary}>{row.summary}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: { label: string; value: string }[] }) {
  return (
    <label className="block">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} className="mt-1 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-950">
        {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
    </label>
  );
}
