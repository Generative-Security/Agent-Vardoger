import type { Tier3Finding } from "../../api/client";
import DashboardPanel from "./DashboardPanel";
import { categoryLabel, formatDateTime, shortSessionId } from "./dashboardFormat";

interface Props {
  data: Tier3Finding[] | null;
}

function titleize(value: string) {
  if (!value) return "-";
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function confidence(value: number) {
  if (!value) return "-";
  return `${Math.round(value * 100)}%`;
}

function badge(finding: Tier3Finding) {
  if (finding.kill_triggered) return "border-red-200 bg-red-50 text-red-700";
  return "border-amber-200 bg-amber-50 text-amber-700";
}

function promptEvidence(finding: Tier3Finding) {
  const ids = finding.example_prompt_ids.slice(0, 3).join(", ");
  if (ids) return `Prompt IDs: ${ids}`;
  return "Prompt evidence linked in prompt history";
}

// Tier3FindingsPanel: Shows cross-session grouped findings without raw prompt text.
export default function Tier3FindingsPanel({ data }: Props) {
  const rows = (data || []).slice(0, 12);

  return (
    <DashboardPanel
      title="Tier 3 Cross-Session Review"
      description="Scheduled analysis of repeated, near-duplicate, and burst attack patterns across sessions and sources."
    >
      {rows.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-sm text-slate-400">
          No Tier 3 grouped findings in this time window
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500">
                <th className="pb-2 pr-4 font-medium">Detected</th>
                <th className="pb-2 pr-4 font-medium">Status</th>
                <th className="pb-2 pr-4 font-medium">Attack Style</th>
                <th className="pb-2 pr-4 font-medium">Sessions</th>
                <th className="pb-2 pr-4 font-medium">Sources</th>
                <th className="pb-2 pr-4 font-medium">Evidence</th>
                <th className="pb-2 pr-4 font-medium">Method</th>
                <th className="pb-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((finding) => (
                <tr key={finding.event_id || finding.burst_id} className="align-top">
                  <td className="py-3 pr-4 text-xs text-slate-500">{formatDateTime(finding.timestamp)}</td>
                  <td className="py-3 pr-4">
                    <span className={`rounded-full border px-2 py-1 text-xs font-medium ${badge(finding)}`}>
                      {finding.kill_triggered ? "Kill requested" : "Grouped alert"}
                    </span>
                  </td>
                  <td className="min-w-[220px] py-3 pr-4">
                    <div className="text-xs font-semibold text-slate-800">
                      {finding.category ? titleize(finding.category) : categoryLabel(finding.category)}
                    </div>
                    <div className="mt-1 text-xs leading-5 text-slate-500">
                      {finding.attack_style || "Cross-session burst"} · Confidence {confidence(finding.confidence)}
                    </div>
                  </td>
                  <td className="min-w-[200px] py-3 pr-4 text-xs leading-5 text-slate-700">
                    <div className="font-semibold">{finding.affected_session_count} affected</div>
                    <div className="mt-1 font-mono text-[11px] text-slate-500">
                      {finding.affected_sessions.slice(0, 4).map(shortSessionId).join(", ")}
                    </div>
                  </td>
                  <td className="min-w-[160px] py-3 pr-4 font-mono text-[11px] leading-5 text-slate-500">
                    {finding.affected_sources.length
                      ? finding.affected_sources.slice(0, 3).join(", ")
                      : finding.source || "all sources"}
                  </td>
                  <td className="min-w-[240px] py-3 pr-4 text-xs leading-5 text-slate-600">
                    {promptEvidence(finding)}
                  </td>
                  <td className="min-w-[180px] py-3 pr-4 text-xs leading-5 text-slate-600">
                    {titleize(finding.similarity_method)} · {finding.threshold_used || "threshold not recorded"}
                    <div className="mt-1 font-mono text-[11px] text-slate-400">{finding.model_version || "tier3-rules"}</div>
                  </td>
                  <td className="min-w-[220px] py-3 text-xs leading-5 text-slate-600">
                    {finding.kill_triggered
                      ? "Existing enforcement path was asked to terminate affected sessions."
                      : "Logged for analysts. No session was terminated by Tier 3."}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </DashboardPanel>
  );
}
