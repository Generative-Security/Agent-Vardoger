import type { PromptHistoryRecord } from "../../api/client";
import DashboardPanel from "./DashboardPanel";
import { categoryExplanation, categoryLabel, formatDateTime, shortSessionId } from "./dashboardFormat";

interface Props {
  data: PromptHistoryRecord[] | null;
}

// statusClass: Chooses the badge color for a Tier 2 model decision.
function statusClass(status: string) {
  if (status === "malicious") return "border-red-200 bg-red-50 text-red-700";
  if (status === "high_risk") return "border-orange-200 bg-orange-50 text-orange-700";
  if (status === "suspicious") return "border-amber-200 bg-amber-50 text-amber-700";
  if (status === "watch") return "border-blue-200 bg-blue-50 text-blue-700";
  if (status === "safe") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (status === "error") return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-slate-200 bg-slate-50 text-slate-600";
}

// confidenceLabel: Converts model confidence into a clear analyst-facing percentage.
function confidenceLabel(value: number) {
  if (!value) return "-";
  return `${Math.round(value * 100)}%`;
}

// riskLabel: Shows Tier 2 risk scores that are stored on the 0-100 scale.
function riskLabel(value: number) {
  if (!value) return "-";
  return `${Math.round(value)}%`;
}

// decisionLabel: Keeps Tier 2 states readable for analysts.
function decisionLabel(status: string) {
  if (status === "malicious") return "Malicious";
  if (status === "high_risk") return "High risk";
  if (status === "suspicious") return "Suspicious";
  if (status === "watch") return "Watch";
  if (status === "safe") return "Safe";
  if (status === "error") return "Error";
  return "Pending";
}

// titleize: Converts stored category/action ids into readable dashboard labels.
function titleize(value: string) {
  if (!value) return "-";
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

// promptPreview: Shows enough prompt evidence to explain the decision in the dashboard.
function promptPreview(prompt: string) {
  if (!prompt) return "No prompt text stored";
  return prompt.length > 140 ? `${prompt.slice(0, 140)}...` : prompt;
}

// Tier2MlPanel: Shows asynchronous ML analysis that ran after regex allowed a prompt.
export default function Tier2MlPanel({ data }: Props) {
  const rows = (data || [])
    .filter((row) => row.tier2_status)
    .sort((a, b) => (b.ingested_at || 0) - (a.ingested_at || 0));

  return (
    <DashboardPanel
      title="Tier 2 ML Review"
      description="Async model review of prompts that passed regex, using recent session context for harder multi-turn attacks."
    >
      {rows.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-sm text-slate-400">
          No Tier 2 model decisions in this time window
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500">
                <th className="pb-2 pr-4 font-medium">Reviewed</th>
                <th className="pb-2 pr-4 font-medium">Session</th>
                <th className="pb-2 pr-4 font-medium">Decision</th>
                <th className="pb-2 pr-4 font-medium">Attack Type</th>
                <th className="pb-2 pr-4 font-medium">Prompt</th>
                <th className="pb-2 pr-4 font-medium">Model Signal</th>
                <th className="pb-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.slice(0, 12).map((row) => (
                <tr key={`${row.session_id}-${row.timestamp}-${row.prompt_id}`} className="align-top">
                  <td className="py-3 pr-4 text-xs text-slate-500">
                    {formatDateTime(row.ingested_at || row.timestamp)}
                  </td>
                  <td className="py-3 pr-4 font-mono text-xs text-slate-700">
                    {shortSessionId(row.session_id)}
                  </td>
                  <td className="py-3 pr-4">
                    <span className={`rounded-full border px-2 py-1 text-xs font-medium ${statusClass(row.tier2_ml_verdict || row.tier2_status)}`}>
                      {decisionLabel(row.tier2_ml_verdict || row.tier2_status)}
                    </span>
                  </td>
                  <td className="min-w-[220px] py-3 pr-4">
                    <div className="text-xs font-semibold text-slate-800">
                      {row.tier2_category ? titleize(row.tier2_category) : categoryLabel(`ml:${row.tier2_label}`)}
                    </div>
                    <div className="mt-1 text-xs leading-5 text-slate-500">
                      {categoryExplanation(`ml:${row.tier2_label}`)}
                    </div>
                  </td>
                  <td className="min-w-[300px] py-3 pr-4 text-xs leading-5 text-slate-700">
                    {promptPreview(row.prompt)}
                  </td>
                  <td className="min-w-[180px] py-3 pr-4">
                    <div className="text-xs font-medium text-slate-800">
                      {row.tier2_label || "No label"} · {confidenceLabel(row.tier2_confidence)}
                    </div>
                    <div className="mt-1 text-xs font-semibold text-slate-700">
                      Prompt risk {riskLabel(row.tier2_prompt_score || row.tier2_risk_score)} · Session risk{" "}
                      {riskLabel(row.tier2_session_score_after)}
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      Action: {titleize(row.tier2_action_taken || "allow")} · Threshold:{" "}
                      {row.tier2_threshold_used || "none"}
                    </div>
                  </td>
                  <td className="min-w-[260px] py-3 text-xs leading-5 text-slate-600">
                    {row.tier2_error
                      ? row.tier2_error
                      : row.tier2_kill_triggered
                        ? "Session termination was requested."
                        : row.tier2_action_taken === "raise_session_risk"
                          ? "Risk raised and logged. Session continues because no kill rule fired."
                          : row.tier2_safe_intent_reason
                            ? `Safe intent: ${row.tier2_safe_intent_reason}`
                            : "No ML escalation required."}
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
