import type { PromptHistoryRecord } from "../../api/client";
import DashboardPanel from "./DashboardPanel";
import {
  categoryExplanation,
  categoryLabel,
  formatDateTime,
  shortSessionId,
} from "./dashboardFormat";

interface Props {
  data: PromptHistoryRecord[] | null;
}

// promptPreview: Keeps raw prompt evidence useful without overwhelming the dashboard.
function promptPreview(prompt: string) {
  if (!prompt) return "No prompt text stored";
  return prompt.length > 180 ? `${prompt.slice(0, 180)}...` : prompt;
}

// evidenceSignal: Finds the clearest detection label from Tier 1 signatures or Tier 2 ML output.
function evidenceSignal(row: PromptHistoryRecord) {
  if (row.matched_policy_rules?.[0]) return row.matched_policy_rules[0];
  if (row.attack_intents?.[0]) return row.attack_intents[0];
  if (row.matched_signatures?.[0]) return row.matched_signatures[0];
  if (row.tier2_label) return `ml:${row.tier2_label}`;
  return "Policy rule";
}

// evidenceLayer: Shows whether the prompt was stopped inline or after async ML review.
function evidenceLayer(row: PromptHistoryRecord) {
  if (row.decision === "block") return "Tier 1 regex";
  if (row.tier2_action_taken === "kill") return "Tier 2 kill";
  if (row.tier2_ml_verdict === "high_risk") return "Tier 2 high risk";
  if (row.tier2_ml_verdict === "suspicious") return "Tier 2 suspicious";
  if (row.tier2_ml_verdict === "watch") return "Tier 2 watch";
  return "Monitoring";
}

// riskLabel: Shows stored Tier 2 session risk on the 0-100 scale.
function riskLabel(value: number) {
  if (!value) return "0%";
  return `${Math.round(value)}%`;
}

// BlockedPromptEvidence: Lists actual prompt text and attack type for blocked, terminated, or suspicious sessions.
export default function BlockedPromptEvidence({ data }: Props) {
  const rows = (data || [])
    .filter((row) => (
      row.decision === "block"
      || row.tier2_action_taken === "kill"
      || ["watch", "suspicious", "high_risk"].includes(row.tier2_ml_verdict)
      || row.tier2_status === "malicious"
      || row.tier2_status === "suspicious"
    ))
    .sort((a, b) => (b.ingested_at || 0) - (a.ingested_at || 0))
    .slice(0, 10);

  return (
    <DashboardPanel
      title="Blocked and Suspicious Prompt Evidence"
      description="Actual suspicious or malicious prompt text from prompt history, with detection layer and plain-language attack type."
    >
      {rows.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-sm text-slate-400">
          No blocked prompt evidence in this time window
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500">
                <th className="pb-2 pr-4 font-medium">Time</th>
                <th className="pb-2 pr-4 font-medium">Session</th>
                <th className="pb-2 pr-4 font-medium">Layer</th>
                <th className="pb-2 pr-4 font-medium">Attack Type</th>
                <th className="pb-2 pr-4 font-medium">Prompt</th>
                <th className="pb-2 font-medium">Outcome</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((row) => {
                const signal = evidenceSignal(row);
                const blockedByTier2 = row.tier2_action_taken === "kill";
                return (
                  <tr key={`${row.source}-${row.session_id}-${row.timestamp}`} className="align-top">
                    <td className="py-3 pr-4 text-xs text-slate-500">
                      {formatDateTime(row.ingested_at || row.timestamp)}
                    </td>
                    <td className="py-3 pr-4 font-mono text-xs text-slate-700">
                      {shortSessionId(row.session_id)}
                    </td>
                    <td className="py-3 pr-4 text-xs font-medium text-slate-700">{evidenceLayer(row)}</td>
                    <td className="min-w-[220px] py-3 pr-4">
                      <div className="text-xs font-semibold text-slate-800">{categoryLabel(signal)}</div>
                      <div className="mt-1 text-xs leading-5 text-slate-500">{categoryExplanation(signal)}</div>
                    </td>
                    <td className="min-w-[320px] py-3 pr-4 text-xs leading-5 text-slate-700">
                      {promptPreview(row.prompt)}
                    </td>
                    <td className="min-w-[180px] py-3 text-xs leading-5 text-slate-600">
                      {blockedByTier2
                        ? row.tier2_kill_triggered
                          ? "Tier 2 requested session termination."
                          : "Tier 2 flagged malicious; kill mode did not fire for this record."
                        : row.tier2_ml_verdict
                          ? `Tier 2 ${row.tier2_action_taken || "logged"} at session risk ${riskLabel(row.tier2_session_score_after)}.`
                        : "Tier 1 blocked before chatbot response."}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </DashboardPanel>
  );
}
