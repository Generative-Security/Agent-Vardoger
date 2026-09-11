import type { DetectionEvent } from "../../api/client";
import DashboardPanel from "./DashboardPanel";
import {
  customerImpact,
  detectionSource,
  formatClock,
  primarySignal,
  primarySignalExplanation,
  recommendedAction,
  riskSeverity,
  ruleReference,
  shortSessionId,
} from "./dashboardFormat";

interface Props {
  data: DetectionEvent[] | null;
}

// decisionClass: Helper for decision class.
function decisionClass(decision: string) {
  return decision === "block"
    ? "border-red-200 bg-red-50 text-red-700"
    : "border-emerald-200 bg-emerald-50 text-emerald-700";
}

// RecentDetectionsTable: Renders the recent detections table UI section.
export default function RecentDetectionsTable({ data }: Props) {
  const rows = data || [];

  return (
    <DashboardPanel
      title="Recent Detection Decisions"
      description="Latest prompt evaluations across the selected source, with plain-language reason labels."
    >
      {rows.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-sm text-slate-400">
          No detection activity yet
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500">
                <th className="pb-2 pr-4 font-medium">Time</th>
                <th className="pb-2 pr-4 font-medium">Session</th>
                <th className="pb-2 pr-4 font-medium">Decision</th>
                <th className="pb-2 pr-4 font-medium">Severity</th>
                <th className="pb-2 pr-4 font-medium">Detection Family</th>
                <th className="pb-2 pr-4 font-medium">Source</th>
                <th className="pb-2 pr-4 font-medium">Rule</th>
                <th className="pb-2 font-medium">Action Guidance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.slice(0, 10).map((row) => {
                const severity = riskSeverity(row.risk_score);
                return (
                <tr key={`${row.session_id}-${row.timestamp}`} className="align-top">
                  <td className="py-3 pr-4 text-xs text-slate-500">{formatClock(row.timestamp)}</td>
                  <td className="py-3 pr-4">
                    <div className="font-mono text-xs text-slate-700">{shortSessionId(row.session_id)}</div>
                  </td>
                  <td className="py-3 pr-4">
                    <span className={`rounded-full border px-2 py-1 text-xs font-medium ${decisionClass(row.decision)}`}>
                      {row.decision === "block" ? "Blocked" : "Allowed"}
                    </span>
                  </td>
                  <td className="py-3 pr-4">
                    <span className={`rounded-full border px-2 py-1 text-xs font-medium ${severity.className}`}>
                      {severity.label} · {row.risk_score}
                    </span>
                  </td>
                  <td className="min-w-[220px] py-3 pr-4">
                    <div className="text-xs font-medium text-slate-800">{primarySignal(row)}</div>
                    <div className="mt-1 text-xs leading-5 text-slate-500">{primarySignalExplanation(row)}</div>
                  </td>
                  <td className="min-w-[150px] py-3 pr-4 text-xs text-slate-600">{detectionSource(row)}</td>
                  <td className="max-w-[220px] py-3 pr-4 font-mono text-[11px] leading-5 text-slate-500">
                    {ruleReference(row)}
                  </td>
                  <td className="min-w-[300px] py-3 text-xs leading-5 text-slate-600">
                    <div>{customerImpact(row)}</div>
                    <div className="mt-1 font-medium text-slate-700">{recommendedAction(row)}</div>
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
