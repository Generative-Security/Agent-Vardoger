import type { SessionSummary } from "../../api/client";

interface Props {
  data: SessionSummary | null;
}

// TerminatedSessions: Renders the terminated sessions UI section.
export default function TerminatedSessions({ data }: Props) {
  const latestRisk = Math.max(...(data?.terminated_sessions || []).map((session) => session.last_risk_score || 0), 0);

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
      <div className="text-sm font-medium text-slate-500">Terminated (24h)</div>
      <div className="mt-2 text-3xl font-semibold text-red-600">
        {data?.terminated_count ?? "—"}
      </div>
      <div className="mt-3 text-xs leading-5 text-slate-500">
        Highest terminated risk score: {latestRisk}
      </div>
    </div>
  );
}
