import type { SessionSummary } from "../../api/client";
import DashboardPanel from "./DashboardPanel";
import { formatClock, riskSeverity, sessionSignal, shortSessionId } from "./dashboardFormat";

interface Props {
  data: SessionSummary | null;
}

// TerminatedSessionsPanel: Renders the terminated sessions panel UI section.
export default function TerminatedSessionsPanel({ data }: Props) {
  const rows = data?.terminated_sessions || [];

  return (
    <DashboardPanel
      title="Terminated Sessions"
      description="Sessions ended after a blocking decision in the selected time window."
    >
      {rows.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-sm text-slate-400">
          No terminated sessions
        </div>
      ) : (
        <div className="space-y-2">
          {rows.slice(0, 8).map((session) => (
            <div
              key={session.session_id}
              className="grid w-full grid-cols-[1fr_auto] gap-3 rounded-md border border-slate-200 bg-white px-4 py-3 text-left"
            >
              <div className="min-w-0">
                <div className="font-mono text-xs text-slate-800">{shortSessionId(session.session_id)}</div>
                <div className="mt-1 truncate text-xs font-medium text-slate-600">{sessionSignal(session)}</div>
                {session.source && (
                  <div className="mt-1 truncate font-mono text-[11px] text-slate-400">{session.source}</div>
                )}
              </div>
              <div className="text-right">
                <div className={`rounded-full border px-2 py-1 text-xs font-medium ${riskSeverity(session.last_risk_score).className}`}>
                  {riskSeverity(session.last_risk_score).label} · {session.last_risk_score || 0}
                </div>
                <div className="mt-1 text-xs text-slate-400">{formatClock(session.last_evaluated_at || session.created_at)}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </DashboardPanel>
  );
}
