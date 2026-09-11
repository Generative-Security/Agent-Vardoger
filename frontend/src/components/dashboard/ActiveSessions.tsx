import type { SessionSummary } from "../../api/client";

interface Props {
  data: SessionSummary | null;
}

// ActiveSessions: Renders the active sessions UI section.
export default function ActiveSessions({ data }: Props) {
  // recentlyEvaluated: Helper for recently evaluated.
  const recentlyEvaluated = (data?.active_sessions || []).filter((session) => session.last_decision).length;

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
      <div className="text-sm font-medium text-slate-500">Active Sessions</div>
      <div className="mt-2 text-3xl font-semibold text-blue-600">{data?.active_count ?? "—"}</div>
      <div className="mt-3 text-xs leading-5 text-slate-500">
        {recentlyEvaluated} session{recentlyEvaluated === 1 ? "" : "s"} evaluated and still open
      </div>
    </div>
  );
}
