import { useCallback, useMemo, useState } from "react";
import { usePolling } from "../hooks/usePolling";
import { dashboardApi, promptHistoryApi } from "../api/client";
import { getSelectedSource } from "../sourceSelection";
import ActiveSessions from "../components/dashboard/ActiveSessions";
import TerminatedSessions from "../components/dashboard/TerminatedSessions";
import DetectionTimeline from "../components/dashboard/DetectionTimeline";
import AbuseFamilyChart from "../components/dashboard/AbuseFamilyChart";
import SignatureHitsTable from "../components/dashboard/SignatureHitsTable";
import RecentDetectionsTable from "../components/dashboard/RecentDetectionsTable";
import TerminatedSessionsPanel from "../components/dashboard/TerminatedSessionsPanel";
import MetricCard from "../components/dashboard/MetricCard";
import Tier2MlPanel from "../components/dashboard/Tier2MlPanel";
import Tier3FindingsPanel from "../components/dashboard/Tier3FindingsPanel";
import BlockedPromptEvidence from "../components/dashboard/BlockedPromptEvidence";
import SourcePicker from "../components/shared/SourcePicker";
import LoadingSpinner from "../components/shared/LoadingSpinner";

const TIME_WINDOWS = [
  { label: "Last 1 hour", value: 1 },
  { label: "Last 6 hours", value: 6 },
  { label: "Last 1 day", value: 24 },
  { label: "Last 7 days", value: 168 },
  { label: "Last 1 month", value: 720 },
  { label: "Last 1 year", value: 8760 },
];

// DashboardPage: Renders the dashboard page UI section.
export default function DashboardPage() {
  const [source, setSource] = useState(getSelectedSource());
  const [hours, setHours] = useState(24);
  const [interval, setInterval] = useState("1h");
  const [live, setLive] = useState(true);
  const pollMs = live ? 10000 : null;

  // One request for every panel. This page previously ran six concurrent polls,
  // and each one triggered its own full scan of the same DetectionEvents table
  // server-side — so a single open dashboard cost five scans per interval.
  const summary = usePolling(
    useCallback(
      () => dashboardApi.summary(hours, interval, source).then((r) => r.data),
      [hours, interval, source],
    ),
    pollMs,
  );
  const promptHistory = usePolling(
    useCallback(() => promptHistoryApi.search({ hours, limit: 200, source }).then((r) => r.data.records), [hours, source]),
    pollMs,
  );

  const timeLabel = useMemo(() => {
    if (hours < 24) return `${hours}h`;
    return `${Math.round(hours / 24)}d`;
  }, [hours]);

  const refreshAll = useCallback(() => {
    void summary.refetch();
    void promptHistory.refetch();
  }, [summary, promptHistory]);

  if (summary.loading) return <LoadingSpinner />;

  // Panel data all comes from the single summary response.
  const sessionsData = summary.data?.sessions ?? null;
  const detectionRows = summary.data?.detections || [];
  const totalDetections = detectionRows.length;
  const blockedDetections = detectionRows.filter((d) => d.decision === "block").length;
  const blockRate = totalDetections > 0 ? Math.round((blockedDetections / totalDetections) * 100) : 0;
  const highestRisk = detectionRows.reduce((max, row) => Math.max(max, row.risk_score || 0), 0);
  const tier2Rows = (promptHistory.data || []).filter((row) => row.tier2_status);
  const tier2Kills = tier2Rows.filter((row) => row.tier2_action_taken === "kill" || row.tier2_kill_triggered).length;
  const tier2Raised = tier2Rows.filter((row) => ["watch", "suspicious", "high_risk"].includes(row.tier2_ml_verdict)).length;
  const tier3Rows = summary.data?.tier3_findings || [];
  const tier3Kills = tier3Rows.filter((row) => row.kill_triggered).length;

  return (
    <div>
      <div className="mb-6 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Security console</p>
          <h1 className="mt-1 text-2xl font-semibold text-slate-950">Dashboard</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-500">
            Prompt security activity shown as plain-language decisions, categories, and session outcomes across the selected source. Choose a source to filter, or leave it on "All sources" for the rollup.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-200 bg-white p-2 shadow-sm">
          <label className="text-xs font-medium text-slate-500">
            Time range
            <select
              value={hours}
              onChange={(event) => setHours(Number(event.target.value))}
              className="ml-2 rounded-md border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-800"
            >
              {TIME_WINDOWS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <label className="text-xs font-medium text-slate-500">
            Bucket
            <select
              value={interval}
              onChange={(event) => setInterval(event.target.value)}
              className="ml-2 rounded-md border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-800"
            >
              <option value="5m">5 min</option>
              <option value="15m">15 min</option>
              <option value="1h">1 hour</option>
              <option value="6h">6 hours</option>
            </select>
          </label>
          <button
            type="button"
            onClick={() => setLive((value) => !value)}
            className={`rounded-md px-3 py-1.5 text-sm font-medium ${
              live ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" : "bg-slate-100 text-slate-600"
            }`}
          >
            {live ? "Live on" : "Live off"}
          </button>
          <button
            type="button"
            onClick={refreshAll}
            className="rounded-md bg-slate-950 px-3 py-1.5 text-sm font-medium text-white"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="mb-6">
        <SourcePicker onSourceChange={setSource} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        <ActiveSessions data={sessionsData} />
        <TerminatedSessions data={sessionsData} />
        <MetricCard
          label={`Detections (${timeLabel})`}
          value={totalDetections}
          detail={`${blockedDetections} blocked, ${Math.max(totalDetections - blockedDetections, 0)} allowed`}
          tone="amber"
        />
        <MetricCard
          label="Block Rate"
          value={`${blockRate}%`}
          detail={`Highest risk score observed: ${highestRisk}`}
          tone={blockRate > 0 ? "red" : "slate"}
        />
        <MetricCard
          label="Tier 2 Reviewed"
          value={tier2Rows.length}
          detail={`${tier2Raised} watched/raised, ${tier2Kills} kill actions`}
          tone={tier2Kills > 0 ? "red" : tier2Raised > 0 ? "amber" : "blue"}
        />
        <MetricCard
          label="Tier 3 Findings"
          value={tier3Rows.length}
          detail={`${tier3Kills} kill actions, ${Math.max(tier3Rows.length - tier3Kills, 0)} grouped alerts`}
          tone={tier3Kills > 0 ? "red" : tier3Rows.length > 0 ? "amber" : "slate"}
        />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <DetectionTimeline data={summary.data?.timeline ?? null} />
        <AbuseFamilyChart data={summary.data?.categories ?? null} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4">
        <RecentDetectionsTable data={detectionRows} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4">
        <Tier2MlPanel data={promptHistory.data} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4">
        <Tier3FindingsPanel data={tier3Rows} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4">
        <BlockedPromptEvidence data={promptHistory.data} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SignatureHitsTable data={summary.data?.signatures ?? null} />
        <TerminatedSessionsPanel data={sessionsData} />
      </div>
    </div>
  );
}
