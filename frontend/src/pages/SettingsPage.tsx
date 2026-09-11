import { useEffect, useState } from "react";
import { settingsApi, type ManagedUpgradeInfo, type SettingsStatus } from "../api/client";
import { useAuth } from "../auth";

// SettingsPage: Deployment settings + managed-upgrade handoff. GET /api/settings/status,
// GET/POST /api/settings/managed-upgrade. Admins can record managed-upgrade intent.
export default function SettingsPage() {
  const { hasRole } = useAuth();
  const canRecordIntent = hasRole("admin");
  const [status, setStatus] = useState<SettingsStatus | null>(null);
  const [managed, setManaged] = useState<ManagedUpgradeInfo | null>(null);
  const [error, setError] = useState("");
  const [recording, setRecording] = useState(false);

  async function load() {
    setError("");
    try {
      const [statusResponse, managedResponse] = await Promise.allSettled([
        settingsApi.status(),
        settingsApi.managedUpgrade(),
      ]);
      if (statusResponse.status === "fulfilled") setStatus(statusResponse.value.data);
      if (managedResponse.status === "fulfilled") setManaged(managedResponse.value.data);
      if (statusResponse.status === "rejected" && managedResponse.status === "rejected") {
        setError("Could not load settings.");
      }
    } catch {
      setError("Could not load settings.");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function recordIntent() {
    if (!canRecordIntent) return;
    setRecording(true);
    setError("");
    try {
      const response = await settingsApi.recordManagedUpgradeIntent();
      setManaged(response.data);
    } catch {
      setError("Could not record managed-upgrade intent. Admin role is required.");
    } finally {
      setRecording(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Admin</p>
          <h1 className="mt-1 text-3xl font-semibold text-slate-950">Settings</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-600">
            Deployment configuration for this self-hosted scope, and the informational handoff to the managed offering.
          </p>
        </div>
        <button onClick={load} className="rounded-md border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700">Refresh</button>
      </div>

      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}

      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="Deployment" value={status?.deployment_mode || "-"} />
        <Metric label="Auth Mode" value={status?.auth_mode || "-"} />
        <Metric label="Scope" value={status?.scope_id || "-"} mono />
        <Metric label="Tier 3" value={status?.tier3_enabled ? "Enabled" : "Disabled"} />
      </div>

      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950">Configuration Flags</h2>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <Flag label="ML endpoint configured" value={status?.ml_endpoint_configured} />
          <Flag label="Global kill enabled" value={status?.global_kill_enabled} />
          <Flag label="Signature feed configured" value={status?.signature_feed_configured} />
          <Flag label="Managed intake configured" value={status?.managed_intake_configured} />
        </div>
      </section>

      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-950">Managed Upgrade</h2>
            <p className="mt-1 text-sm text-slate-600">{managed?.handoff_text || "Informational handoff to the managed offering."}</p>
          </div>
          {canRecordIntent && (
            <button onClick={recordIntent} disabled={recording} className="rounded-md bg-slate-950 px-4 py-2 text-sm font-semibold text-white disabled:bg-slate-300">
              {recording ? "Recording..." : "Record intent"}
            </button>
          )}
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <Detail label="Telemetry mode" value={managed?.telemetry_mode || "not set"} />
          <Detail label="Intent recorded" value={managed?.intent_recorded ? "Yes" : "No"} />
          <Detail
            label="Intake"
            value={managed?.intake_url || "not configured"}
            link={managed?.intake_url || undefined}
          />
        </div>
        {managed?.instructions && (
          <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-slate-700">
            {managed.instructions}
          </div>
        )}
      </section>
    </div>
  );
}

function Metric({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 break-words text-2xl font-semibold text-slate-950 ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}

function Flag({ label, value }: { label: string; value?: boolean }) {
  return (
    <div className="flex items-center justify-between rounded-md border border-slate-200 bg-slate-50 px-4 py-3">
      <p className="text-sm font-semibold text-slate-700">{label}</p>
      <span className={`rounded-full px-2 py-1 text-xs font-semibold ${value ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" : "bg-slate-100 text-slate-500 ring-1 ring-slate-200"}`}>
        {value ? "On" : "Off"}
      </span>
    </div>
  );
}

// isSafeHttpsUrl: only https:// URLs are rendered as clickable links. This is
// defense-in-depth against a javascript: (or other-scheme) value planted in an
// operator-set env var; React does not block such schemes in href.
function isSafeHttpsUrl(value?: string): boolean {
  return typeof value === "string" && /^https:\/\//i.test(value.trim());
}

function Detail({ label, value, link }: { label: string; value: string; link?: string }) {
  return (
    <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p>
      {isSafeHttpsUrl(link) ? (
        <a href={link} target="_blank" rel="noreferrer" className="mt-1 block break-words text-sm font-semibold text-blue-700 underline">
          {value}
        </a>
      ) : (
        <p className="mt-1 break-words text-sm font-semibold text-slate-950">{value}</p>
      )}
    </div>
  );
}
