import { useEffect, useState } from "react";
import { healthApi, settingsApi, type HealthResponse, type SettingsStatus } from "../api/client";

// HealthPage: Deployment health and configuration, backed by /api/settings/status
// and /api/health. There is no per-source troubleshooting endpoint in the OSS
// backend, so this shows deployment mode, auth mode, scope_id, tier flags, and
// the service health check.
export default function HealthPage() {
  const [status, setStatus] = useState<SettingsStatus | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [statusResponse, healthResponse] = await Promise.allSettled([
        settingsApi.status(),
        healthApi.get(),
      ]);
      if (statusResponse.status === "fulfilled") setStatus(statusResponse.value.data);
      if (healthResponse.status === "fulfilled") setHealth(healthResponse.value.data);
      if (statusResponse.status === "rejected" && healthResponse.status === "rejected") {
        setError("Could not load deployment status or health.");
      }
    } catch {
      setError("Could not load deployment status or health.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const healthy = health?.status === "ok";

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Security console</p>
          <h1 className="mt-1 text-3xl font-semibold text-slate-950">Health</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-600">
            Deployment mode, auth mode, scope, tier flags, and the service health check for this self-hosted deployment.
          </p>
        </div>
        <button onClick={load} className="rounded-md bg-slate-950 px-4 py-2 text-sm font-semibold text-white">Refresh</button>
      </div>

      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
      {loading && <div className="rounded-lg border border-slate-200 bg-white p-8 text-sm text-slate-500 shadow-sm">Loading health...</div>}

      {!loading && (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <Metric label="Service" value={health?.service || "-"} detail={healthy ? "Healthy" : "Unknown"} tone={healthy ? "green" : "amber"} />
            <Metric label="Deployment" value={status?.deployment_mode || "-"} detail="Self-hosted or managed" />
            <Metric label="Auth Mode" value={status?.auth_mode || "-"} detail="none = local dev (admin)" />
            <Metric label="Scope" value={status?.scope_id || "-"} detail="Isolation partition (local)" />
          </div>

          <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="text-lg font-semibold text-slate-950">Feature Flags</h2>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <Flag label="Tier 3 enabled" value={status?.tier3_enabled} />
              <Flag label="Global kill enabled" value={status?.global_kill_enabled} />
              <Flag label="ML endpoint configured" value={status?.ml_endpoint_configured} />
              <Flag label="Premium signatures" value={status?.premium_signatures_configured} />
              <Flag label="Managed intake configured" value={status?.managed_intake_configured} />
            </div>
          </section>

          <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="text-lg font-semibold text-slate-950">Service Check</h2>
            <div className="mt-4 flex items-center gap-3">
              <span className={`rounded-full px-3 py-1 text-sm font-semibold ${healthy ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" : "bg-amber-50 text-amber-700 ring-1 ring-amber-200"}`}>
                {health?.status || "unknown"}
              </span>
              <span className="text-sm text-slate-600">{health?.service || "service name unavailable"}</span>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

function Metric({ label, value, detail, tone = "blue" }: { label: string; value: string; detail: string; tone?: "blue" | "green" | "amber" }) {
  const color = tone === "green" ? "text-emerald-600" : tone === "amber" ? "text-amber-600" : "text-slate-950";
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 break-words text-2xl font-semibold ${color}`}>{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
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
