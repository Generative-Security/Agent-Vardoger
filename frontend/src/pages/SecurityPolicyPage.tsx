import { FormEvent, useEffect, useState } from "react";
import { policyApi, type SecurityPolicy } from "../api/client";
import { useAuth } from "../auth";

const MODES = ["off", "shadow", "enforce"];

// SecurityPolicyPage: Reads the scope's Tier 2/Tier 3 policy (all roles) and lets
// admins edit and save it. Non-admins see a read-only view. GET/PUT /api/policy.
export default function SecurityPolicyPage() {
  const { hasRole } = useAuth();
  const canEdit = hasRole("admin");
  const [policy, setPolicy] = useState<SecurityPolicy | null>(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  async function load() {
    setError("");
    try {
      const response = await policyApi.get();
      setPolicy(response.data);
    } catch {
      setError("Could not load the security policy.");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  function update<K extends keyof SecurityPolicy>(key: K, value: SecurityPolicy[K]) {
    setPolicy((current) => (current ? { ...current, [key]: value } : current));
    setSaved(false);
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!policy || !canEdit) return;
    setSaving(true);
    setError("");
    setSaved(false);
    try {
      const response = await policyApi.update(policy);
      setPolicy(response.data);
      setSaved(true);
    } catch (err: any) {
      // Prefer the server's reason. A save can fail for reasons other than
      // permissions (the store being unavailable, for one), and blaming the
      // admin role every time sends the operator down the wrong path.
      const detail = err?.response?.data?.detail;
      const status = err?.response?.status;
      setError(
        detail ||
          (status === 403
            ? "Could not save the security policy. Admin role is required."
            : "Could not save the security policy. Please try again."),
      );
    } finally {
      setSaving(false);
    }
  }

  if (error && !policy) return <div className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>;
  if (!policy) return <div className="rounded-lg border border-slate-200 bg-white p-8 text-sm text-slate-500 shadow-sm">Loading security policy...</div>;

  return (
    <form onSubmit={save} className="space-y-6">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Admin</p>
          <h1 className="mt-1 text-3xl font-semibold text-slate-950">Security Policy</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-600">
            Tier 2 and Tier 3 enforcement policy for this scope. {canEdit ? "You can edit and save these values." : "Read-only — admin role is required to edit."}
          </p>
        </div>
        {canEdit && (
          <button type="submit" disabled={saving} className="rounded-md bg-slate-950 px-4 py-2 text-sm font-semibold text-white disabled:bg-slate-300">
            {saving ? "Saving..." : "Save policy"}
          </button>
        )}
      </div>

      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
      {saved && <div className="rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">Policy saved. Version {policy.policy_version}.</div>}

      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950">Tier 2</h2>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <SelectField label="Tier 2 mode" value={policy.tier2_mode} disabled={!canEdit} options={MODES} onChange={(v) => update("tier2_mode", v)} />
          <NumberField label="Default kill threshold" value={policy.tier2_default_kill_threshold} step={0.01} disabled={!canEdit} onChange={(v) => update("tier2_default_kill_threshold", v)} />
          <NumberField label="High-risk threshold" value={policy.tier2_high_risk_threshold} step={0.01} disabled={!canEdit} onChange={(v) => update("tier2_high_risk_threshold", v)} />
          <BoolField label="Require repeated malicious" value={policy.tier2_require_repeated_malicious} disabled={!canEdit} onChange={(v) => update("tier2_require_repeated_malicious", v)} />
          <NumberField label="Min malicious verdicts for kill" value={policy.tier2_min_malicious_verdicts_for_kill} step={1} disabled={!canEdit} onChange={(v) => update("tier2_min_malicious_verdicts_for_kill", v)} />
          <NumberField label="Single-verdict kill threshold" value={policy.tier2_allow_single_verdict_kill_threshold} step={0.01} disabled={!canEdit} onChange={(v) => update("tier2_allow_single_verdict_kill_threshold", v)} />
        </div>
      </section>

      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950">Tier 3</h2>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <SelectField label="Tier 3 mode" value={policy.tier3_mode} disabled={!canEdit} options={MODES} onChange={(v) => update("tier3_mode", v)} />
          <NumberField label="Min sessions for kill" value={policy.tier3_min_sessions_for_kill} step={1} disabled={!canEdit} onChange={(v) => update("tier3_min_sessions_for_kill", v)} />
          <NumberField label="Similarity threshold" value={policy.tier3_similarity_threshold} step={0.01} disabled={!canEdit} onChange={(v) => update("tier3_similarity_threshold", v)} />
          <NumberField label="Kill threshold" value={policy.tier3_kill_threshold} step={0.01} disabled={!canEdit} onChange={(v) => update("tier3_kill_threshold", v)} />
        </div>
      </section>

      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950">Metadata</h2>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <ReadOnly label="Policy version" value={String(policy.policy_version)} />
          <ReadOnly label="Updated by" value={policy.updated_by || "-"} />
          <ReadOnly label="Updated at" value={policy.updated_at ? new Date(policy.updated_at * 1000).toLocaleString() : "-"} />
        </div>
      </section>
    </form>
  );
}

function SelectField({ label, value, options, disabled, onChange }: { label: string; value: string; options: string[]; disabled: boolean; onChange: (v: string) => void }) {
  return (
    <label className="text-sm font-semibold text-slate-700">
      {label}
      <select value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)} className="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 disabled:bg-slate-100 disabled:text-slate-500">
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );
}

function NumberField({ label, value, step, disabled, onChange }: { label: string; value: number; step: number; disabled: boolean; onChange: (v: number) => void }) {
  return (
    <label className="text-sm font-semibold text-slate-700">
      {label}
      <input type="number" step={step} value={value} disabled={disabled} onChange={(e) => onChange(Number(e.target.value))} className="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 disabled:bg-slate-100 disabled:text-slate-500" />
    </label>
  );
}

function BoolField({ label, value, disabled, onChange }: { label: string; value: boolean; disabled: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm font-semibold text-slate-700">
      <input type="checkbox" checked={value} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

function ReadOnly({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 break-words text-sm font-semibold text-slate-950">{value}</p>
    </div>
  );
}
