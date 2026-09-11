import { FormEvent, useEffect, useState } from "react";
import { signaturesApi, type CustomSignatureRequest, type CustomSignatureResponse, type SignaturesResponse } from "../api/client";
import { useAuth } from "../auth";

const SEVERITIES = ["low", "medium", "high", "critical"];

const EMPTY_CUSTOM: CustomSignatureRequest = {
  signature_id: "",
  category: "",
  pattern: "",
  severity: "medium",
  description: "",
};

// SignaturesPage: Community signature metadata + premium status (all roles), and
// custom signature authoring (admin only). GET /api/signatures, POST /api/signatures/custom.
export default function SignaturesPage() {
  const { hasRole } = useAuth();
  const canAuthor = hasRole("admin");
  const [signatures, setSignatures] = useState<SignaturesResponse | null>(null);
  const [error, setError] = useState("");
  const [custom, setCustom] = useState<CustomSignatureRequest>(EMPTY_CUSTOM);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<CustomSignatureResponse | null>(null);

  async function load() {
    setError("");
    try {
      const response = await signaturesApi.get();
      setSignatures(response.data);
    } catch {
      setError("Could not load signatures.");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  function updateCustom<K extends keyof CustomSignatureRequest>(key: K, value: CustomSignatureRequest[K]) {
    setCustom((current) => ({ ...current, [key]: value }));
    setResult(null);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!canAuthor) return;
    setSaving(true);
    setError("");
    setResult(null);
    try {
      const response = await signaturesApi.addCustom(custom);
      setResult(response.data);
      setCustom(EMPTY_CUSTOM);
    } catch (err: any) {
      // Surface the server's reason. 400 = the pattern was rejected (bad regex
      // or ReDoS risk), 503 = it was valid but could not be stored, 403 = role.
      // Blaming the admin role for all three sends the operator the wrong way.
      const detail = err?.response?.data?.detail;
      const status = err?.response?.status;
      setError(
        detail ||
          (status === 403
            ? "Could not store the custom signature. Admin role is required."
            : "Could not store the custom signature. Please try again."),
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Admin</p>
          <h1 className="mt-1 text-3xl font-semibold text-slate-950">Signatures</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-600">
            Community signature coverage and premium status. {canAuthor ? "Admins can author custom signatures for this scope." : "Custom authoring requires admin role."}
          </p>
        </div>
        <button onClick={load} className="rounded-md border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700">Refresh</button>
      </div>

      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}

      <div className="grid gap-4 md:grid-cols-3">
        <Metric label="Community signatures" value={String(signatures?.community_count ?? "—")} detail="Bundled community rule count" />
        <Metric label="Categories" value={String(signatures?.categories.length ?? "—")} detail="Distinct signature categories" />
        <Metric
          label="Premium feed"
          value={signatures?.premium_enabled ? "Enabled" : "Disabled"}
          detail={signatures?.aws_account_id ? `Account ${signatures.aws_account_id}` : "Not configured"}
          tone={signatures?.premium_enabled ? "green" : "slate"}
        />
      </div>

      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950">Categories</h2>
        {(signatures?.categories.length ?? 0) === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No categories reported.</p>
        ) : (
          <div className="mt-4 flex flex-wrap gap-2">
            {signatures!.categories.map((c) => (
              <span key={c} className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700 ring-1 ring-slate-200">{c}</span>
            ))}
          </div>
        )}
        {signatures?.premium_enabled && signatures.marketplace_link && (
          <p className="mt-4 text-sm text-slate-600">
            Premium feed:{" "}
            {/^https:\/\//i.test(signatures.marketplace_link) ? (
              <a href={signatures.marketplace_link} target="_blank" rel="noreferrer" className="font-semibold text-blue-700 underline">
                {signatures.marketplace_link}
              </a>
            ) : (
              <span className="font-semibold text-slate-700">{signatures.marketplace_link}</span>
            )}
          </p>
        )}
      </section>

      <form onSubmit={submit} className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950">Author Custom Signature</h2>
        <p className="mt-1 text-sm text-slate-500">{canAuthor ? "Stored for this scope." : "Read-only — admin role is required."}</p>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <label className="text-sm font-semibold text-slate-700">
            Signature ID
            <input value={custom.signature_id} disabled={!canAuthor} onChange={(e) => updateCustom("signature_id", e.target.value)} placeholder="sig-custom-001" className="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 disabled:bg-slate-100" />
          </label>
          <label className="text-sm font-semibold text-slate-700">
            Category
            <input value={custom.category} disabled={!canAuthor} onChange={(e) => updateCustom("category", e.target.value)} placeholder="prompt_injection" className="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 disabled:bg-slate-100" />
          </label>
          <label className="text-sm font-semibold text-slate-700">
            Severity
            <select value={custom.severity} disabled={!canAuthor} onChange={(e) => updateCustom("severity", e.target.value)} className="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 disabled:bg-slate-100">
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="text-sm font-semibold text-slate-700">
            Pattern (regex)
            <input value={custom.pattern} disabled={!canAuthor} onChange={(e) => updateCustom("pattern", e.target.value)} placeholder="ignore (all|previous) instructions" className="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs disabled:bg-slate-100" />
          </label>
        </div>
        <label className="mt-4 block text-sm font-semibold text-slate-700">
          Description
          <textarea value={custom.description} disabled={!canAuthor} onChange={(e) => updateCustom("description", e.target.value)} rows={3} className="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 disabled:bg-slate-100" />
        </label>
        {canAuthor && (
          <button disabled={saving} className="mt-5 rounded-md bg-slate-950 px-4 py-2 text-sm font-semibold text-white disabled:bg-slate-300">
            {saving ? "Saving..." : "Add custom signature"}
          </button>
        )}
        {result && (
          // Only a 200 reaches here, and a 200 now means the write landed: a
          // rejected pattern returns 400 and a failed store returns 503, both
          // of which surface in the red error box above.
          <div className="mt-4 rounded-md border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800">
            {`Stored signature ${result.signature_id} in ${result.store} for scope ${result.scope_id}.`}
            {result.note ? ` ${result.note}` : ""}
          </div>
        )}
      </form>
    </div>
  );
}

function Metric({ label, value, detail, tone = "blue" }: { label: string; value: string; detail: string; tone?: "blue" | "green" | "slate" }) {
  const color = tone === "green" ? "text-emerald-600" : tone === "slate" ? "text-slate-900" : "text-blue-600";
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 text-2xl font-semibold ${color}`}>{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </div>
  );
}
