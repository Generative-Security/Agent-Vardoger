import { useEffect, useState } from "react";
import { sourcesApi, type SourcesResponse } from "../api/client";
import { setSelectedSource } from "../sourceSelection";

// SourcesPage: Read-only listing of the distinct sources seen in the scope.
// GET /api/sources. Selecting a source persists it for the monitoring pages.
export default function SourcesPage() {
  const [data, setData] = useState<SourcesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const response = await sourcesApi.list();
      setData(response.data);
    } catch {
      setError("Could not load sources.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Admin</p>
          <h1 className="mt-1 text-3xl font-semibold text-slate-950">Sources</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-600">
            Distinct sources ("&lt;aws_account_id&gt;/&lt;agent&gt;") seen within the scope. This is a read-only listing; use a source as the segmentation filter on monitoring pages.
          </p>
        </div>
        <button onClick={load} className="rounded-md bg-slate-950 px-4 py-2 text-sm font-semibold text-white">Refresh</button>
      </div>

      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}

      <div className="grid gap-4 md:grid-cols-2">
        <Metric label="Scope" value={data?.scope_id || "-"} detail="Isolation partition" />
        <Metric label="Sources" value={String(data?.count ?? "—")} detail="Distinct sources in scope" />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {loading ? (
              <tr><td colSpan={2} className="px-4 py-12 text-center text-slate-500">Loading sources...</td></tr>
            ) : (data?.sources.length ?? 0) === 0 ? (
              <tr><td colSpan={2} className="px-4 py-12 text-center text-slate-500">No sources seen in this scope yet.</td></tr>
            ) : data!.sources.map((source) => (
              <tr key={source} className="align-top">
                <td className="px-4 py-3 font-mono text-slate-800">{source}</td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => setSelectedSource(source)}
                    className="rounded-md border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:border-slate-300"
                  >
                    Use as filter
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className="mt-2 break-words text-2xl font-semibold text-slate-950">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </div>
  );
}
