import type { SignatureHit } from "../../api/client";
import DashboardPanel from "./DashboardPanel";
import { categoryExplanation, categoryLabel, explainSignature, formatDateTime, signatureLabel } from "./dashboardFormat";

interface Props {
  data: SignatureHit[] | null;
}

// SignatureHitsTable: Renders the signature hits table UI section.
export default function SignatureHitsTable({ data }: Props) {
  const rows = data || [];

  return (
    <DashboardPanel
      title="Top Triggered Signatures"
      description="Detection rules firing most often, translated into operational labels."
    >
      {rows.length === 0 ? (
        <div className="py-8 text-center text-sm text-slate-400">No data</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-slate-500">
                <th className="pb-2 pr-4 font-medium">Detection</th>
                <th className="pb-2 pr-4 font-medium">Threat Category</th>
                <th className="pb-2 pr-4 font-medium">What It Means</th>
                <th className="pb-2 pr-4 font-medium">Operational Use</th>
                <th className="pb-2 pr-4 font-medium">Hits</th>
                <th className="pb-2 font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.slice(0, 10).map((row) => (
                <tr key={row.signature_id} className="align-top">
                  <td className="min-w-[220px] py-3 pr-4">
                    <div className="text-xs font-medium text-slate-800">{signatureLabel(row)}</div>
                    <div className="mt-1 font-mono text-[11px] text-slate-400">{row.signature_id}</div>
                  </td>
                  <td className="min-w-[150px] py-3 pr-4 text-xs text-slate-600">
                    {categoryLabel(row.category || row.signature_id)}
                  </td>
                  <td className="max-w-sm py-3 pr-4 text-xs leading-5 text-slate-500">{explainSignature(row.signature_id)}</td>
                  <td className="max-w-sm py-3 pr-4 text-xs leading-5 text-slate-500">
                    {categoryExplanation(row.category || row.signature_id)}
                  </td>
                  <td className="py-2 pr-4 text-slate-950">{row.hit_count}</td>
                  <td className="py-2 text-slate-500">{formatDateTime(row.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </DashboardPanel>
  );
}
