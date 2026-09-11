const COLORS: Record<string, string> = {
  block: "bg-red-50 text-red-700 ring-red-200",
  allow: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  high: "bg-red-50 text-red-700 ring-red-200",
  medium: "bg-amber-50 text-amber-700 ring-amber-200",
  low: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  active: "bg-blue-50 text-blue-700 ring-blue-200",
  terminated: "bg-red-50 text-red-700 ring-red-200",
};

// StatusBadge: Renders the status badge UI section.
export default function StatusBadge({ status }: { status: string }) {
  const color = COLORS[status] || "bg-slate-100 text-slate-600 ring-slate-200";
  return (
    <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ${color}`}>
      {status}
    </span>
  );
}
