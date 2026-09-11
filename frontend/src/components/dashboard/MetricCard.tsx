interface Props {
  label: string;
  value: string | number;
  detail: string;
  tone?: "blue" | "red" | "amber" | "slate";
}

const tones = {
  blue: "text-blue-600 bg-blue-50 border-blue-100",
  red: "text-red-600 bg-red-50 border-red-100",
  amber: "text-amber-600 bg-amber-50 border-amber-100",
  slate: "text-slate-900 bg-slate-50 border-slate-200",
};

// MetricCard: Renders the metric card UI section.
export default function MetricCard({ label, value, detail, tone = "slate" }: Props) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-medium text-slate-500">{label}</div>
          <div className="mt-2 text-3xl font-semibold text-slate-950">{value}</div>
        </div>
        <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${tones[tone]}`}>
          live
        </span>
      </div>
      <div className="mt-3 text-xs leading-5 text-slate-500">{detail}</div>
    </div>
  );
}
