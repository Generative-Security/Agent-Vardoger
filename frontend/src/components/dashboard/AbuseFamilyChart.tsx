import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { CategoryBreakdown } from "../../api/client";
import DashboardPanel from "./DashboardPanel";
import { categoryExplanation, categoryLabel } from "./dashboardFormat";

interface Props {
  data: CategoryBreakdown[] | null;
}

const COLORS = [
  "#ef4444", "#f59e0b", "#3b82f6", "#8b5cf6", "#ec4899",
  "#14b8a6", "#f97316", "#6366f1", "#06b6d4", "#84cc16",
];

// AbuseFamilyChart: Renders the abuse family chart UI section.
export default function AbuseFamilyChart({ data }: Props) {
  const grouped = new Map<string, CategoryBreakdown & { explanation: string }>();
  for (const row of data || []) {
    const label = categoryLabel(row.category);
    const existing = grouped.get(label);
    if (existing) {
      existing.count += row.count;
    } else {
      grouped.set(label, { ...row, category: label, explanation: categoryExplanation(row.category) });
    }
  }
  const total = Array.from(grouped.values()).reduce((sum, row) => sum + row.count, 0) || 1;
  const chartData = Array.from(grouped.values()).map((row) => ({
    ...row,
    percentage: Math.round((row.count / total) * 1000) / 10,
  }));

  return (
    <DashboardPanel
      title="Abuse Categories"
      description="Blocked prompt families translated into readable threat labels."
    >
      {chartData.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-sm text-slate-400">
          No data
        </div>
      ) : (
        <div className="flex items-center gap-4">
          <div className="dashboard-chart h-56 w-1/2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
              <Pie
                data={chartData}
                dataKey="count"
                nameKey="category"
                cx="50%"
                cy="50%"
                innerRadius={40}
                outerRadius={80}
                paddingAngle={2}
              >
                {chartData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 8 }}
              />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex-1 space-y-1.5 max-h-[220px] overflow-y-auto">
            {chartData.map((cat, i) => (
              <div key={cat.category} className="rounded-md border border-slate-100 p-2 text-xs">
                <div className="flex items-center gap-2">
                  <span
                    className="h-2.5 w-2.5 rounded-full"
                    style={{ backgroundColor: COLORS[i % COLORS.length] }}
                  />
                  <span className="font-medium text-slate-700">{cat.category}</span>
                  <span className="ml-auto text-slate-500">{cat.count}</span>
                  <span className="w-10 text-right text-slate-400">{cat.percentage}%</span>
                </div>
                <div className="mt-1 pl-4 text-slate-500">{cat.explanation}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </DashboardPanel>
  );
}
