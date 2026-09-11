import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import type { TimelinePoint } from "../../api/client";
import DashboardPanel from "./DashboardPanel";

interface Props {
  data: TimelinePoint[] | null;
}

// DetectionTimeline: Renders the detection timeline UI section.
export default function DetectionTimeline({ data }: Props) {
  // chartData: Helper for chart data.
  const chartData = (data || []).map((d) => ({
    ...d,
    time: d.timestamp.split("T")[1]?.slice(0, 5) || d.timestamp,
  }));

  return (
    <DashboardPanel
      title="Detection Timeline"
      description="Allowed and blocked prompt evaluations in the selected time window."
    >
      {chartData.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-sm text-slate-400">
          No data
        </div>
      ) : (
        <div className="dashboard-chart h-56">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis dataKey="time" tick={{ fill: "#6b7280", fontSize: 11 }} />
            <YAxis tick={{ fill: "#6b7280", fontSize: 11 }} />
            <Tooltip
              contentStyle={{ backgroundColor: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 8 }}
              labelStyle={{ color: "#475569" }}
            />
            <Area
              type="monotone"
              dataKey="block_count"
              stackId="1"
              stroke="#ef4444"
              fill="#ef4444"
              fillOpacity={0.3}
              name="Blocked"
            />
            <Area
              type="monotone"
              dataKey="allow_count"
              stackId="1"
              stroke="#10b981"
              fill="#10b981"
              fillOpacity={0.15}
              name="Allowed"
            />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </DashboardPanel>
  );
}
