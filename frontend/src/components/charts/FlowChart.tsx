import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Trends } from "../../api/types";
import { shortDate } from "../../lib/format";
import { axisProps } from "./axis";
import { ChartTooltip, Legend, type SeriesDef } from "./ChartTooltip";

const SERIES: SeriesDef[] = [
  { key: "new", label: "New", color: "var(--flow-new)" },
  { key: "closed", label: "Closed", color: "var(--flow-closed)" },
];

export default function FlowChart({ data, bucket }: { data: Trends["new_vs_closed"]; bucket: Trends["bucket"] }) {
  const fmt = (p: string) => (bucket === "week" ? `Week of ${shortDate(p)}` : shortDate(p));
  return (
    <div>
      <div className="mb-3">
        <Legend series={SERIES} shape="rect" />
      </div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }} barGap={2} barCategoryGap="25%">
            <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
            <XAxis dataKey="period" {...axisProps} tickFormatter={shortDate} minTickGap={24} />
            <YAxis {...axisProps} axisLine={false} allowDecimals={false} width={44} />
            <Tooltip cursor={{ fill: "rgb(var(--ink) / 0.05)" }} content={<ChartTooltip series={SERIES} formatLabel={fmt} />} />
            {SERIES.map((s) => (
              <Bar key={s.key} dataKey={s.key} name={s.label} fill={s.color} radius={[4, 4, 0, 0]} maxBarSize={24} isAnimationActive={false} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
