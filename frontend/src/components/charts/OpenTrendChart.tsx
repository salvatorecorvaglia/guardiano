import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Trends } from "../../api/types";
import { CHART_SEVERITIES, fmtDate, SEVERITY_LABEL, sevColor, shortDate } from "../../lib/format";
import { axisProps } from "./axis";
import { ChartTooltip, Legend, type SeriesDef } from "./ChartTooltip";

const SERIES: SeriesDef[] = CHART_SEVERITIES.map((s) => ({ key: s, label: SEVERITY_LABEL[s], color: sevColor(s) }));

export default function OpenTrendChart({ data }: { data: Trends["open_by_severity"] }) {
  // Latest values ride in the legend (direct labels that never collide when lines converge).
  const latest = data[data.length - 1] as unknown as Record<string, number> | undefined;
  return (
    <div>
      <div className="mb-3">
        <Legend series={SERIES} values={latest} />
      </div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
            <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
            <XAxis dataKey="date" {...axisProps} tickFormatter={shortDate} minTickGap={36} />
            <YAxis {...axisProps} axisLine={false} allowDecimals={false} width={44} />
            <Tooltip
              cursor={{ stroke: "var(--chart-axis)", strokeWidth: 1 }}
              content={<ChartTooltip series={SERIES} formatLabel={fmtDate} showTotal />}
            />
            {SERIES.map((s) => (
              <Line
                key={s.key}
                type="linear"
                dataKey={s.key}
                name={s.label}
                stroke={s.color}
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
                dot={false}
                activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--chart-surface)" }}
                isAnimationActive={false}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
