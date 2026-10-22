import type { TooltipContentProps } from "recharts";

export interface SeriesDef {
  key: string;
  label: string;
  color: string;
}

type ChartTooltipProps = Partial<Pick<TooltipContentProps<number, string>, "active" | "payload" | "label">> & {
  series: SeriesDef[];
  formatLabel: (label: string) => string;
  showTotal?: boolean;
};

/** Values lead, labels follow; series keyed by a short line stroke of the series color. */
export function ChartTooltip({
  active,
  payload,
  label,
  series,
  formatLabel,
  showTotal,
}: ChartTooltipProps) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload as Record<string, number>;
  const total = series.reduce((a, s) => a + (row[s.key] ?? 0), 0);
  return (
    <div className="min-w-[160px] rounded-lg border border-line bg-raised px-3 py-2 text-xs shadow-lg">
      <div className="mb-1.5 font-medium text-ink2">{formatLabel(String(label))}</div>
      <ul className="space-y-1">
        {series.map((s) => (
          <li key={s.key} className="flex items-center gap-2">
            <span className="h-0.5 w-3 rounded-full" style={{ background: s.color }} aria-hidden />
            <span className="tabular font-semibold text-ink">{(row[s.key] ?? 0).toLocaleString()}</span>
            <span className="text-ink2">{s.label}</span>
          </li>
        ))}
      </ul>
      {showTotal && (
        <div className="mt-1.5 flex items-center gap-2 border-t border-line pt-1.5">
          <span className="w-3" />
          <span className="tabular font-semibold text-ink">{total.toLocaleString()}</span>
          <span className="text-ink2">Total</span>
        </div>
      )}
    </div>
  );
}

export function Legend({
  series,
  shape = "line",
  values,
}: {
  series: SeriesDef[];
  shape?: "line" | "rect";
  values?: Record<string, number>;
}) {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink2">
      {series.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5">
          <span
            className={shape === "line" ? "h-0.5 w-3.5 rounded-full" : "h-2.5 w-2.5 rounded-sm"}
            style={{ background: s.color }}
            aria-hidden
          />
          {s.label}
          {values && <span className="tabular font-semibold text-ink">{values[s.key]?.toLocaleString()}</span>}
        </li>
      ))}
    </ul>
  );
}
