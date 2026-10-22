import { useQuery } from "@tanstack/react-query";
import { Printer } from "lucide-react";
import { analyticsKeys, getTopAssets, useAssetOptions } from "../api/queries";
import { request } from "../api/typed";
import AsyncState from "../components/AsyncState";
import TableScroll from "../components/TableScroll";
import { fmtDate } from "../lib/format";
import { optionalNumber, useUrlParams } from "../lib/urlState";

const WINDOWS = [30, 90, 180, 365];
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function pct(value: number | null | undefined) {
  return value === null || value === undefined ? "—" : `${value}%`;
}

/** A bar that survives printing: a filled span, not a chart library. */
function Bar({ value, of, tone = "bg-accent" }: { value: number; of: number; tone?: string }) {
  const width = of > 0 ? Math.round((value / of) * 100) : 0;
  return (
    <span className="inline-flex h-2 w-24 overflow-hidden rounded-full bg-ink/10 align-middle">
      <span className={`h-full ${tone}`} style={{ width: `${width}%` }} />
    </span>
  );
}

const BREAKDOWNS = [
  ["product", "product"],
  ["team", "team"],
  ["environment", "environment"],
  ["tool", "scanner"],
] as const;

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="card break-inside-avoid p-4 print:border print:shadow-none">
      <h2 className="text-sm font-semibold">{title}</h2>
      {hint && <p className="mb-3 text-xs text-muted">{hint}</p>}
      {children}
    </section>
  );
}

/**
 * A report meant to be printed or saved as PDF from the browser, so it needs no export dependency and
 * no server-side renderer. Printing waits for the compliance, summary and estate breakdown queries.
 */
export default function Reports() {
  // In the URL, like every list page's filters, so a report can be bookmarked or sent to someone.
  const { params, update } = useUrlParams();
  const assetId = params.get("asset") ?? "";
  const days = WINDOWS.includes(Number(params.get("days"))) ? Number(params.get("days")) : 90;

  const assets = useAssetOptions(); // the same list every asset picker uses, from one cache entry
  const report = useQuery({
    queryKey: analyticsKeys.compliance(assetId, days),
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/compliance", { signal, query: { days, asset_id: optionalNumber(assetId) } }),
  });
  const summary = useQuery({
    queryKey: analyticsKeys.summary(assetId),
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/summary", { signal, query: { asset_id: optionalNumber(assetId) } }),
  });
  const by = BREAKDOWNS.find(([key]) => key === params.get("by"))?.[0] ?? "product";
  const breakdown = useQuery({
    queryKey: ["analytics", "breakdown", by, days],
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/breakdown", { signal, query: { by, days } }),
    enabled: !assetId,
  });
  const top = useQuery({
    queryKey: analyticsKeys.top("assets", 10),
    queryFn: ({ signal }) => getTopAssets(10, signal),
    enabled: !assetId,
  });

  const c = report.data;
  const s = summary.data;
  const assetName = assets.data?.find((a) => String(a.id) === assetId)?.name;
  const printReady = !!c && !!s && !report.isFetching && !summary.isFetching
    && !report.error && !summary.error
    && (!assetId || !!assetName)
    && (!!assetId || (!!top.data && !!breakdown.data && !top.isFetching && !breakdown.isFetching && !top.error && !breakdown.error));

  return (
    <>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3 print:hidden">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Reports</h1>
          <p className="text-sm text-ink2">
            A printable summary of where the estate stands. Use your browser’s print dialog to save it as PDF.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select className="input w-52" aria-label="Report asset" value={assetId} onChange={(e) => update({ asset: e.target.value || null })}>
            <option value="">All assets</option>
            {assets.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
          <select className="input w-32" aria-label="Report time window" value={days} onChange={(e) => update({ days: e.target.value === "90" ? null : e.target.value })}>
            {WINDOWS.map((d) => (
              <option key={d} value={d}>
                Last {d} days
              </option>
            ))}
          </select>
          <button className="btn-primary" disabled={!printReady} onClick={() => window.print()}>
            <Printer className="h-4 w-4" /> Print
          </button>
        </div>
      </div>

      <AsyncState queries={assetId ? [report, summary, assets] : [report, summary, top, breakdown]} label="Report">
      {c && s && (
        <div className="space-y-4">
          <header className="border-b border-line pb-3">
            <h2 className="text-lg font-semibold tracking-tight">
              Security posture — {assetName ?? "all assets"}
            </h2>
            <p className="text-xs text-muted">
              Generated {fmtDate(c.generated_at)} · remediation window {c.sla.days} days · open findings only
            </p>
          </header>

          <Section title="Where the estate stands">
            <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
              <div>
                <p className="text-xs text-muted">Open findings</p>
                <p className="text-2xl font-semibold tabular">{s.open_total}</p>
              </div>
              <div>
                <p className="text-xs text-muted">Past SLA</p>
                <p className="text-2xl font-semibold tabular">{s.overdue}</p>
              </div>
              <div>
                <p className="text-xs text-muted">Known exploited</p>
                <p className="text-2xl font-semibold tabular">{s.known_exploited}</p>
              </div>
              <div>
                <p className="text-xs text-muted">Mean time to remediate</p>
                <p className="text-2xl font-semibold tabular">
                  {s.mttr_days_overall === null ? "—" : `${s.mttr_days_overall} d`}
                </p>
              </div>
            </div>
            <TableScroll label="Estate severity totals"><table className="mt-4 w-full text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Severity</th>
                  <th className="th text-right">Open</th>
                  <th className="th text-right">Mean time to remediate</th>
                </tr>
              </thead>
              <tbody>
                {SEVERITIES.map((sev) => (
                  <tr key={sev} className="border-b border-line/60">
                    <td className="td capitalize">{sev}</td>
                    <td className="td text-right tabular">{s.open_by_severity[sev]}</td>
                    <td className="td text-right tabular">
                      {s.mttr_days[sev] === null ? "—" : `${s.mttr_days[sev]} d`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table></TableScroll>
          </Section>

          <Section
            title="Remediation against SLA"
            hint={`“Within SLA” is where things stand now. “Resolved on time” is how the last ${c.sla.days} days were actually worked. Severities without an SLA are excluded from both.`}
          >
            <TableScroll label="Remediation compliance"><table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Severity</th>
                  <th className="th text-right">Open</th>
                  <th className="th text-right">Within SLA</th>
                  <th className="th text-right">Resolved</th>
                  <th className="th text-right">On time</th>
                </tr>
              </thead>
              <tbody>
                {c.sla.by_severity.map((row) => (
                  <tr key={row.severity} className="border-b border-line/60">
                    <td className="td capitalize">{row.severity}</td>
                    <td className="td text-right tabular">{row.open}</td>
                    <td className="td text-right tabular">
                      {row.within_sla}/{row.open} · {pct(row.within_sla_pct)}
                    </td>
                    <td className="td text-right tabular">{row.resolved}</td>
                    <td className="td text-right tabular">
                      {row.resolved_on_time}/{row.resolved} · {pct(row.resolved_on_time_pct)}
                    </td>
                  </tr>
                ))}
                <tr className="font-medium">
                  <td className="td">All</td>
                  <td className="td text-right tabular">{c.sla.open}</td>
                  <td className="td text-right tabular">{pct(c.sla.within_sla_pct)}</td>
                  <td className="td text-right tabular">{c.sla.resolved}</td>
                  <td className="td text-right tabular">{pct(c.sla.resolved_on_time_pct)}</td>
                </tr>
              </tbody>
            </table></TableScroll>
          </Section>

          {c.mttr_trend.length > 0 && (
            <Section
              title="Mean time to remediate, over time"
              hint="Findings resolved in each period, and how long they had been open. The count is shown because an average over one finding is not a trend."
            >
              <TableScroll label="Closed findings"><table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line">
                    <th className="th">Period beginning</th>
                    <th className="th text-right">Resolved</th>
                    <th className="th text-right">Mean days open</th>
                    <th className="th w-32" />
                  </tr>
                </thead>
                <tbody>
                  {c.mttr_trend.map((point) => (
                    <tr key={point.period} className="border-b border-line/60">
                      <td className="td">{fmtDate(point.period)}</td>
                      <td className="td text-right tabular">{point.resolved}</td>
                      <td className="td text-right tabular">{point.days} d</td>
                      <td className="td">
                        <Bar value={point.days} of={Math.max(...c.mttr_trend.map((p) => p.days), 1)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table></TableScroll>
            </Section>
          )}

          <Section
            title={`OWASP Top 10 (${c.owasp.edition})`}
            hint={`Open findings by category. ${c.owasp.unmapped} of ${c.owasp.open_total} carry no CWE that OWASP maps, so they appear in no category.`}
          >
            <TableScroll label="Remediation performance"><table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Category</th>
                  <th className="th text-right">Open</th>
                  <th className="th text-right">Critical / high</th>
                  <th className="th w-28" />
                </tr>
              </thead>
              <tbody>
                {c.owasp.categories.map((cat) => (
                  <tr key={cat.id} className="border-b border-line/60">
                    <td className="td">
                      <span className="font-mono text-xs text-muted">{cat.id}</span> {cat.title}
                    </td>
                    <td className="td text-right tabular">{cat.open}</td>
                    <td className="td text-right tabular">{cat.critical_high}</td>
                    <td className="td">
                      <Bar value={cat.open} of={Math.max(...c.owasp.categories.map((x) => x.open), 1)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table></TableScroll>
          </Section>

          <Section
            title={`CWE Top 25 (${c.cwe_top_25_edition})`}
            hint="Only the weaknesses present here are listed; the rest of the 25 have nothing open."
          >
            {c.cwe_top_25.some((w) => w.open > 0) ? (
              <TableScroll label="SLA policies"><table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line">
                    <th className="th">Rank</th>
                    <th className="th">Weakness</th>
                    <th className="th text-right">Open</th>
                    <th className="th text-right">Critical / high</th>
                  </tr>
                </thead>
                <tbody>
                  {c.cwe_top_25
                    .filter((w) => w.open > 0)
                    .map((w) => (
                      <tr key={w.cwe} className="border-b border-line/60">
                        <td className="td tabular">#{w.rank}</td>
                        <td className="td">
                          <span className="font-mono text-xs text-muted">{w.cwe}</span> {w.name}
                        </td>
                        <td className="td text-right tabular">{w.open}</td>
                        <td className="td text-right tabular">{w.critical_high}</td>
                      </tr>
                    ))}
                </tbody>
              </table></TableScroll>
            ) : (
              <p className="text-sm text-muted">None of the CWE Top 25 weaknesses are open here.</p>
            )}
          </Section>

          {!assetId && top.data && top.data.length > 0 && (
            <Section title="Assets carrying the most risk" hint="Weighted severity × business criticality.">
              <TableScroll label="Assets carrying risk"><table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line">
                    <th className="th">Asset</th>
                    <th className="th">Criticality</th>
                    <th className="th text-right">Risk score</th>
                    <th className="th text-right">Open</th>
                    <th className="th text-right">Critical</th>
                    <th className="th text-right">High</th>
                  </tr>
                </thead>
                <tbody>
                  {top.data.map((a) => (
                    <tr key={a.id} className="border-b border-line/60">
                      <td className="td">{a.name}</td>
                      <td className="td capitalize">{a.criticality}</td>
                      <td className="td text-right tabular">{a.risk_score}</td>
                      <td className="td text-right tabular">{a.open}</td>
                      <td className="td text-right tabular">{a.critical}</td>
                      <td className="td text-right tabular">{a.high}</td>
                    </tr>
                  ))}
                </tbody>
              </table></TableScroll>
            </Section>
          )}

          {!assetId && breakdown.data && breakdown.data.length > 0 && (
            <Section
              title="Breakdown"
              hint={`Resolved, MTTR and time to triage cover the last ${days} days. Time to triage runs from a finding appearing to a person first acting on it.`}
            >
              <div className="mb-2 print:hidden">
                <select className="input w-auto py-1 text-xs" aria-label="Break down by" value={by} onChange={(e) => update({ by: e.target.value === "product" ? null : e.target.value })}>
                  {BREAKDOWNS.map(([k, label]) => (
                    <option key={k} value={k}>
                      By {label}
                    </option>
                  ))}
                </select>
              </div>
              <TableScroll label="Grouped findings"><table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line">
                    <th className="th">{BREAKDOWNS.find(([k]) => k === by)![1]}</th>
                    <th className="th text-right">Open</th>
                    <th className="th text-right">Crit/high</th>
                    <th className="th text-right">Past SLA</th>
                    <th className="th text-right">Accepted</th>
                    <th className="th text-right">Resolved</th>
                    <th className="th text-right">MTTR</th>
                    <th className="th text-right">To triage</th>
                    {by === "tool" && <th className="th text-right">Only this tool</th>}
                  </tr>
                </thead>
                <tbody>
                  {breakdown.data.map((r) => (
                    <tr key={r.key ?? "none"} className="border-b border-line/60">
                      <td className="td">{r.label}</td>
                      <td className="td text-right tabular">{r.open}</td>
                      <td className="td text-right tabular">{r.critical_high}</td>
                      <td className="td text-right tabular">{r.overdue}</td>
                      <td className="td text-right tabular">{r.accepted}</td>
                      <td className="td text-right tabular">{r.resolved}</td>
                      <td className="td text-right tabular">{r.mttr_days == null ? "—" : `${r.mttr_days} d`}</td>
                      <td className="td text-right tabular">{r.median_triage_hours == null ? "—" : `${r.median_triage_hours} h`}</td>
                      {by === "tool" && <td className="td text-right tabular">{r.unique_open ?? "—"}</td>}
                    </tr>
                  ))}
                </tbody>
              </table></TableScroll>
            </Section>
          )}

          <p className="pt-2 text-[11px] text-muted">
            Guardiano · figures taken {fmtDate(c.generated_at)} · counts cover open and in-progress findings
            only. A finding carrying several weaknesses appears under each of their categories, so category
            counts need not sum to the total.
          </p>
        </div>
      )}
      </AsyncState>
    </>
  );
}
