import { useQuery } from "@tanstack/react-query";
import { AlarmClock, Flame, ShieldAlert, Siren, Timer, TriangleAlert, UploadCloud } from "lucide-react";
import { type ReactNode, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { analyticsKeys, getTopAssets, getTopCwes, getTopPackages, useAssetOptions } from "../api/queries";
import { request } from "../api/typed";
import { useAuth } from "../auth/AuthContext";
import FlowChart from "../components/charts/FlowChart";
import OpenTrendChart from "../components/charts/OpenTrendChart";
import SeverityBreakdown from "../components/charts/SeverityBreakdown";
import UploadDialog from "../components/UploadDialog";
import { ErrorBox, PageHeader, SeverityBar, Spinner, StatTile, TypeBadge } from "../components/ui";
import { compact, fmtNum, relTime, STATUS_LABEL, STATUSES } from "../lib/format";

const RANGES = [30, 90, 180] as const;
const STALE_DAYS = 30;

function Panel({ title, subtitle, children, action }: { title: string; subtitle?: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="card p-4">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          {subtitle && <p className="text-xs text-muted">{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

export default function Dashboard() {
  const [params, setParams] = useSearchParams();
  const days = Number(params.get("days")) || 90;
  const assetId = params.get("asset") ? Number(params.get("asset")) : undefined;
  const assets = useAssetOptions();
  const { can } = useAuth();
  const [uploading, setUploading] = useState(false);

  const summary = useQuery({
    queryKey: analyticsKeys.summary(assetId),
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/summary", { signal, query: { asset_id: assetId } }),
  });
  const trends = useQuery({
    queryKey: analyticsKeys.trends(days, assetId),
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/trends", { signal, query: { days, asset_id: assetId } }),
  });
  const topAssets = useQuery({
    queryKey: analyticsKeys.top("assets", 6),
    queryFn: ({ signal }) => getTopAssets(6, signal),
    enabled: !assetId,
  });
  const topCwes = useQuery({
    queryKey: analyticsKeys.top("cwes", 8, assetId),
    queryFn: ({ signal }) => getTopCwes(8, assetId, signal),
  });
  const owasp = useQuery({
    queryKey: analyticsKeys.compliance(assetId),
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/compliance", { signal, query: { asset_id: assetId } }),
  });
  const topPkgs = useQuery({
    queryKey: analyticsKeys.top("packages", 8, assetId),
    queryFn: ({ signal }) =>
      getTopPackages(8, assetId, signal),
  });
  const coverage = useQuery({
    queryKey: analyticsKeys.coverage(STALE_DAYS),
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/coverage", { signal, query: { stale_days: STALE_DAYS } }),
    enabled: !assetId,
  });
  const approvals = useQuery({
    queryKey: ["acceptance-requests", "pending"],
    queryFn: ({ signal }) => request("get", "/api/v1/acceptance-requests", { signal, query: { state: "pending", limit: 20 } }),
    enabled: can("manager"),
  });
  const scans = useQuery({
    queryKey: ["scans", "recent", assetId],
    queryFn: ({ signal }) => request("get", "/api/v1/scans", { signal, query: { page_size: 6, asset_id: assetId } }),
  });

  const setParam = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };

  const s = summary.data;
  const findingsLink = (extra: string) => `/findings?status=open&status=in_progress${assetId ? `&asset_id=${assetId}` : ""}${extra}`;

  return (
    <>
      <PageHeader title="Security posture" subtitle="Open exposure, remediation flow and hotspots across your application portfolio" />

      <div className="mb-5 flex flex-wrap items-center gap-2">
        <div className="inline-flex rounded-lg border border-line bg-raised p-0.5" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r}
              onClick={() => setParam("days", r === 90 ? null : String(r))}
              className={`rounded-md px-2.5 py-1 text-xs font-medium ${days === r ? "bg-accent/10 text-accent" : "text-ink2 hover:text-ink"}`}
              aria-pressed={days === r}
            >
              Last {r} days
            </button>
          ))}
        </div>
        <select
          className="input w-auto py-1 text-xs"
          value={assetId ?? ""}
          onChange={(e) => setParam("asset", e.target.value || null)}
          aria-label="Asset"
        >
          <option value="">All assets</option>
          {assets.data?.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </div>

      {trends.data?.severity_history_complete === false && <p role="status" className="text-sm text-warn">Some older severity changes lack structured history; those historical severity counts are approximate.</p>}
      <ErrorBox
        error={summary.error || trends.error || topAssets.error || topCwes.error || topPkgs.error || scans.error || owasp.error || coverage.error}
      />

      {s && s.assets_total === 0 && (
        <section className="card mb-5 flex flex-wrap items-center gap-4 p-5">
          <UploadCloud className="h-8 w-8 shrink-0 text-accent" aria-hidden />
          <div className="min-w-0 flex-1">
            <h2 className="font-semibold">Import your first scan</h2>
            <p className="mt-0.5 text-sm text-ink2">
              Upload a SARIF, CycloneDX, Trivy, Semgrep or Guardiano JSON report, or push results from CI with an API token.
            </p>
          </div>
          <div className="flex gap-2">
            {can("analyst") && (
              <button className="btn-primary" onClick={() => setUploading(true)}>
                Upload scan
              </button>
            )}
            <Link className="btn-secondary" to="/settings">
              Set up CI
            </Link>
          </div>
        </section>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Link to={findingsLink("&severity=critical")}>
          <StatTile label="Open critical" tone="critical" icon={<Flame className="h-3.5 w-3.5" />} value={s ? compact(s.open_by_severity.critical) : "–"} hint="Active findings" />
        </Link>
        <Link to={findingsLink("&severity=high")}>
          <StatTile label="Open high" tone="high" icon={<ShieldAlert className="h-3.5 w-3.5" />} value={s ? compact(s.open_by_severity.high) : "–"} hint="Active findings" />
        </Link>
        <Link to={findingsLink("")}>
          <StatTile
            label="Total open"
            icon={<TriangleAlert className="h-3.5 w-3.5" />}
            value={s ? compact(s.open_total) : "–"}
            hint={s ? `${fmtNum(s.open_by_type.sast)} SAST · ${fmtNum(s.open_by_type.sca)} SCA · ${fmtNum(s.open_by_type.iac)} IaC · ${fmtNum(s.open_by_type.dast)} DAST` : undefined}
          />
        </Link>
        <Link to={findingsLink("&kev=true")}>
          <StatTile
            label="Known exploited"
            tone={s?.known_exploited ? "danger" : undefined}
            icon={<Siren className="h-3.5 w-3.5" />}
            value={s ? compact(s.known_exploited) : "–"}
            hint="Listed by CISA as exploited"
          />
        </Link>
        <Link to={findingsLink("&overdue=true")}>
          <StatTile label="Past SLA" tone="danger" icon={<AlarmClock className="h-3.5 w-3.5" />} value={s ? compact(s.overdue) : "–"} hint="Open beyond remediation SLA" />
        </Link>
        <StatTile
          label="Mean time to remediate"
          icon={<Timer className="h-3.5 w-3.5" />}
          value={s?.mttr_days_overall != null ? `${s.mttr_days_overall} d` : "–"}
          hint={s ? `${fmtNum(s.resolved_last_30d)} resolved · ${fmtNum(s.new_last_30d)} new in 30d` : undefined}
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Panel title="Open findings by severity" subtitle={`Daily snapshot · last ${days} days`}>
            {trends.data ? <OpenTrendChart data={trends.data.open_by_severity} /> : <ChartPlaceholder />}
          </Panel>
        </div>
        <Panel title="Current open exposure" subtitle="Open and in-progress findings">
          {s ? (
            <>
              <SeverityBreakdown counts={s.open_by_severity} assetId={assetId} />
              <div className="mt-5 border-t border-line pt-4">
                <h3 className="mb-2 text-xs font-medium text-ink2">All findings by status</h3>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
                  {STATUSES.map((st) => (
                    <div key={st} className="flex items-center justify-between">
                      <dt className="text-ink2">{STATUS_LABEL[st]}</dt>
                      <dd className="tabular font-medium">{fmtNum(s.by_status[st])}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            </>
          ) : (
            <ChartPlaceholder />
          )}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Panel title="Remediation flow" subtitle={`New vs closed findings per ${trends.data?.bucket ?? "period"}`}>
            {trends.data ? <FlowChart data={trends.data.new_vs_closed} bucket={trends.data.bucket} /> : <ChartPlaceholder />}
          </Panel>
        </div>
        <Panel title="MTTR by severity" subtitle="Days from first detection to resolution">
          {s ? (
            <table className="w-full text-sm">
              <tbody>
                {(["critical", "high", "medium", "low"] as const).map((sev) => (
                  <tr key={sev} className="border-b border-line last:border-0">
                    <td className="py-2 capitalize text-ink2">{sev}</td>
                    <td className="tabular py-2 text-right font-medium">{s.mttr_days[sev] != null ? `${s.mttr_days[sev]} d` : "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <ChartPlaceholder />
          )}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
        {!assetId && (
          <Panel title="Riskiest assets" subtitle="Weighted open severity × business criticality" action={<Link className="text-xs text-accent hover:underline" to="/assets">All assets</Link>}>
            <ul className="divide-y divide-line">
              {topAssets.data?.map((a) => (
                <li key={a.id} className="py-2">
                  <Link to={`/assets/${a.id}`} className="group block">
                    <div className="flex items-center justify-between gap-2 text-sm">
                      <span className="truncate font-medium group-hover:text-accent">{a.name}</span>
                      <span className="tabular shrink-0 text-xs text-ink2">
                        risk <span className="font-semibold text-ink">{a.risk_score}</span> · {a.open} open
                      </span>
                    </div>
                    <SeverityBar className="mt-1.5" counts={{ ...a, info: 0 }} />
                  </Link>
                </li>
              ))}
              {topAssets.data?.length === 0 && <li className="py-6 text-center text-sm text-muted">No open findings</li>}
            </ul>
          </Panel>
        )}
        {can("manager") && !!approvals.data?.length && (
          <Panel title="Awaiting your approval" subtitle="Risk-acceptance requests">
            <ul className="divide-y divide-line">
              {approvals.data.slice(0, 6).map((r) => (
                <li key={r.id} className="py-1.5 text-sm">
                  <Link to={`/findings/${r.finding_id}`} className="block truncate font-medium hover:text-accent">
                    {r.finding_title}
                  </Link>
                  <span className="text-xs text-ink2">
                    {r.asset.name} · {r.severity} · asked by {r.requested_by ? r.requested_by.full_name || r.requested_by.email : "somebody"}{" "}
                    {relTime(r.created_at)}
                  </span>
                </li>
              ))}
            </ul>
            {approvals.data.length > 6 && <p className="mt-2 text-[11px] text-muted">and {approvals.data.length - 6} more</p>}
          </Panel>
        )}
        {!assetId && coverage.data && coverage.data.assets > 0 && (
          <Panel title="Scan coverage" subtitle={`Assets without a scan in the last ${STALE_DAYS} days`}>
            <p className="mb-2 text-sm">
              <span className="font-semibold">{fmtNum(coverage.data.covered)}</span>
              <span className="text-ink2"> of {fmtNum(coverage.data.assets)} assets scanned recently</span>
              {coverage.data.never_scanned > 0 && <span className="text-danger"> · {fmtNum(coverage.data.never_scanned)} never</span>}
            </p>
            <ul className="divide-y divide-line">
              {coverage.data.uncovered.slice(0, 6).map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-2 py-1.5 text-sm">
                  <Link to={`/assets/${a.id}`} className="truncate font-medium hover:text-accent">
                    {a.name}
                  </Link>
                  <span className="shrink-0 text-xs text-ink2">
                    {a.last_scan_at ? `last scanned ${relTime(a.last_scan_at)}` : "never scanned"}
                  </span>
                </li>
              ))}
              {coverage.data.uncovered.length === 0 && (
                <li className="py-6 text-center text-sm text-muted">Every asset was scanned recently</li>
              )}
            </ul>
            {coverage.data.without_sca > 0 && (
              <p className="mt-2 text-[11px] text-muted">
                {fmtNum(coverage.data.without_sca)} asset{coverage.data.without_sca === 1 ? " has" : "s have"} never had a
                dependency (SCA) scan.
              </p>
            )}
          </Panel>
        )}
        <Panel
          title={`OWASP Top 10 (${owasp.data?.owasp.edition ?? "2021"})`}
          subtitle="Open findings by category"
          action={
            <Link className="text-xs text-accent hover:underline" to="/reports">
              Full report
            </Link>
          }
        >
          <ul className="divide-y divide-line">
            {owasp.data?.owasp.categories
              .filter((cat) => cat.open > 0)
              .map((cat) => (
                <li key={cat.id} className="flex items-center justify-between gap-2 py-1.5 text-sm">
                  <span className="min-w-0 truncate">
                    <span className="font-mono text-xs text-muted">{cat.id}</span> {cat.title}
                  </span>
                  <span className="tabular shrink-0 text-xs text-ink2">
                    <span className="font-semibold text-ink">{cat.open}</span>
                    {cat.critical_high > 0 && ` · ${cat.critical_high} crit/high`}
                  </span>
                </li>
              ))}
            {owasp.data?.owasp.categories.every((cat) => cat.open === 0) && (
              <li className="py-6 text-center text-sm text-muted">Nothing open in any category</li>
            )}
          </ul>
          {owasp.data && owasp.data.owasp.unmapped > 0 && (
            <p className="mt-2 text-[11px] text-muted">
              {owasp.data.owasp.unmapped} of {owasp.data.owasp.open_total} open findings carry no CWE that
              OWASP maps.
            </p>
          )}
        </Panel>
        <Panel title="Top weaknesses (CWE)" subtitle="Across open findings">
          <RankList
            items={topCwes.data?.map((c) => ({ key: c.cwe, label: c.cwe, value: c.count, to: `/findings?cwe=${c.cwe}&status=open&status=in_progress` }))}
          />
        </Panel>
        <Panel title="Most vulnerable packages" subtitle="Open SCA findings, critical/high first">
          <RankList
            items={topPkgs.data?.map((p) => ({
              key: `${p.ecosystem}:${p.package}`,
              label: p.package,
              sub: `${p.ecosystem ?? "?"} · ${p.critical_high} crit/high · ${p.assets} asset${p.assets === 1 ? "" : "s"}`,
              value: p.count,
              to: `/findings?package=${encodeURIComponent(p.package)}&status=open&status=in_progress`,
            }))}
          />
        </Panel>
        <Panel title="Recent scans" action={<Link className="text-xs text-accent hover:underline" to="/scans">All scans</Link>}>
          <ul className="divide-y divide-line">
            {scans.data?.items.map((sc) => (
              <li key={sc.id} className="flex items-center justify-between gap-2 py-2 text-sm">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <TypeBadge type={sc.scan_type} />
                    <span className="truncate font-medium">{sc.tool_name}</span>
                  </div>
                  <div className="truncate text-xs text-muted">
                    {sc.asset.name} · {relTime(sc.created_at)}
                  </div>
                </div>
                <span className="tabular shrink-0 text-xs text-ink2">
                  +{sc.new_count} new · {sc.total_count} total
                </span>
              </li>
            ))}
            {scans.data?.items.length === 0 && <li className="py-6 text-center text-sm text-muted">No scans yet</li>}
          </ul>
        </Panel>
      </div>
      <UploadDialog open={uploading} onClose={() => setUploading(false)} />
    </>
  );
}

function ChartPlaceholder() {
  return (
    <div className="flex h-64 items-center justify-center">
      <Spinner />
    </div>
  );
}

function RankList({ items }: { items?: { key: string; label: string; sub?: string; value: number; to: string }[] }) {
  if (!items) return <Spinner />;
  if (!items.length) return <p className="py-6 text-center text-sm text-muted">Nothing to show</p>;
  const max = Math.max(...items.map((i) => i.value));
  return (
    <ul className="space-y-2">
      {items.map((i) => (
        <li key={i.key}>
          <Link to={i.to} className="group block">
            <div className="flex items-baseline justify-between gap-2 text-sm">
              <span className="truncate font-medium group-hover:text-accent">{i.label}</span>
              <span className="tabular shrink-0 text-xs font-medium">{fmtNum(i.value)}</span>
            </div>
            {i.sub && <div className="truncate text-xs text-muted">{i.sub}</div>}
            <div className="mt-1 h-1.5 rounded-r-[4px] bg-accent/80" style={{ width: `${(i.value / max) * 100}%` }} />
          </Link>
        </li>
      ))}
    </ul>
  );
}
