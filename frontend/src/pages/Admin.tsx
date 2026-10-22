import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { RotateCcw, ScrollText } from "lucide-react";
import { request } from "../api/typed";

import { useToast } from "../components/Toaster";
import { EmptyState, ErrorBox, PageHeader, Pagination, Spinner, StatTile, Tabs, tabPanel } from "../components/ui";
import { describeChanges } from "../lib/audit";
import { fmtDateTime, fmtNum, relTime } from "../lib/format";
import { useClampPage, useUrlParams } from "../lib/urlState";

const PAGE_SIZE = 50;

const TABS = [
  { key: "audit", label: "Audit log" },
  { key: "jobs", label: "Background jobs" },
] as const;
type Tab = (typeof TABS)[number]["key"];

const ACTION_GROUPS = [
  { value: "", label: "All actions" },
  { value: "auth.", label: "Sign-in & sessions" },
  { value: "user.", label: "Users" },
  { value: "asset.", label: "Assets" },
  { value: "token.", label: "API tokens" },
  { value: "job.", label: "Background jobs" },
];

const ACTION_LABEL: Record<string, string> = {
  "auth.login": "Signed in",
  "auth.login_failed": "Failed sign-in",
  "auth.logout_all": "Signed out everywhere",
  "auth.password_change": "Changed password",
  "user.create": "Created user",
  "user.update": "Updated user",
  "user.delete": "Deleted user",
  "asset.create": "Created asset",
  "asset.update": "Updated asset",
  "asset.delete": "Deleted asset",
  "token.create": "Created API token",
  "token.revoke": "Revoked API token",
  "job.retry": "Retried job",
};

const JOB_STATUSES = ["queued", "running", "done", "dead"] as const;

function AuditTab() {
  const { params, update, page } = useUrlParams();
  const action = params.get("action") ?? "";
  const list = useQuery({
    queryKey: ["admin", "audit", action, page],
    queryFn: ({ signal }) =>
      request("get", "/api/v1/admin/audit", { signal, query: { ...(action ? { action } : {}), page, page_size: PAGE_SIZE } }),
    placeholderData: keepPreviousData,
  });
  useClampPage(page, PAGE_SIZE, list.data?.total, update, list.isPlaceholderData);

  return (
    <>
      <div className="mb-3 flex items-center gap-2">
        <select className="input w-auto" aria-label="Action" value={action} onChange={(e) => update({ action: e.target.value || null })}>
          {ACTION_GROUPS.map((g) => (
            <option key={g.value} value={g.value}>
              {g.label}
            </option>
          ))}
        </select>
      </div>
      <ErrorBox error={list.error} />
      <div className="card overflow-hidden">
        {list.isLoading ? (
          <div className="flex justify-center py-12">
            <Spinner />
          </div>
        ) : !list.data?.items.length ? (
          <EmptyState icon={<ScrollText className="h-6 w-6" />} title="No audit entries">
            Sign-ins and changes to users, assets and API tokens appear here.
          </EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-line bg-page/50">
                  <tr>
                    <th className="th">When</th>
                    <th className="th">Actor</th>
                    <th className="th">Action</th>
                    <th className="th">Target</th>
                    <th className="th">Details</th>
                    <th className="th">IP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {list.data.items.map((e) => (
                    <tr key={e.id}>
                      <td className="td whitespace-nowrap text-xs text-ink2" title={fmtDateTime(e.created_at)}>
                        {relTime(e.created_at)}
                      </td>
                      <td className="td text-xs">{e.actor_email ?? <span className="text-muted">system / anonymous</span>}</td>
                      <td className={clsx("td whitespace-nowrap", e.action === "auth.login_failed" && "text-danger")}>
                        {ACTION_LABEL[e.action] ?? e.action}
                      </td>
                      <td className="td text-xs">{e.target_label ?? "–"}</td>
                      <td className="td text-xs text-ink2">
                        {describeChanges(e.changes).map((line) => (
                          <div key={line}>{line}</div>
                        ))}
                      </td>
                      <td className="td font-mono text-xs text-muted">{e.ip ?? "–"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={(p) => update({ page: String(p) }, true)} />
          </>
        )}
      </div>
    </>
  );
}

function JobsTab() {
  const { params, update, page } = useUrlParams();
  const qc = useQueryClient();
  const toast = useToast();
  const status = params.get("status") ?? "";
  const stats = useQuery({ queryKey: ["admin", "jobs", "stats"], queryFn: ({ signal }) => request("get", "/api/v1/admin/jobs/stats", { signal }), refetchInterval: 15_000 });
  const list = useQuery({
    queryKey: ["admin", "jobs", status, page],
    queryFn: ({ signal }) => request("get", "/api/v1/admin/jobs", { signal, query: { ...(status ? { status } : {}), page, page_size: PAGE_SIZE } }),
    placeholderData: keepPreviousData,
    refetchInterval: 15_000,
  });
  useClampPage(page, PAGE_SIZE, list.data?.total, update, list.isPlaceholderData);
  const retry = useMutation({
    mutationFn: (id: number) => request("post", "/api/v1/admin/jobs/{job_id}/retry", { params: { job_id: Number(id) } }),
    onSuccess: (j) => {
      toast(`Job #${j.id} requeued`);
      qc.invalidateQueries({ queryKey: ["admin", "jobs"] });
    },
  });

  // A due job waiting for more than a few minutes means no worker is draining the queue.
  const oldest = stats.data?.oldest_queued_at;
  const stalled = !!oldest && Date.now() - new Date(oldest).getTime() > 5 * 60_000;

  return (
    <>
      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {JOB_STATUSES.map((s) => (
          <StatTile
            key={s}
            label={s[0].toUpperCase() + s.slice(1)}
            value={fmtNum(stats.data?.counts[s])}
            tone={s === "dead" && stats.data?.counts.dead ? "danger" : undefined}
            hint={s === "done" && stats.data?.last_finished_at ? `last ${relTime(stats.data.last_finished_at)}` : undefined}
          />
        ))}
      </div>
      {stalled && (
        <div className="mb-3 rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger" role="alert">
          The oldest queued job has been waiting since {relTime(oldest)}. Check that the worker is running
          (<code className="font-mono text-xs">python -m app.cli worker</code>).
        </div>
      )}
      <div className="mb-3 flex items-center gap-2">
        <select className="input w-auto" aria-label="Status" value={status} onChange={(e) => update({ status: e.target.value || null })}>
          <option value="">All statuses</option>
          {JOB_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      <ErrorBox error={list.error ?? stats.error ?? retry.error} />
      <div className="card overflow-hidden">
        {list.isLoading ? (
          <div className="flex justify-center py-12">
            <Spinner />
          </div>
        ) : !list.data?.items.length ? (
          <EmptyState title="No jobs">Periodic tasks and notifications appear here once the worker runs them.</EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-line bg-page/50">
                  <tr>
                    <th className="th">Job</th>
                    <th className="th">Status</th>
                    <th className="th">Attempts</th>
                    <th className="th">Created</th>
                    <th className="th">Next run / finished</th>
                    <th className="th">Last error</th>
                    <th className="th" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {list.data.items.map((j) => (
                    <tr key={j.id}>
                      <td className="td">
                        <div className="font-mono text-xs">{j.kind}</div>
                        <div className="text-xs text-muted">#{j.id}</div>
                      </td>
                      <td className={clsx("td text-xs", j.status === "dead" ? "text-danger" : j.status === "done" ? "text-good" : "text-ink2")}>
                        {j.status}
                      </td>
                      <td className="td tabular text-xs">
                        {j.attempts} / {j.max_attempts}
                      </td>
                      <td className="td whitespace-nowrap text-xs text-ink2" title={fmtDateTime(j.created_at)}>
                        {relTime(j.created_at)}
                      </td>
                      <td className="td whitespace-nowrap text-xs text-ink2">
                        {j.finished_at ? fmtDateTime(j.finished_at) : j.status === "queued" ? fmtDateTime(j.run_after) : "–"}
                      </td>
                      <td className="td max-w-xs truncate font-mono text-xs text-muted" title={j.last_error ?? undefined}>
                        {j.last_error ?? "–"}
                      </td>
                      <td className="td text-right">
                        {j.status === "dead" && (
                          <button
                            className="btn-ghost p-1.5"
                            aria-label={`Retry job ${j.id}`}
                            title="Retry"
                            disabled={retry.isPending}
                            onClick={() => retry.mutate(j.id)}
                          >
                            <RotateCcw className="h-4 w-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={(p) => update({ page: String(p) }, true)} />
          </>
        )}
      </div>
    </>
  );
}

export default function Admin() {
  const { params, update } = useUrlParams();
  const tab: Tab = params.get("tab") === "jobs" ? "jobs" : "audit";
  return (
    <>
      <PageHeader title="System" subtitle="Audit trail of administrative actions and background job health" />
      <Tabs
        id="admin"
        label="System"
        className="mb-4 border-b border-line"
        tabs={TABS}
        active={tab}
        // Filters belong to one tab, so switching resets them.
        onChange={(key) => update({ tab: key === "audit" ? null : key, action: null, status: null })}
      />
      <div {...tabPanel("admin", tab)}>{tab === "audit" ? <AuditTab /> : <JobsTab />}</div>
    </>
  );
}
