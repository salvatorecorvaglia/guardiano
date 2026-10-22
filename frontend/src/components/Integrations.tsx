import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { Pencil, Plug, Plus, Ticket as TicketIcon, Trash2 } from "lucide-react";
import { useState } from "react";
import { useAssetOptions } from "../api/queries";
import { type RequestBody, request } from "../api/typed";
import type { Integration, IntegrationCheck, Severity } from "../api/types";
import { relTime, SEVERITIES, SEVERITY_LABEL } from "../lib/format";
import { useToast } from "./Toaster";
import { ConfirmDialog, EmptyState, ErrorBox, Field, Modal, Spinner } from "./ui";

const KINDS = [
  { value: "jira", label: "Jira", url: "https://your-org.atlassian.net", project: "Project key, e.g. SEC" },
  { value: "github", label: "GitHub Issues", url: "https://api.github.com", project: "owner/repo" },
  { value: "gitlab", label: "GitLab Issues", url: "https://gitlab.com", project: "group/project" },
] as const;

type Draft = {
  kind: RequestBody<"/api/v1/integrations">["kind"];
  name: string;
  base_url: string;
  project: string;
  username: string;
  issue_type: string;
  labels: string;
  asset_id: string;
  scm_feedback: boolean;
  close_resolves_finding: boolean;
  done_transition: string;
  reopen_transition: string;
  auto_ticket_min_severity: Severity | "";
  auto_ticket_kev: boolean;
  token: string;
};

const EMPTY: Draft = {
  kind: "jira",
  name: "",
  base_url: "https://your-org.atlassian.net",
  project: "",
  username: "",
  issue_type: "Bug",
  labels: "security",
  asset_id: "",
  scm_feedback: false,
  close_resolves_finding: false,
  done_transition: "",
  reopen_transition: "",
  auto_ticket_min_severity: "",
  auto_ticket_kev: false,
  token: "",
};

function IntegrationForm({ integration, onClose }: { integration?: Integration; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const assets = useAssetOptions();
  const [draft, setDraft] = useState<Draft>(
    integration
      ? {
          kind: integration.kind as Draft["kind"],
          name: integration.name,
          base_url: integration.base_url,
          project: integration.project,
          username: integration.username ?? "",
          issue_type: integration.issue_type ?? "",
          labels: integration.labels.join(", "),
          asset_id: integration.asset ? String(integration.asset.id) : "",
          scm_feedback: integration.scm_feedback,
          close_resolves_finding: integration.close_resolves_finding,
          done_transition: integration.done_transition ?? "",
          reopen_transition: integration.reopen_transition ?? "",
          auto_ticket_min_severity: (integration.auto_ticket_min_severity ?? "") as Severity | "",
          auto_ticket_kev: integration.auto_ticket_kev,
          token: "",
        }
      : EMPTY,
  );
  const kind = KINDS.find((k) => k.value === draft.kind)!;

  const save = useMutation({
    mutationFn: () => {
      const body = {
        ...draft,
        username: draft.username || null,
        issue_type: draft.issue_type || null,
        labels: draft.labels.split(",").map((l) => l.trim()).filter(Boolean),
        asset_id: draft.asset_id ? Number(draft.asset_id) : null,
        // Empty clears a transition on an existing tracker, and is simply absent on a new one.
        done_transition: draft.done_transition.trim() || (integration ? "" : null),
        reopen_transition: draft.reopen_transition.trim() || (integration ? "" : null),
        auto_ticket_min_severity: draft.auto_ticket_min_severity || null,
        ...(draft.token ? { token: draft.token } : {}),
      };
      return integration
        ? request("patch", "/api/v1/integrations/{integration_id}", { params: { integration_id: Number(integration.id) }, body })
        : request("post", "/api/v1/integrations", { body });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations"] });
      toast(integration ? "Tracker saved" : "Tracker added");
      onClose();
    },
  });

  const valid = draft.name.trim() && /^https?:\/\//.test(draft.base_url) && draft.project.trim() && (integration || draft.token);

  return (
    <Modal
      open
      onClose={onClose}
      wide
      title={integration ? `Edit ${integration.name}` : "New issue tracker"}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
            Save tracker
          </button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Tracker">
          <select
            className="input"
            value={draft.kind}
            disabled={!!integration}
            onChange={(e) => {
              const next = KINDS.find((k) => k.value === e.target.value)!;
              setDraft({ ...draft, kind: next.value, base_url: next.url, issue_type: next.value === "jira" ? "Bug" : "" });
            }}
          >
            {KINDS.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Name">
          <input className="input" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Security backlog" />
        </Field>
        <Field label="Base URL">
          <input className="input font-mono text-xs" value={draft.base_url} onChange={(e) => setDraft({ ...draft, base_url: e.target.value })} />
        </Field>
        <Field label="Project" hint={kind.project}>
          <input className="input" value={draft.project} onChange={(e) => setDraft({ ...draft, project: e.target.value })} />
        </Field>
        {draft.kind === "jira" && (
          <>
            <Field label="Account email" hint="Jira Cloud API tokens; leave empty for a Data Center PAT">
              <input className="input" value={draft.username} onChange={(e) => setDraft({ ...draft, username: e.target.value })} />
            </Field>
            <Field label="Issue type">
              <input className="input" value={draft.issue_type} onChange={(e) => setDraft({ ...draft, issue_type: e.target.value })} placeholder="Bug" />
            </Field>
            <Field label="Close with transition" hint="Workflow transition (or target status) used when a finding closes; empty to only comment">
              <input className="input" value={draft.done_transition} onChange={(e) => setDraft({ ...draft, done_transition: e.target.value })} placeholder="Done" />
            </Field>
            <Field label="Reopen with transition" hint="Used when a finding reopens; empty to only comment">
              <input className="input" value={draft.reopen_transition} onChange={(e) => setDraft({ ...draft, reopen_transition: e.target.value })} placeholder="Reopen" />
            </Field>
          </>
        )}
        <Field label="Labels" hint="Comma separated">
          <input className="input" value={draft.labels} onChange={(e) => setDraft({ ...draft, labels: e.target.value })} />
        </Field>
        <Field label="Asset" hint="Limit this tracker to one asset">
          <select className="input" value={draft.asset_id} onChange={(e) => setDraft({ ...draft, asset_id: e.target.value })}>
            <option value="">Offer for every asset</option>
            {assets.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {draft.kind !== "jira" && (
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={draft.scm_feedback}
            onChange={(e) => setDraft({ ...draft, scm_feedback: e.target.checked })}
          />
          <span>
            Report results on commits and pull requests
            <span className="block text-xs text-muted">
              A commit status on every scanned commit, and a comment on the pull request for a scanned
              branch. Branch protection can require it.
            </span>
          </span>
        </label>
      )}
      <div className="flex flex-wrap items-center gap-2 text-sm">
        Open a ticket automatically for new findings
        <select
          className="input w-auto py-1"
          aria-label="Automatic tickets from severity"
          value={draft.auto_ticket_min_severity}
          onChange={(e) => setDraft({ ...draft, auto_ticket_min_severity: e.target.value as Severity | "" })}
        >
          <option value="">never by severity</option>
          {SEVERITIES.filter((s) => s !== "info").map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s].toLowerCase()} and above
            </option>
          ))}
        </select>
        <label className="flex items-center gap-1.5">
          <input type="checkbox" checked={draft.auto_ticket_kev} onChange={(e) => setDraft({ ...draft, auto_ticket_kev: e.target.checked })} />
          or known to be exploited (KEV)
        </label>
      </div>
      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={draft.close_resolves_finding}
          onChange={(e) => setDraft({ ...draft, close_resolves_finding: e.target.checked })}
        />
        <span>
          Resolve a finding when its ticket is closed here
          <span className="block text-xs text-muted">
            Otherwise a closed ticket is only noted on the finding. Needs ticket polling (TRACKER_POLL_HOURS).
          </span>
        </span>
      </label>
      <Field
        label={integration ? "Replace API token" : "API token"}
        hint={integration ? "Leave empty to keep the current token" : "Stored encrypted; never shown again"}
      >
        <input className="input font-mono text-xs" type="password" autoComplete="new-password" value={draft.token} onChange={(e) => setDraft({ ...draft, token: e.target.value })} />
      </Field>
      <ErrorBox error={save.error} />
    </Modal>
  );
}

/** Issue trackers Guardiano can open tickets in. Admin-only. */
export default function Integrations() {
  const qc = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<Integration | "new" | null>(null);
  const [deleting, setDeleting] = useState<Integration | null>(null);
  const [checked, setChecked] = useState<Record<number, IntegrationCheck>>({});
  const list = useQuery({ queryKey: ["integrations"], queryFn: ({ signal }) => request("get", "/api/v1/integrations", { signal }) });

  const check = useMutation({
    mutationFn: (id: number) => request("post", "/api/v1/integrations/{integration_id}/check", { params: { integration_id: Number(id) } }),
    onSuccess: (result, id) => {
      setChecked((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["integrations"] });
    },
  });
  const del = useMutation({
    mutationFn: (id: number) => request("delete", "/api/v1/integrations/{integration_id}", { params: { integration_id: Number(id) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations"] });
      toast(`Deleted ${deleting?.name}`);
      setDeleting(null);
    },
  });

  return (
    <section className="card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold">Issue trackers</h2>
          <p className="text-xs text-muted">
            Open a Jira, GitHub or GitLab ticket straight from a finding. Guardiano comments on the ticket
            when the finding's status changes.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setEditing("new")}>
          <Plus className="h-4 w-4" /> New tracker
        </button>
      </div>
      <ErrorBox error={list.error ?? check.error} />
      {list.isLoading ? (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      ) : !list.data?.length ? (
        <EmptyState icon={<Plug className="h-6 w-6" />} title="No trackers yet">
          Add one to turn findings into tickets your engineers already see.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line border-t border-line">
          {list.data.map((i) => {
            const result = checked[i.id];
            return (
              <li key={i.id} className={clsx("flex flex-wrap items-center gap-2 px-4 py-3", !i.enabled && "opacity-60")}>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <TicketIcon className="h-4 w-4 text-muted" />
                    <span className="font-medium">{i.name}</span>
                    <span className="rounded bg-ink/5 px-1.5 py-0.5 text-xs">{i.kind}</span>
                    {!i.enabled && <span className="text-xs text-muted">disabled</span>}
                  </div>
                  <div className="truncate text-xs text-muted">
                    {i.base_url} · {i.project} · {i.asset ? i.asset.name : "every asset"}
                    {i.scm_feedback && " · reports on commits"}
                    {i.last_used_at && ` · last used ${relTime(i.last_used_at)}`}
                  </div>
                  {result ? (
                    <div className={clsx("text-xs", result.ok ? "text-good" : "text-danger")}>{result.detail}</div>
                  ) : (
                    i.last_error && <div className="truncate text-xs text-danger">{i.last_error}</div>
                  )}
                </div>
                <button className="btn-secondary py-1" disabled={check.isPending} onClick={() => check.mutate(i.id)}>
                  Test
                </button>
                <button className="btn-ghost p-1.5" aria-label={`Edit ${i.name}`} onClick={() => setEditing(i)}>
                  <Pencil className="h-4 w-4" />
                </button>
                <button className="btn-ghost p-1.5 hover:text-danger" aria-label={`Delete ${i.name}`} onClick={() => setDeleting(i)}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </li>
            );
          })}
        </ul>
      )}
      {editing && <IntegrationForm integration={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={!!deleting}
        title="Delete tracker"
        confirmLabel="Delete tracker"
        pending={del.isPending}
        error={del.error}
        onConfirm={() => deleting && del.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      >
        Delete <span className="font-medium">{deleting?.name}</span>? Tickets already opened keep their links
        but stop being updated.
      </ConfirmDialog>
    </section>
  );
}
