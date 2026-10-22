import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { Pencil, Plus, Send, Trash2, Webhook as WebhookIcon } from "lucide-react";
import { useState } from "react";
import { useAssetOptions } from "../api/queries";
import { type RequestBody, request } from "../api/typed";
import type { Severity, Webhook, WebhookCreated } from "../api/types";
import { fmtDateTime, relTime, SEVERITIES, SEVERITY_LABEL } from "../lib/format";
import { useToast } from "./Toaster";
import { ConfirmDialog, EmptyState, ErrorBox, Field, Modal, Spinner } from "./ui";

const EVENTS = [
  { value: "scan.completed", label: "Scan completed", hint: "Every ingested report, previews included" },
  { value: "gate.failed", label: "Quality gate failed", hint: "A scan broke its gate" },
  { value: "finding.reopened", label: "Finding reopened", hint: "A resolved finding came back" },
  { value: "finding.status_changed", label: "Status changed", hint: "Somebody triaged a finding" },
  { value: "finding.assigned", label: "Finding assigned", hint: "Somebody assigned or unassigned a finding" },
  { value: "finding.kev_added", label: "Now known exploited", hint: "CISA added an open finding's CVE to KEV" },
  { value: "finding.risk_acceptance_expiring", label: "Acceptance ending", hint: "A risk acceptance is about to end" },
  { value: "sla.breached", label: "SLA breached", hint: "A finding passed its deadline" },
] as const;

const FORMATS = [
  { value: "guardiano", label: "Guardiano JSON", hint: "Full event payload for your own receiver" },
  { value: "slack", label: "Slack", hint: "Incoming webhook URL" },
  { value: "teams", label: "Microsoft Teams", hint: "Workflow / connector URL" },
] as const;

type Draft = {
  name: string;
  url: string;
  format: NonNullable<RequestBody<"/api/v1/webhooks">["format"]>;
  events: RequestBody<"/api/v1/webhooks">["events"];
  min_severity: Severity;
  asset_id: string;
};

const EMPTY: Draft = { name: "", url: "", format: "slack", events: ["gate.failed"], min_severity: "high", asset_id: "" };

function SecretNotice({ secret }: { secret: string }) {
  return (
    <div className="rounded-lg border border-line bg-page p-3">
      <p className="text-sm font-medium">Signing secret</p>
      <p className="mb-2 text-xs text-muted">
        Copy it now; it is not shown again. Payloads are signed with it in <code className="font-mono">X-Guardiano-Signature</code>.
      </p>
      <pre className="overflow-x-auto rounded border border-line bg-raised p-2 font-mono text-xs">{secret}</pre>
    </div>
  );
}

function WebhookForm({ webhook, onClose }: { webhook?: Webhook; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const assets = useAssetOptions();
  const [draft, setDraft] = useState<Draft>(
    webhook
      ? {
          name: webhook.name,
          url: webhook.url,
          format: webhook.format as Draft["format"],
          events: webhook.events as Draft["events"],
          min_severity: webhook.min_severity as Severity,
          asset_id: webhook.asset ? String(webhook.asset.id) : "",
        }
      : EMPTY,
  );
  const [secret, setSecret] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () => {
      const body = { ...draft, asset_id: draft.asset_id ? Number(draft.asset_id) : null };
      return webhook
        ? request("patch", "/api/v1/webhooks/{webhook_id}", { params: { webhook_id: Number(webhook.id) }, body })
        : request("post", "/api/v1/webhooks", { body });
    },
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: ["webhooks"] });
      // Only the create response carries the signing secret, and only once.
      const created = (saved as WebhookCreated).secret;
      if (created) {
        setSecret(created);
        toast("Webhook created");
      } else {
        toast("Webhook saved");
        onClose();
      }
    },
  });

  const valid = draft.name.trim() && /^https?:\/\//.test(draft.url) && draft.events.length > 0;

  return (
    <Modal
      open
      onClose={onClose}
      wide
      title={webhook ? `Edit ${webhook.name}` : "New webhook"}
      footer={
        secret ? (
          <button className="btn-primary" onClick={onClose}>
            Done
          </button>
        ) : (
          <>
            <button className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button className="btn-primary" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
              Save webhook
            </button>
          </>
        )
      }
    >
      {secret ? (
        <SecretNotice secret={secret} />
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Name">
              <input className="input" value={draft.name} maxLength={100} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Security channel" />
            </Field>
            <Field label="Format">
              <select className="input" value={draft.format} onChange={(e) => setDraft({ ...draft, format: e.target.value as Draft["format"] })}>
                {FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="URL" hint={FORMATS.find((f) => f.value === draft.format)?.hint}>
            <input className="input font-mono text-xs" value={draft.url} onChange={(e) => setDraft({ ...draft, url: e.target.value })} placeholder="https://hooks.slack.com/services/…" />
          </Field>
          <fieldset>
            <legend className="label">Events</legend>
            <div className="space-y-1">
              {EVENTS.map((e) => (
                <label key={e.value} className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={draft.events.includes(e.value)}
                    onChange={(ev) =>
                      setDraft({
                        ...draft,
                        events: ev.target.checked ? [...draft.events, e.value] : draft.events.filter((x) => x !== e.value),
                      })
                    }
                  />
                  <span>
                    {e.label} <span className="block text-xs text-muted">{e.hint}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Minimum severity" hint="For finding events; scan and gate events always arrive">
              <select className="input" value={draft.min_severity} onChange={(e) => setDraft({ ...draft, min_severity: e.target.value as Severity })}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {SEVERITY_LABEL[s]}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Asset">
              <select className="input" value={draft.asset_id} onChange={(e) => setDraft({ ...draft, asset_id: e.target.value })}>
                <option value="">Every asset</option>
                {assets.data?.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <ErrorBox error={save.error} />
        </>
      )}
    </Modal>
  );
}

function Deliveries({ webhook }: { webhook: Webhook }) {
  const list = useQuery({
    queryKey: ["webhooks", webhook.id, "deliveries"],
    queryFn: ({ signal }) => request("get", "/api/v1/webhooks/{webhook_id}/deliveries", { params: { webhook_id: Number(webhook.id) }, signal, query: { page_size: 10 } }),
    refetchInterval: 10_000,
  });
  if (list.isLoading) return <Spinner />;
  if (!list.data?.items.length) return <p className="text-xs text-muted">Nothing sent yet.</p>;
  return (
    <ul className="space-y-1 text-xs">
      {list.data.items.map((d) => (
        <li key={d.id} className="flex items-center gap-2">
          <span className={clsx("font-medium", d.delivered_at ? "text-good" : d.error ? "text-danger" : "text-ink2")}>
            {d.delivered_at ? "sent" : d.error ? "failed" : "queued"}
          </span>
          <span className="font-mono">{d.event}</span>
          <span className="text-muted" title={fmtDateTime(d.created_at)}>
            {relTime(d.created_at)}
          </span>
          {d.attempts > 1 && <span className="text-muted">· {d.attempts} attempts</span>}
          {d.error && <span className="truncate text-danger">· {d.error}</span>}
        </li>
      ))}
    </ul>
  );
}

/** Outbound webhooks: admin-only configuration, delivery log and a test button. */
export default function Webhooks() {
  const qc = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<Webhook | "new" | null>(null);
  const [deleting, setDeleting] = useState<Webhook | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const hooks = useQuery({ queryKey: ["webhooks"], queryFn: ({ signal }) => request("get", "/api/v1/webhooks", { signal }) });

  const test = useMutation({
    mutationFn: (id: number) => request("post", "/api/v1/webhooks/{webhook_id}/test", { params: { webhook_id: Number(id) } }),
    onSuccess: (_d, id) => {
      toast("Test event queued");
      setExpanded(id);
      setTimeout(() => qc.invalidateQueries({ queryKey: ["webhooks"] }), 1500);
    },
  });
  const del = useMutation({
    mutationFn: (id: number) => request("delete", "/api/v1/webhooks/{webhook_id}", { params: { webhook_id: Number(id) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["webhooks"] });
      toast(`Deleted ${deleting?.name}`);
      setDeleting(null);
    },
  });

  return (
    <section className="card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold">Webhooks</h2>
          <p className="text-xs text-muted">
            Send scans, gate failures and finding events to Slack, Teams or your own endpoint. Delivery is
            signed, retried, and never delays an upload.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setEditing("new")}>
          <Plus className="h-4 w-4" /> New webhook
        </button>
      </div>
      <ErrorBox error={hooks.error ?? test.error} />
      {hooks.isLoading ? (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      ) : !hooks.data?.length ? (
        <EmptyState icon={<WebhookIcon className="h-6 w-6" />} title="No webhooks yet">
          Add one to get a message in Slack or Teams when a quality gate fails or a finding is reopened.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line border-t border-line">
          {hooks.data.map((h) => (
            <li key={h.id} className={clsx("px-4 py-3", !h.enabled && "opacity-60")}>
              <div className="flex flex-wrap items-center gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{h.name}</span>
                    <span className="rounded bg-ink/5 px-1.5 py-0.5 text-xs">{h.format}</span>
                    {!h.enabled && <span className="text-xs text-muted">disabled</span>}
                    {h.last_status != null && (
                      <span className={clsx("text-xs", h.last_error ? "text-danger" : "text-good")}>
                        last {h.last_error ? `failed (${h.last_error})` : "ok"} · {relTime(h.last_delivery_at)}
                      </span>
                    )}
                  </div>
                  <div className="truncate font-mono text-xs text-muted">{h.url}</div>
                  <div className="text-xs text-ink2">
                    {h.events.join(", ")} · ≥ {h.min_severity} · {h.asset ? h.asset.name : "every asset"}
                  </div>
                </div>
                <button className="btn-ghost p-1.5" title="Send test event" aria-label={`Send test event to ${h.name}`} disabled={test.isPending} onClick={() => test.mutate(h.id)}>
                  <Send className="h-4 w-4" />
                </button>
                <button className="btn-ghost p-1.5" aria-label={`Edit ${h.name}`} onClick={() => setEditing(h)}>
                  <Pencil className="h-4 w-4" />
                </button>
                <button className="btn-ghost p-1.5 hover:text-danger" aria-label={`Delete ${h.name}`} onClick={() => setDeleting(h)}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
              <button className="mt-1 text-xs text-accent hover:underline" onClick={() => setExpanded(expanded === h.id ? null : h.id)}>
                {expanded === h.id ? "Hide deliveries" : "Recent deliveries"}
              </button>
              {expanded === h.id && (
                <div className="mt-2">
                  <Deliveries webhook={h} />
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {editing && <WebhookForm webhook={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={!!deleting}
        title="Delete webhook"
        confirmLabel="Delete webhook"
        pending={del.isPending}
        error={del.error}
        onConfirm={() => deleting && del.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      >
        Delete <span className="font-medium">{deleting?.name}</span>? Its delivery history goes with it.
      </ConfirmDialog>
    </section>
  );
}
