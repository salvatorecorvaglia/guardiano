import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Mail, Pencil, Plus, Send, Trash2 } from "lucide-react";
import { useState } from "react";
import { useDirectory, useMeta, useProducts } from "../api/queries";
import { request } from "../api/typed";
import type { ReportSchedule } from "../api/types";
import { fmtDateTime } from "../lib/format";
import { useToast } from "./Toaster";
import { ConfirmDialog, ErrorBox, Field, Modal, Spinner } from "./ui";

type Draft = { name: string; frequency: "weekly" | "monthly"; product_id: string; recipient_ids: number[]; enabled: boolean };
const EMPTY: Draft = { name: "", frequency: "weekly", product_id: "", recipient_ids: [], enabled: true };

/** Security reports emailed weekly or monthly; each recipient's copy covers only what they can see. */
export default function ReportSchedules() {
  const qc = useQueryClient();
  const toast = useToast();
  const meta = useMeta();
  const directory = useDirectory();
  const products = useProducts();
  const list = useQuery({ queryKey: ["report-schedules"], queryFn: ({ signal }) => request("get", "/api/v1/report-schedules", { signal }) });
  const [editing, setEditing] = useState<ReportSchedule | "new" | null>(null);
  const [deleting, setDeleting] = useState<ReportSchedule | null>(null);
  const [draft, setDraft] = useState<Draft>(EMPTY);

  const save = useMutation({
    mutationFn: () => {
      const body = { ...draft, name: draft.name.trim(), product_id: draft.product_id ? Number(draft.product_id) : null };
      return editing === "new" || !editing
        ? request("post", "/api/v1/report-schedules", { body })
        : request("put", "/api/v1/report-schedules/{schedule_id}", { params: { schedule_id: Number(editing.id) }, body });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["report-schedules"] });
      toast("Report schedule saved");
      setEditing(null);
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => request("delete", "/api/v1/report-schedules/{schedule_id}", { params: { schedule_id: Number(id) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["report-schedules"] });
      setDeleting(null);
    },
  });
  const sendNow = useMutation({
    mutationFn: (id: number) => request("post", "/api/v1/report-schedules/{schedule_id}/send", { params: { schedule_id: Number(id) } }),
    onSuccess: (r) => toast(`Sending to ${r.queued} recipient${r.queued === 1 ? "" : "s"}`),
  });
  const open = (s: ReportSchedule | "new") => {
    save.reset();
    setDraft(
      s === "new"
        ? EMPTY
        : { name: s.name, frequency: s.frequency as Draft["frequency"], product_id: s.product_id ? String(s.product_id) : "", recipient_ids: s.recipient_ids, enabled: s.enabled },
    );
    setEditing(s);
  };
  const who = (ids: number[]) =>
    ids.map((id) => directory.data?.find((u) => u.id === id)).filter(Boolean).map((u) => u!.full_name || u!.email).join(", ");

  return (
    <section className="card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold">Scheduled reports</h2>
          <p className="text-xs text-muted">
            The Reports page's headline figures, emailed to Guardiano users. Each copy covers only the assets its recipient can see.
            {meta.data && !meta.data.email_enabled && " Email is not configured, so nothing is sent yet."}
          </p>
        </div>
        <button className="btn-secondary" onClick={() => open("new")}>
          <Plus className="h-4 w-4" /> New schedule
        </button>
      </div>
      <ErrorBox error={list.error || sendNow.error} />
      {list.isLoading ? (
        <div className="flex justify-center py-6">
          <Spinner />
        </div>
      ) : (
        <ul className="divide-y divide-line border-t border-line">
          {list.data?.map((s) => (
            <li key={s.id} className={`flex flex-wrap items-center gap-3 px-4 py-2 text-sm ${s.enabled ? "" : "opacity-60"}`}>
              <Mail className="h-4 w-4 text-muted" />
              <div className="min-w-0 flex-1">
                <div className="font-medium">{s.name}</div>
                <div className="truncate text-xs text-muted">
                  {s.frequency}
                  {s.product_id && ` · ${products.data?.find((p) => p.id === s.product_id)?.name ?? "product"}`} · to {who(s.recipient_ids) || `${s.recipient_ids.length} people`}
                  {s.last_sent_at && ` · last sent ${fmtDateTime(s.last_sent_at)}`}
                </div>
              </div>
              <button className="btn-ghost p-1.5" aria-label={`Send ${s.name} now`} title="Send now" disabled={!meta.data?.email_enabled || sendNow.isPending} onClick={() => sendNow.mutate(s.id)}>
                <Send className="h-4 w-4" />
              </button>
              <button className="btn-ghost p-1.5" aria-label={`Edit ${s.name}`} onClick={() => open(s)}>
                <Pencil className="h-4 w-4" />
              </button>
              <button className="btn-ghost p-1.5 hover:text-danger" aria-label={`Delete ${s.name}`} onClick={() => setDeleting(s)}>
                <Trash2 className="h-4 w-4" />
              </button>
            </li>
          ))}
          {list.data?.length === 0 && <li className="px-4 py-6 text-center text-sm text-muted">No scheduled reports</li>}
        </ul>
      )}
      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={editing === "new" ? "New scheduled report" : "Edit scheduled report"}
        footer={
          <>
            <button className="btn-secondary" onClick={() => setEditing(null)}>
              Cancel
            </button>
            <button className="btn-primary" disabled={!draft.name.trim() || !draft.recipient_ids.length || save.isPending} onClick={() => save.mutate()}>
              Save
            </button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name">
            <input className="input" value={draft.name} maxLength={200} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Weekly security report" />
          </Field>
          <Field label="How often" hint="Weekly on Mondays, monthly on the 1st">
            <select className="input" value={draft.frequency} onChange={(e) => setDraft({ ...draft, frequency: e.target.value as Draft["frequency"] })}>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </Field>
          <Field label="About">
            <select className="input" value={draft.product_id} onChange={(e) => setDraft({ ...draft, product_id: e.target.value })}>
              <option value="">Everything the recipient can see</option>
              {products.data?.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </Field>
          <label className="flex items-center gap-2 self-end pb-2 text-sm">
            <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
            Enabled
          </label>
        </div>
        <fieldset>
          <legend className="label">Recipients</legend>
          <div className="grid max-h-48 gap-1 overflow-y-auto sm:grid-cols-2">
            {directory.data?.map((u) => (
              <label key={u.id} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={draft.recipient_ids.includes(u.id)}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      recipient_ids: e.target.checked ? [...draft.recipient_ids, u.id] : draft.recipient_ids.filter((x) => x !== u.id),
                    })
                  }
                />
                {u.full_name || u.email}
              </label>
            ))}
          </div>
        </fieldset>
        <ErrorBox error={save.error} />
      </Modal>
      <ConfirmDialog
        open={!!deleting}
        title="Delete scheduled report"
        confirmLabel="Delete"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      >
        Stop sending <span className="font-medium">{deleting?.name}</span>?
      </ConfirmDialog>
    </section>
  );
}
