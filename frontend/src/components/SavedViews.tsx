import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bookmark, Trash2 } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { request } from "../api/typed";

import { useAuth } from "../auth/AuthContext";
import { canonicalQuery } from "../lib/urlState";
import { useToast } from "./Toaster";
import { ConfirmDialog, ErrorBox, Field, Modal } from "./ui";

/** Saved Findings filters: pick one to apply it, save the current filters, or delete the active view. */
export default function SavedViews({ search }: { search: string }) {
  const { user, can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [name, setName] = useState("");
  const [shared, setShared] = useState(false);
  const views = useQuery({ queryKey: ["views"], queryFn: ({ signal }) => request("get", "/api/v1/views", { signal }) });

  const current = canonicalQuery(search);
  const active = views.data?.find((v) => canonicalQuery(v.query) === current);
  const mine = views.data?.filter((v) => v.user.id === user?.id) ?? [];
  const others = views.data?.filter((v) => v.user.id !== user?.id) ?? [];
  const canDelete = active && (active.user.id === user?.id || (active.shared && can("admin")));

  const save = useMutation({
    mutationFn: () => request("post", "/api/v1/views", { body: { name: name.trim(), query: current, shared } }),
    onSuccess: (v) => {
      qc.invalidateQueries({ queryKey: ["views"] });
      toast(`Saved view "${v.name}"`);
      setSaving(false);
    },
  });
  const del = useMutation({
    mutationFn: (id: number) => request("delete", "/api/v1/views/{view_id}", { params: { view_id: Number(id) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["views"] });
      toast(`Deleted view "${active?.name}"`);
      setDeleting(false);
    },
  });

  return (
    <div className="flex items-center gap-1">
      <select
        className="input w-auto max-w-[220px]"
        aria-label="Saved views"
        value={active ? String(active.id) : ""}
        onChange={(e) => {
          const v = views.data?.find((x) => String(x.id) === e.target.value);
          if (v) navigate(`/findings${v.query ? `?${v.query}` : ""}`);
        }}
      >
        <option value="">{active ? active.name : "Saved views…"}</option>
        {mine.length > 0 && (
          <optgroup label="My views">
            {mine.map((v) => (
              <option key={v.id} value={v.id}>
                {v.name}
                {v.shared ? " (shared)" : ""}
              </option>
            ))}
          </optgroup>
        )}
        {others.length > 0 && (
          <optgroup label="Shared with everyone">
            {others.map((v) => (
              <option key={v.id} value={v.id}>
                {v.name} · {v.user.full_name || v.user.email}
              </option>
            ))}
          </optgroup>
        )}
      </select>
      {canDelete ? (
        <button className="btn-ghost p-1.5" aria-label={`Delete view ${active.name}`} title="Delete this view" onClick={() => setDeleting(true)}>
          <Trash2 className="h-4 w-4" />
        </button>
      ) : (
        <button
          className="btn-ghost p-1.5"
          aria-label="Save current filters as a view"
          title="Save current filters as a view"
          onClick={() => {
            save.reset();
            setName("");
            setShared(false);
            setSaving(true);
          }}
        >
          <Bookmark className="h-4 w-4" />
        </button>
      )}

      <Modal
        open={saving}
        onClose={() => setSaving(false)}
        title="Save view"
        footer={
          <>
            <button className="btn-secondary" onClick={() => setSaving(false)}>
              Cancel
            </button>
            <button className="btn-primary" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
              Save
            </button>
          </>
        }
      >
        <Field label="Name" hint={current ? undefined : "No filters are set: the view shows every finding."}>
          <input className="input" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} placeholder="e.g. Critical SCA, unassigned" />
        </Field>
        {can("analyst") && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} /> Share with everyone
          </label>
        )}
        <ErrorBox error={save.error} />
      </Modal>
      <ConfirmDialog
        open={deleting}
        title="Delete view"
        confirmLabel="Delete view"
        pending={del.isPending}
        error={del.error}
        onConfirm={() => active && del.mutate(active.id)}
        onClose={() => setDeleting(false)}
      >
        Delete the saved view <span className="font-medium">{active?.name}</span>
        {active?.shared ? ", which is shared with everyone" : ""}? The findings are not affected.
      </ConfirmDialog>
    </div>
  );
}
