import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { invalidateInventory, useDirectory, useProducts } from "../api/queries";
import { type RequestBody, request } from "../api/typed";
import type { Asset } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "./Toaster";
import { ErrorBox, Field, Modal } from "./ui";

// Mirrors the API pattern (app/schemas/asset.py NAME_PATTERN).
export const ASSET_NAME_RE = /^[\p{L}\p{N}_.\-/ @:]+$/u;

export default function AssetForm({ asset, onClose, onSaved }: { asset?: Asset; onClose: () => void; onSaved?: (a: Asset) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const directory = useDirectory();
  const { can } = useAuth();
  // Only an administrator may move an asset between teams, so only they are offered the choice.
  const teams = useQuery({ queryKey: ["teams"], queryFn: ({ signal }) => request("get", "/api/v1/teams", { signal }), enabled: can("admin") });
  const [form, setForm] = useState({
    name: asset?.name ?? "",
    type: asset?.type ?? "repository",
    criticality: asset?.criticality ?? "medium",
    owner: asset?.owner ?? "",
    repo_url: asset?.repo_url ?? "",
    description: asset?.description ?? "",
    tags: asset?.tags.join(", ") ?? "",
    default_assignee_id: asset?.default_assignee_id ? String(asset.default_assignee_id) : "",
    default_branch: asset?.default_branch ?? "",
    team_id: asset?.team_id ? String(asset.team_id) : "",
    product_id: asset?.product_id ? String(asset.product_id) : "",
    environment: asset?.environment ?? "",
  });
  const products = useProducts();
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  const nameOk = ASSET_NAME_RE.test(form.name.trim());

  const save = useMutation({
    mutationFn: () => {
      const { team_id, ...rest } = form;
      const body: RequestBody<"/api/v1/assets"> = {
        ...rest,
        ...(can("admin") ? { team_id: team_id ? Number(team_id) : null } : {}),
        owner: form.owner || null,
        repo_url: form.repo_url || null,
        default_assignee_id: form.default_assignee_id ? Number(form.default_assignee_id) : null,
        default_branch: form.default_branch.trim() || null,
        product_id: form.product_id ? Number(form.product_id) : null,
        environment: (form.environment || null) as RequestBody<"/api/v1/assets">["environment"],
        tags: form.tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      };
      // Sent only by an administrator: for anybody else the field is not theirs to set, and the API says so.

      return asset ? request("patch", "/api/v1/assets/{asset_id}", { params: { asset_id: Number(asset.id) }, body }) : request("post", "/api/v1/assets", { body });
    },
    onSuccess: (a) => {
      invalidateInventory(qc);
      toast(asset ? `Saved ${a.name}` : `Created ${a.name}`);
      onSaved?.(a);
      onClose();
    },
  });

  return (
    <Modal
      open
      onClose={onClose}
      title={asset ? `Edit ${asset.name}` : "New asset"}
      wide
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={!nameOk || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint={form.name && !nameOk ? "Letters, digits and . _ - / @ : or spaces only" : undefined}>
          <input className="input" value={form.name} onChange={set("name")} placeholder="payments-api" aria-invalid={!!form.name && !nameOk} />
        </Field>
        <Field label="Owner" hint="Free text: the person or squad responsible">
          <input className="input" value={form.owner} onChange={set("owner")} />
        </Field>
        <Field label="Type">
          <select className="input" value={form.type} onChange={set("type")}>
            {["repository", "application", "service", "container"].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Business criticality" hint="Multiplies the asset risk score">
          <select className="input" value={form.criticality} onChange={set("criticality")}>
            {["low", "medium", "high", "critical"].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Product" hint="Groups this asset with the others that make up one product">
          <select className="input" value={form.product_id} onChange={set("product_id")}>
            <option value="">None</option>
            {products.data?.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Environment">
          <select className="input" value={form.environment} onChange={set("environment")}>
            <option value="">Not set</option>
            {["production", "staging", "development", "test"].map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <Field label="Default assignee" hint="New findings on this asset are assigned to this person">
        <select className="input" value={form.default_assignee_id} onChange={set("default_assignee_id")}>
          <option value="">Nobody (leave unassigned)</option>
          {directory.data?.map((u) => (
            <option key={u.id} value={u.id}>
              {u.full_name || u.email}
            </option>
          ))}
        </select>
      </Field>
      <Field
        label="Default branch"
        hint="Optional. Scans of other branches become previews: they are gated but never change the inventory."
      >
        <input className="input" value={form.default_branch} onChange={set("default_branch")} placeholder="main" />
      </Field>
      {can("admin") && (
        <Field label="Visible to" hint="A team restricts who can see this asset and everything found on it">
          <select className="input" value={form.team_id} onChange={set("team_id")}>
            <option value="">Everyone</option>
            {teams.data?.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="Repository URL">
        <input className="input" value={form.repo_url} onChange={set("repo_url")} placeholder="https://…" />
      </Field>
      <Field label="Tags" hint="Comma separated">
        <input className="input" value={form.tags} onChange={set("tags")} placeholder="pci, internet-facing" />
      </Field>
      <Field label="Description">
        <textarea className="input min-h-[64px]" value={form.description} onChange={set("description")} />
      </Field>
      <ErrorBox error={save.error} />
    </Modal>
  );
}
