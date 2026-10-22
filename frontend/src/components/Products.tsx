import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { useProducts } from "../api/queries";
import { request } from "../api/typed";
import type { Product } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { fmtNum } from "../lib/format";
import { useToast } from "./Toaster";
import { ConfirmDialog, ErrorBox, Field, Modal, SeverityBar, Spinner } from "./ui";

/** Products group assets that ship together. Counts cover only the assets you can see. */
export default function Products() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const products = useProducts();
  const [editing, setEditing] = useState<Product | "new" | null>(null);
  const [deleting, setDeleting] = useState<Product | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["products"] });
    qc.invalidateQueries({ queryKey: ["assets"] });
  };
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), description };
      return editing === "new" || !editing
        ? request("post", "/api/v1/products", { body })
        : request("patch", "/api/v1/products/{product_id}", { params: { product_id: Number(editing.id) }, body });
    },
    onSuccess: () => {
      refresh();
      toast(editing === "new" ? `Added ${name.trim()}` : `Saved ${name.trim()}`);
      setEditing(null);
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => request("delete", "/api/v1/products/{product_id}", { params: { product_id: Number(id) } }),
    onSuccess: () => {
      refresh();
      toast(`Deleted ${deleting?.name}`);
      setDeleting(null);
    },
  });
  const open = (p: Product | "new") => {
    save.reset();
    setName(p === "new" ? "" : p.name);
    setDescription(p === "new" ? "" : p.description);
    setEditing(p);
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (name.trim()) save.mutate();
  };

  return (
    <section className="card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold">Products</h2>
          <p className="text-xs text-muted">Group the assets that ship together; filter findings and assets by product.</p>
        </div>
        {can("manager") && (
          <button className="btn-secondary" onClick={() => open("new")}>
            <Plus className="h-4 w-4" /> New product
          </button>
        )}
      </div>
      <ErrorBox error={products.error} />
      {products.isLoading ? (
        <div className="flex justify-center py-6">
          <Spinner />
        </div>
      ) : (
        <ul className="divide-y divide-line border-t border-line">
          {products.data?.map((p) => (
            <li key={p.id} className="flex flex-wrap items-center gap-3 px-4 py-2 text-sm">
              <div className="min-w-0 flex-1">
                <Link className="font-medium hover:text-accent" to={`/assets?product_id=${p.id}`}>
                  {p.name}
                </Link>
                <div className="text-xs text-muted">
                  {fmtNum(p.assets)} asset{p.assets === 1 ? "" : "s"} · {fmtNum(p.open_total)} open
                </div>
              </div>
              <SeverityBar className="w-32" counts={p.open_counts ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 }} />
              {can("manager") && (
                <span>
                  <button className="btn-ghost p-1.5" aria-label={`Rename ${p.name}`} onClick={() => open(p)}>
                    <Pencil className="h-4 w-4" />
                  </button>
                  <button className="btn-ghost p-1.5 hover:text-danger" aria-label={`Delete ${p.name}`} onClick={() => setDeleting(p)}>
                    <Trash2 className="h-4 w-4" />
                  </button>
                </span>
              )}
            </li>
          ))}
          {products.data?.length === 0 && <li className="px-4 py-6 text-center text-sm text-muted">No products yet</li>}
        </ul>
      )}
      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={editing === "new" ? "New product" : "Edit product"}
        footer={
          <>
            <button className="btn-secondary" onClick={() => setEditing(null)}>
              Cancel
            </button>
            <button className="btn-primary" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
              Save
            </button>
          </>
        }
      >
        <form onSubmit={submit} className="space-y-3">
          <Field label="Name">
            <input className="input" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder="Checkout" />
          </Field>
          <Field label="Description">
            <textarea className="input min-h-[60px]" maxLength={5000} value={description} onChange={(e) => setDescription(e.target.value)} />
          </Field>
        </form>
        <ErrorBox error={save.error} />
      </Modal>
      <ConfirmDialog
        open={!!deleting}
        title="Delete product"
        confirmLabel="Delete product"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      >
        Delete <span className="font-medium">{deleting?.name}</span>? Its assets stay, and are no longer grouped.
      </ConfirmDialog>
    </section>
  );
}
