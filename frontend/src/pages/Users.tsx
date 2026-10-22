import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { request } from "../api/typed";
import type { Role, User } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toaster";
import { ConfirmDialog, ErrorBox, Field, Modal, PageHeader, Spinner } from "../components/ui";
import { fmtDate, relTime } from "../lib/format";

const ROLES: { value: Role; label: string; desc: string }[] = [
  { value: "viewer", label: "Viewer", desc: "Read-only access to findings, assets and analytics" },
  { value: "analyst", label: "Analyst", desc: "Upload scans, triage, comment, mark false positives" },
  { value: "manager", label: "Security Manager", desc: "Everything above plus risk acceptance and asset management" },
  { value: "admin", label: "Administrator", desc: "Full access including user management" },
];
const ROLE_LABEL = Object.fromEntries(ROLES.map((r) => [r.value, r.label])) as Record<Role, string>;

function UserForm({ user, onClose }: { user?: User; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [email, setEmail] = useState(user?.email ?? "");
  const [name, setName] = useState(user?.full_name ?? "");
  const [role, setRole] = useState<Role>(user?.role ?? "analyst");
  const [active, setActive] = useState(user?.is_active ?? true);
  const [password, setPassword] = useState("");

  const save = useMutation({
    mutationFn: () =>
      user
        ? request("patch", "/api/v1/users/{user_id}", { params: { user_id: Number(user.id) }, body: { full_name: name, role, is_active: active, ...(password ? { password } : {}) } })
        : request("post", "/api/v1/users", { body: { email, full_name: name, role, password } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      toast(user ? `Saved ${user.email}` : `Added ${email}`);
      onClose();
    },
  });

  const valid = (user || (email && password.length >= 12)) && (!password || password.length >= 12);

  return (
    <Modal
      open
      onClose={onClose}
      title={user ? `Edit ${user.email}` : "Add user"}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
            Save
          </button>
        </>
      }
    >
      {!user && (
        <Field label="Email">
          <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
      )}
      <Field label="Full name">
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <fieldset>
        <legend className="label">Role</legend>
        <div className="space-y-1.5">
          {ROLES.map((r) => (
            <label key={r.value} className="flex cursor-pointer items-start gap-2 rounded-lg border border-line p-2.5 text-sm has-[:checked]:border-accent">
              <input type="radio" className="mt-0.5" checked={role === r.value} onChange={() => setRole(r.value)} />
              <span>
                <span className="font-medium">{r.label}</span>
                <span className="block text-xs text-muted">{r.desc}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      <Field label={user ? "Reset password (optional)" : "Initial password"} hint="At least 12 characters">
        <input className="input" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      {user && (
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} /> Account active
        </label>
      )}
      <ErrorBox error={save.error} />
    </Modal>
  );
}

export default function Users() {
  const { user: me } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<User | "new" | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const users = useQuery({ queryKey: ["users", "all"], queryFn: ({ signal }) => request("get", "/api/v1/users", { signal }) });
  const del = useMutation({
    mutationFn: (id: number) => request("delete", "/api/v1/users/{user_id}", { params: { user_id: Number(id) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      toast(`Deleted ${deleting?.email}`);
      setDeleting(null);
    },
  });

  return (
    <>
      <PageHeader
        title="Users"
        subtitle="Manage accounts and role-based access"
        actions={
          <button className="btn-primary" onClick={() => setEditing("new")}>
            <Plus className="h-4 w-4" /> Add user
          </button>
        }
      />
      <ErrorBox error={users.error} />
      <div className="card overflow-hidden">
        {users.isLoading ? (
          <div className="flex justify-center py-12">
            <Spinner />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line bg-page/50">
                <tr>
                  <th className="th">User</th>
                  <th className="th">Role</th>
                  <th className="th">Status</th>
                  <th className="th">Last login</th>
                  <th className="th">Created</th>
                  <th className="th" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {users.data?.map((u) => (
                  <tr key={u.id}>
                    <td className="td">
                      <div className="font-medium">{u.full_name || "–"}</div>
                      <div className="text-xs text-muted">{u.email}</div>
                    </td>
                    <td className="td">{ROLE_LABEL[u.role]}</td>
                    <td className="td">
                      {u.is_active ? <span className="text-good">Active</span> : <span className="text-muted">Disabled</span>}
                    </td>
                    <td className="td text-xs text-ink2">{relTime(u.last_login_at)}</td>
                    <td className="td text-xs text-ink2">{fmtDate(u.created_at)}</td>
                    <td className="td text-right">
                      <button className="btn-ghost p-1.5" onClick={() => setEditing(u)} aria-label={`Edit ${u.email}`}>
                        <Pencil className="h-4 w-4" />
                      </button>
                      {u.id !== me?.id && (
                        <button
                          className="btn-ghost p-1.5 hover:text-danger"
                          aria-label={`Delete ${u.email}`}
                          onClick={() => {
                            del.reset();
                            setDeleting(u);
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <ConfirmDialog
        open={!!deleting}
        title="Delete user"
        confirmLabel="Delete user"
        pending={del.isPending}
        error={del.error}
        onConfirm={() => deleting && del.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      >
        Delete <span className="font-medium">{deleting?.email}</span>? Their API tokens are revoked. Findings and scans keep
        their history. This cannot be undone; disable the account instead if you may need it again.
      </ConfirmDialog>
      {editing && <UserForm user={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
    </>
  );
}
