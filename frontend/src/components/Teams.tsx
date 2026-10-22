import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Users } from "lucide-react";
import { useRef, useState } from "react";
import { useDirectory } from "../api/queries";
import { request } from "../api/typed";
import type { Team } from "../api/types";
import { useToast } from "./Toaster";
import { ConfirmDialog, EmptyState, ErrorBox, Field, Modal, Spinner } from "./ui";

/** Teams restrict who sees an asset. Administrators create them; membership is set here. */
export default function Teams() {
  const qc = useQueryClient();
  const toast = useToast();
  const directory = useDirectory();
  const teams = useQuery({ queryKey: ["teams"], queryFn: ({ signal }) => request("get", "/api/v1/teams", { signal }) });
  const [editing, setEditing] = useState<Team | "new" | null>(null);
  const [removing, setRemoving] = useState<Team | null>(null);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["teams"] });
    qc.invalidateQueries({ queryKey: ["assets"] });
  };

  const remove = useMutation({
    mutationFn: (team: Team) => request("delete", "/api/v1/teams/{team_id}", { params: { team_id: Number(team.id) } }),
    onSuccess: (_r, team) => {
      invalidate();
      toast(`Deleted ${team.name}. Its assets are visible to everyone again.`);
      setRemoving(null);
    },
  });

  return (
    <section className="card p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">Teams</h2>
          <p className="text-xs text-muted">
            An asset with no team is visible to everyone. Put it in a team and only that team’s members — and
            administrators — can see it, its findings, scans and components.
          </p>
        </div>
        <button className="btn-secondary" onClick={() => setEditing("new")}>
          <Plus className="h-4 w-4" /> New team
        </button>
      </div>
      <ErrorBox error={teams.error ?? remove.error} />
      {teams.isLoading ? (
        <Spinner />
      ) : teams.data?.length ? (
        <ul className="divide-y divide-line">
          {teams.data.map((team) => (
            <li key={team.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{team.name}</p>
                <p className="text-xs text-muted">
                  {team.member_count} member{team.member_count === 1 ? "" : "s"} · {team.asset_count} asset
                  {team.asset_count === 1 ? "" : "s"}
                  {team.description ? ` · ${team.description}` : ""}
                </p>
              </div>
              <div className="flex items-center gap-1">
                <button className="btn-secondary" onClick={() => setEditing(team)}>
                  Members
                </button>
                <button className="btn-ghost p-1.5" aria-label={`Delete ${team.name}`} onClick={() => setRemoving(team)}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState icon={<Users className="h-6 w-6" />} title="No teams">
          Everyone can see every asset. Create a team to restrict one.
        </EmptyState>
      )}

      {editing && (
        <TeamDialog
          team={editing === "new" ? undefined : editing}
          people={directory.data ?? []}
          onClose={() => setEditing(null)}
          onSaved={invalidate}
        />
      )}
      {removing && (
        <ConfirmDialog
          open
          title={`Delete ${removing.name}?`}
          confirmLabel="Delete"
          onConfirm={() => remove.mutate(removing)}
          onClose={() => setRemoving(null)}
        >
          Its {removing.asset_count} asset{removing.asset_count === 1 ? "" : "s"} will be visible to everyone
          again. Nothing else is deleted.
        </ConfirmDialog>
      )}
    </section>
  );
}

function TeamDialog({
  team,
  people,
  onClose,
  onSaved,
}: {
  team?: Team;
  people: { id: number; email: string; full_name: string }[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [name, setName] = useState(team?.name ?? "");
  const [description, setDescription] = useState(team?.description ?? "");
  const [members, setMembers] = useState<number[]>((team?.members ?? []).map((m) => m.id));

  // Saving is two requests. If the team is created and setting its members then fails, a second
  // press of Save must update that team, not create another one with the same name.
  const created = useRef<number | null>(null);
  const save = useMutation({
    mutationFn: async () => {
      const body = { name: name.trim(), description };
      const id = team?.id ?? created.current;
      const saved = id
        ? await request("patch", "/api/v1/teams/{team_id}", { params: { team_id: Number(id) }, body })
        : await request("post", "/api/v1/teams", { body });
      created.current = saved.id;
      return request("put", "/api/v1/teams/{team_id}/members", { params: { team_id: Number(saved.id) }, body: { user_ids: members } });
    },
    onSuccess: (saved) => {
      onSaved();
      toast(team ? `Saved ${saved.name}` : `Created ${saved.name}`);
      onClose();
    },
  });

  const toggle = (id: number) => setMembers((m) => (m.includes(id) ? m.filter((x) => x !== id) : [...m, id]));

  return (
    <Modal
      open
      onClose={onClose}
      title={team ? `Edit ${team.name}` : "New team"}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <Field label="Name">
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="payments" />
      </Field>
      <Field label="Description">
        <input className="input" value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>
      <Field label="Members" hint="Administrators always see every asset, whether or not they are in a team.">
        <div className="max-h-56 space-y-1 overflow-y-auto rounded-lg border border-line p-2">
          {people.length === 0 && <p className="text-sm text-muted">No other accounts yet.</p>}
          {people.map((person) => (
            <label key={person.id} className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={members.includes(person.id)} onChange={() => toggle(person.id)} />
              <span className="truncate">{person.full_name || person.email}</span>
              <span className="truncate text-xs text-muted">{person.email}</span>
            </label>
          ))}
        </div>
      </Field>
      <ErrorBox error={save.error} />
    </Modal>
  );
}
