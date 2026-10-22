import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ExternalLink, Ticket as TicketIcon, X } from "lucide-react";
import { useState } from "react";
import { request } from "../api/typed";
import type { FindingLink } from "../api/types";
import { relTime } from "../lib/format";
import { useToast } from "./Toaster";
import { ErrorBox, Modal } from "./ui";

/** Linked tickets for a finding, and the button that opens a new one. */
export default function FindingTickets({
  findingId,
  links,
  canEdit,
  onChange,
}: {
  findingId: number;
  links: FindingLink[];
  canEdit: boolean;
  onChange: () => void;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const [picking, setPicking] = useState(false);
  // Only asked for when the button is pressed: most people never open a ticket.
  const trackers = useQuery({
    queryKey: ["finding", findingId, "trackers"],
    queryFn: ({ signal }) => request("get", "/api/v1/findings/{finding_id}/trackers", { params: { finding_id: Number(findingId) }, signal }),
    enabled: canEdit,
  });

  const create = useMutation({
    mutationFn: (integrationId?: number) =>
      request("post", "/api/v1/findings/{finding_id}/ticket", { params: { finding_id: Number(findingId) }, body: integrationId ? { integration_id: integrationId } : {} }),
    onSuccess: (link) => {
      toast(`Opened ${link.external_key}`);
      setPicking(false);
      qc.invalidateQueries({ queryKey: ["finding", String(findingId)] });
      onChange();
    },
  });
  const unlink = useMutation({
    mutationFn: (linkId: number) => request("delete", "/api/v1/findings/{finding_id}/ticket/{link_id}", { params: { finding_id: findingId, link_id: linkId } }),
    onSuccess: () => {
      toast("Ticket unlinked");
      qc.invalidateQueries({ queryKey: ["finding", String(findingId)] });
      onChange();
    },
  });

  // A ticket the tracker now calls finished. It is a prompt for a person, never an automatic change.
  const suggested = links.filter((l) => l.remote_done_at);
  const available = (trackers.data ?? []).filter((t) => !links.some((l) => l.system === t.kind && l.url));
  const unused = (trackers.data ?? []).length - links.length;

  function open() {
    create.reset();
    const options = trackers.data ?? [];
    if (options.length === 1) create.mutate(options[0].id);
    else setPicking(true);
  }

  return (
    <div className="space-y-2">
      {links.map((l) => (
        <div key={l.id} className="flex items-center gap-2 text-sm">
          <TicketIcon className="h-3.5 w-3.5 text-muted" />
          <a className="inline-flex items-center gap-1 text-accent hover:underline" href={l.url} target="_blank" rel="noreferrer noopener">
            {l.external_key} <ExternalLink className="h-3 w-3" />
          </a>
          <span className="text-xs text-muted">
            {l.system}
            {l.remote_status ? ` · ${l.remote_status}` : ""}
          </span>
          {canEdit && (
            <button className="btn-ghost p-1 hover:text-danger" aria-label={`Unlink ${l.external_key}`} title="Unlink (the ticket is kept)" onClick={() => unlink.mutate(l.id)}>
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      ))}
      {suggested.length > 0 && (
        <p className="flex items-start gap-1.5 rounded-lg bg-good/10 px-2.5 py-2 text-xs text-ink2">
          <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-good" />
          <span>
            {suggested.length === 1
              ? `${suggested[0].external_key} was closed in ${suggested[0].system} ${relTime(suggested[0].remote_done_at!)}.`
              : `${suggested.length} linked tickets have been closed.`}{" "}
            Guardiano does not change a finding's status by itself — resolve it above if the work is really done.
          </span>
        </p>
      )}
      {!links.length && <p className="text-sm text-muted">No ticket yet.</p>}
      {canEdit && (trackers.data?.length ?? 0) > 0 && unused > 0 && (
        <button className="btn-secondary py-1" disabled={create.isPending} onClick={open}>
          {create.isPending ? "Opening…" : "Create ticket"}
        </button>
      )}
      <ErrorBox error={create.error ?? unlink.error} />

      <Modal
        open={picking}
        onClose={() => setPicking(false)}
        title="Create ticket"
        footer={
          <button className="btn-secondary" onClick={() => setPicking(false)}>
            Cancel
          </button>
        }
      >
        <p className="text-sm text-ink2">Where should this ticket go?</p>
        <div className="space-y-2">
          {available.map((t) => (
            <button key={t.id} className="btn-secondary w-full justify-start" disabled={create.isPending} onClick={() => create.mutate(t.id)}>
              {t.name} <span className="ml-1 text-xs text-muted">{t.kind} · {t.project}</span>
            </button>
          ))}
        </div>
        <ErrorBox error={create.error} />
      </Modal>
    </div>
  );
}
