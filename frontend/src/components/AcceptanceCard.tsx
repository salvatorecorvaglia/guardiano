import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldQuestion } from "lucide-react";
import { useState } from "react";
import { invalidateAfterTriage } from "../api/queries";
import { request } from "../api/typed";
import type { Status } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { endOfLocalDay, fmtDate, relTime } from "../lib/format";
import { useToast } from "./Toaster";
import { ErrorBox, Field, Modal } from "./ui";

const ACTIVE: Status[] = ["open", "in_progress"];

/** A finding's pending risk-acceptance request, or the way to make one (services/acceptance.py). */
export default function AcceptanceCard({ findingId, status }: { findingId: number; status: Status }) {
  const { can, user } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const [asking, setAsking] = useState(false);
  const [justification, setJustification] = useState("");
  const [until, setUntil] = useState("");
  const [note, setNote] = useState("");

  const key = ["acceptance-requests", "finding", findingId];
  const pending = useQuery({
    queryKey: key,
    queryFn: ({ signal }) =>
      request("get", "/api/v1/acceptance-requests", { signal, query: { finding_id: findingId, state: "pending" } }),
  });
  const done = (message: string) => {
    qc.invalidateQueries({ queryKey: ["acceptance-requests"] });
    qc.invalidateQueries({ queryKey: ["finding", String(findingId)] });
    invalidateAfterTriage(qc);
    toast(message);
  };
  const ask = useMutation({
    mutationFn: () =>
      request("post", "/api/v1/findings/{finding_id}/acceptance-requests", { params: { finding_id: Number(findingId) }, body: { justification: justification.trim(), until: until ? endOfLocalDay(until) : null } }),
    onSuccess: () => {
      setAsking(false);
      setJustification("");
      setUntil("");
      done("Risk acceptance requested");
    },
  });
  const decide = useMutation({
    mutationFn: ({ id, verb }: { id: number; verb: "approve" | "reject" }) =>
      request("post", verb === "approve" ? "/api/v1/acceptance-requests/{request_id}/approve" : "/api/v1/acceptance-requests/{request_id}/reject", { params: { request_id: id }, body: { note: note.trim() || null } }),
    onSuccess: (_, { verb }) => {
      setNote("");
      done(verb === "approve" ? "Risk accepted" : "Request rejected");
    },
  });

  const req = pending.data?.[0];
  if (req) {
    const mine = req.requested_by?.id === user?.id;
    return (
      <div className="rounded-xl border border-accent/40 bg-raised p-4 text-sm">
        <div className="mb-1 flex items-center gap-2 font-medium">
          <ShieldQuestion className="h-4 w-4 text-accent" /> Risk acceptance requested
        </div>
        <p className="text-xs text-muted">
          by {req.requested_by ? req.requested_by.full_name || req.requested_by.email : "somebody"} {relTime(req.created_at)} ·{" "}
          {req.until ? `until ${fmtDate(req.until)}` : "no end date"}
        </p>
        <p className="mt-2 whitespace-pre-wrap text-ink2">{req.justification}</p>
        {can("manager") && !mine && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <input
              className="input min-w-0 flex-1 py-1"
              placeholder="Note (optional)"
              aria-label="Decision note"
              value={note}
              maxLength={2000}
              onChange={(e) => setNote(e.target.value)}
            />
            <button className="btn-primary py-1" disabled={decide.isPending} onClick={() => decide.mutate({ id: req.id, verb: "approve" })}>
              Approve
            </button>
            <button className="btn-secondary py-1" disabled={decide.isPending} onClick={() => decide.mutate({ id: req.id, verb: "reject" })}>
              Reject
            </button>
          </div>
        )}
        {mine && <p className="mt-2 text-xs text-muted">A manager other than you decides.</p>}
        <ErrorBox error={decide.error} />
      </div>
    );
  }
  if (!can("analyst") || !ACTIVE.includes(status) || pending.isLoading) return null;
  return (
    <>
      <button className="text-xs text-accent hover:underline" onClick={() => setAsking(true)}>
        Request risk acceptance…
      </button>
      <Modal
        open={asking}
        onClose={() => setAsking(false)}
        title="Request risk acceptance"
        footer={
          <>
            <button className="btn-secondary" onClick={() => setAsking(false)}>
              Cancel
            </button>
            <button className="btn-primary" disabled={!justification.trim() || ask.isPending} onClick={() => ask.mutate()}>
              Send request
            </button>
          </>
        }
      >
        <Field label="Why the risk can be accepted" hint="Recorded on the finding, and shown to whoever decides">
          <textarea
            className="input min-h-[80px]"
            maxLength={5000}
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
          />
        </Field>
        <Field label="Until" hint="When the acceptance ends and the finding reopens">
          <input className="input w-auto" type="date" aria-label="Accepted until" value={until} onChange={(e) => setUntil(e.target.value)} />
        </Field>
        <ErrorBox error={ask.error} />
      </Modal>
    </>
  );
}
