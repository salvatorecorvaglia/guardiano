import { useState } from "react";
import type { Status } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { STATUS_LABEL, STATUSES } from "../lib/format";
import { ErrorBox, Field, Modal } from "./ui";

export interface StatusChange {
  status: Status;
  justification?: string;
  risk_accepted_until?: string | null;
}

const NEEDS_REASON: Status[] = ["false_positive", "risk_accepted"];

export default function StatusDialog({
  open,
  onClose,
  onSubmit,
  current,
  count = 1,
  pending,
  error,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (c: StatusChange) => void;
  current?: Status;
  count?: number;
  pending?: boolean;
  error?: unknown;
}) {
  const { can } = useAuth();
  const [status, setStatus] = useState<Status>(current && current !== "open" ? "open" : "in_progress");
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");

  // Mirrors lifecycle.min_role_for_status: risk acceptance, and turning an acceptance into a false positive, need a manager.
  const options = STATUSES.filter(
    (s) => can("manager") || (s !== "risk_accepted" && !(s === "false_positive" && current === "risk_accepted")),
  );
  const needsReason = NEEDS_REASON.includes(status);
  const valid = !needsReason || reason.trim().length > 0;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={count > 1 ? `Change status of ${count} findings` : "Change status"}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={!valid || pending}
            onClick={() =>
              onSubmit({
                status,
                justification: reason.trim() || undefined,
                risk_accepted_until: status === "risk_accepted" && until ? new Date(until + "T23:59:59").toISOString() : null,
              })
            }
          >
            {pending ? "Saving…" : "Apply"}
          </button>
        </>
      }
    >
      <Field label="New status">
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value as Status)}>
          {options.map((s) => (
            <option key={s} value={s}>
              {STATUS_LABEL[s]}
            </option>
          ))}
        </select>
      </Field>
      {!can("manager") && (
        <p className="-mt-2 text-xs text-muted">
          {current === "risk_accepted"
            ? "Changing a risk acceptance into a false positive requires the Security Manager role."
            : "Risk acceptance requires the Security Manager role."}
        </p>
      )}
      <Field label={needsReason ? "Justification (required)" : "Comment (optional)"}>
        <textarea
          className="input min-h-[88px]"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={
            status === "false_positive"
              ? "Why is this not exploitable? e.g. input validated by schema, test-only code…"
              : status === "risk_accepted"
                ? "Business rationale and compensating controls"
                : ""
          }
        />
      </Field>
      {status === "risk_accepted" && (
        <Field label="Acceptance expires" hint="The finding reopens automatically if still detected after this date.">
          <input type="date" className="input" value={until} min={new Date().toISOString().slice(0, 10)} onChange={(e) => setUntil(e.target.value)} />
        </Field>
      )}
      <ErrorBox error={error} />
    </Modal>
  );
}
