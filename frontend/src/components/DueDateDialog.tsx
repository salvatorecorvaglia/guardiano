import { useState } from "react";
import type { FindingDetail } from "../api/types";
import { endOfLocalDay, fmtDate, toLocalDateInput } from "../lib/format";
import { ErrorBox, Field, Modal } from "./ui";

export type DueChange = { due_at: string; due_reason?: string } | { clear_due_at: true };

/** Manager-only: override the SLA due date of a finding, or reset it to the SLA. */
export default function DueDateDialog({
  finding,
  onClose,
  onSubmit,
  pending,
  error,
}: {
  finding: FindingDetail;
  onClose: () => void;
  onSubmit: (c: DueChange) => void;
  pending?: boolean;
  error?: unknown;
}) {
  const initial = toLocalDateInput(finding.due_at_override ?? finding.sla_due_at);
  const [date, setDate] = useState(initial);
  const [reason, setReason] = useState("");
  return (
    <Modal
      open
      onClose={onClose}
      title="Change due date"
      footer={
        <>
          {finding.due_at_override && (
            <button className="btn-ghost mr-auto" disabled={pending} onClick={() => onSubmit({ clear_due_at: true })}>
              Reset to SLA
            </button>
          )}
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={!date || pending}
            // End of the chosen day in the user's timezone, so a finding is not past due on its due date.
            onClick={() => onSubmit({ due_at: endOfLocalDay(date), due_reason: reason.trim() || undefined })}
          >
            Save
          </button>
        </>
      }
    >
      <p className="text-sm text-ink2">
        {finding.due_at_override
          ? `Currently set manually to ${fmtDate(finding.due_at_override)}.`
          : `Currently due ${finding.sla_due_at ? fmtDate(finding.sla_due_at) : "never"} under the remediation SLA.`}
      </p>
      <Field label="Due date">
        <input className="input" type="date" value={date} onChange={(e) => setDate(e.target.value)} />
      </Field>
      <Field label="Reason" hint="Recorded in the finding's activity">
        <textarea className="input min-h-[64px]" maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />
      </Field>
      <ErrorBox error={error} />
    </Modal>
  );
}
