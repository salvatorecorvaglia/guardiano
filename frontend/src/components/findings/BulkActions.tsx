import type { FormEvent } from "react";
import { CalendarClock, Tag, UserPlus } from "lucide-react";
import type { BulkChange } from "../../api/types";
import { endOfLocalDay, fmtNum } from "../../lib/format";
import AsyncPicker from "../AsyncPicker";

export default function BulkActions({ selection, pending, canManage, tag, onTag, onAddTag, onRemoveTag,
  onChangeStatus, onChange, onSelectAll, onClear }: {
  selection: { count: number; allMatching: boolean; allSelected: boolean; total: number; pageCount: number };
  pending: boolean; canManage: boolean; tag: string; onTag: (value: string) => void;
  onAddTag: (event: FormEvent) => void; onRemoveTag: () => void; onChangeStatus: () => void;
  onChange: (change: BulkChange) => void; onSelectAll: () => void; onClear: () => void;
}) {
  return (
        <fieldset disabled={pending} className="sticky top-0 z-10 mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-raised px-3 py-2 shadow-sm">
          <span className="text-sm font-medium">
            {selection.allMatching ? `All ${fmtNum(selection.total)} matching selected` : `${selection.count} selected`}
          </span>
          {selection.allSelected && !selection.allMatching && selection.total > selection.pageCount && (
            <button className="text-xs text-accent hover:underline" onClick={() => onSelectAll()}>
              Select all {fmtNum(selection.total)} matching
            </button>
          )}
          <button className="btn-secondary py-1" onClick={() => onChangeStatus()}>
            Change status
          </button>
          <form className="flex items-center gap-1" onSubmit={onAddTag}>
            <Tag className="h-4 w-4 text-muted" />
            <input
              className="input w-36 py-1"
              placeholder="Add tag…"
              aria-label="Add tag to selected"
              value={tag}
              maxLength={64}
              onChange={(e) => onTag(e.target.value)}
            />
            <button type="button" className="btn-ghost py-1 text-xs" disabled={!tag.trim()} onClick={onRemoveTag}>
              Remove
            </button>
          </form>
          {canManage && (
            <div className="flex items-center gap-1">
              <CalendarClock className="h-4 w-4 text-muted" />
              <input
                className="input w-auto py-1"
                type="date"
                aria-label="Set due date for selected"
                value=""
                onChange={(e) => e.target.value && onChange({ due_at: endOfLocalDay(e.target.value) })}
              />
              <button className="btn-ghost py-1 text-xs" onClick={() => onChange({ clear_due_at: true })}>
                Reset to SLA
              </button>
            </div>
          )}
          <div className="flex items-center gap-1">
            <UserPlus className="h-4 w-4 text-muted" />
            <AsyncPicker kind="users" label="Assign selected" value="" emptyLabel="Assign to…"
              disabled={pending} extraOptions={[{ value: "none", label: "Unassign" }]}
              onChange={(value) => { if (value) onChange(value === "none" ? { unassign: true } : { assignee_id: Number(value) }); }} />
          </div>
          <button
            className="btn-ghost ml-auto py-1"
            onClick={() => {
              onClear();
            }}
          >
            Clear selection
          </button>
        </fieldset>
  );
}
