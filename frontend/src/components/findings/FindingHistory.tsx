import type { ReactNode } from "react";
import { CalendarClock, CircleDot, Eye, Gauge, MessageSquare, RotateCcw, ScanLine, ShieldQuestion, Sparkles, Tag, UserPlus, Wand2 } from "lucide-react";
import type { FindingEvent } from "../../api/types";
import { fmtDateTime, STATUS_LABEL } from "../../lib/format";

// Mirrors services/notifications.py MENTION: "@someone@example.com" notifies that person.
const MENTION = /(?<![\w.+-])(@[\w.+-]+@[\w-]+(?:\.[\w-]+)+)/g;

function withMentions(text: string): ReactNode[] {
  return text.split(MENTION).map((part, i) =>
    i % 2 === 1 ? (
      <span key={i} className="rounded bg-accent/10 px-0.5 font-medium text-accent">
        {part}
      </span>
    ) : (
      part
    ),
  );
}

const EVENT_ICON: Record<string, ReactNode> = {
  created: <ScanLine className="h-3.5 w-3.5" />,
  reopened: <RotateCcw className="h-3.5 w-3.5" />,
  auto_resolved: <Wand2 className="h-3.5 w-3.5" />,
  status_changed: <CircleDot className="h-3.5 w-3.5" />,
  assigned: <UserPlus className="h-3.5 w-3.5" />,
  comment: <MessageSquare className="h-3.5 w-3.5" />,
  seen_again: <Eye className="h-3.5 w-3.5" />,
  no_longer_reported: <Wand2 className="h-3.5 w-3.5" />,
  rule_applied: <Sparkles className="h-3.5 w-3.5" />,
  tags_changed: <Tag className="h-3.5 w-3.5" />,
  due_date_changed: <CalendarClock className="h-3.5 w-3.5" />,
  severity_changed: <Gauge className="h-3.5 w-3.5" />,
  acceptance_requested: <ShieldQuestion className="h-3.5 w-3.5" />,
  acceptance_rejected: <ShieldQuestion className="h-3.5 w-3.5" />,
};

// Events whose whole message is in the comment, shown inline rather than as a quote.
const INLINE_COMMENT = new Set([
  "assigned", "tags_changed", "due_date_changed", "severity_changed", "acceptance_requested", "acceptance_rejected",
]);

function eventText(e: FindingEvent) {
  const who = e.actor ? e.actor.full_name || e.actor.email : "Guardiano";
  switch (e.event) {
    case "created":
      return <>Finding first detected{e.scan_id ? ` in scan #${e.scan_id}` : ""}</>;
    case "reopened":
      return <>Reopened automatically{e.scan_id ? ` by scan #${e.scan_id}` : ""}</>;
    case "auto_resolved":
      return <>Resolved automatically - no longer reported</>;
    case "status_changed":
      return (
        <>
          <span className="font-medium">{who}</span> changed status {e.from_status && <>from {STATUS_LABEL[e.from_status]} </>}
          to <span className="font-medium">{e.to_status && STATUS_LABEL[e.to_status]}</span>
        </>
      );
    case "no_longer_reported":
      return <>Dropped by a scanner{e.scan_id ? ` in scan #${e.scan_id}` : ""}</>;
    case "rule_applied":
      return (
        <>
          Auto-triage rule applied{e.to_status && <> · status {STATUS_LABEL[e.to_status]}</>}
        </>
      );
    case "assigned":
    case "tags_changed":
    case "due_date_changed":
    case "acceptance_requested":
    case "acceptance_rejected":
      return (
        <>
          <span className="font-medium">{who}</span>: {e.comment}
        </>
      );
    case "severity_changed":
      return <><span className="font-medium">{who}</span>: {e.comment || `Severity changed from ${e.from_severity ?? "unknown"} to ${e.to_severity ?? "unknown"}`}</>;
    case "comment":
      return (
        <>
          <span className="font-medium">{who}</span> commented
        </>
      );
    default:
      return e.event;
  }
}

export default function FindingHistory({ events }: { events: FindingEvent[] }) {
  return <ol className="relative space-y-4 border-l border-line pl-5">{events.map((event) => (
    <li key={event.id} className="relative">
      <span className="absolute -left-[29px] flex h-[18px] w-[18px] items-center justify-center rounded-full border border-line bg-raised text-ink2">
        {EVENT_ICON[event.event] ?? <CircleDot className="h-3.5 w-3.5" />}
      </span>
      <div className="text-sm">{eventText(event)}</div>
      <div className="text-xs text-muted" title={fmtDateTime(event.created_at)}>{fmtDateTime(event.created_at)}</div>
      {event.comment && !INLINE_COMMENT.has(event.event) && <p className="mt-1.5 whitespace-pre-wrap rounded-lg bg-page px-3 py-2 text-sm text-ink2">
        {event.event === "comment" ? withMentions(event.comment) : event.comment}
      </p>}
    </li>
  ))}</ol>;
}
