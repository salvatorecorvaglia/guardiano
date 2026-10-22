import clsx from "clsx";
import { AlertTriangle, ArrowLeft, ChevronLeft, ChevronRight, Loader2, X } from "lucide-react";
import { type ReactNode, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import type { Severity, Status } from "../api/types";
import { fmtNum, SEVERITY_LABEL, STATUS_LABEL, sevColor } from "../lib/format";

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={clsx("h-5 w-5 animate-spin text-muted", className)} aria-label="Loading" />;
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="truncate text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-ink2">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Severity badge: colored dot carries identity, text stays in ink (never color alone). */
export function SeverityBadge({ severity, score }: { severity: Severity; score?: number | null }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-line bg-raised px-1.5 py-0.5 text-xs font-medium text-ink">
      <span className="h-2 w-2 rounded-full" style={{ background: sevColor(severity) }} aria-hidden />
      {SEVERITY_LABEL[severity]}
      {score != null && <span className="tabular text-muted">{score.toFixed(1)}</span>}
    </span>
  );
}

const STATUS_STYLE: Record<Status, string> = {
  open: "border-accent/40 text-ink",
  in_progress: "border-warn/50 text-ink",
  false_positive: "border-line text-ink2",
  risk_accepted: "border-line text-ink2",
  resolved: "border-good/40 text-ink2",
};
const STATUS_DOT: Record<Status, string> = {
  open: "bg-accent",
  in_progress: "bg-warn",
  false_positive: "bg-muted",
  risk_accepted: "bg-muted",
  resolved: "bg-good",
};

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border bg-raised px-2 py-0.5 text-xs font-medium",
        STATUS_STYLE[status],
      )}
    >
      <span className={clsx("h-1.5 w-1.5 rounded-full", STATUS_DOT[status])} aria-hidden />
      {STATUS_LABEL[status]}
    </span>
  );
}

export function TypeBadge({ type }: { type: "sast" | "sca" | "iac" | "dast" }) {
  return (
    <span className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px] uppercase text-ink2">{type}</span>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div className="flex items-start gap-2 rounded-lg border border-danger/40 bg-danger/5 px-3 py-2 text-sm text-danger" role="alert">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{error instanceof Error ? error.message : String(error)}</span>
    </div>
  );
}

export function EmptyState({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      {icon && <div className="mb-3 text-muted">{icon}</div>}
      <p className="font-medium">{title}</p>
      {children && <div className="mt-1 max-w-md text-sm text-ink2">{children}</div>}
    </div>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone,
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: Severity | "danger";
  icon?: ReactNode;
}) {
  return (
    <div className="card relative overflow-hidden p-4">
      {tone && (
        <span
          className="absolute inset-y-0 left-0 w-1"
          style={{ background: tone === "danger" ? "rgb(var(--danger))" : sevColor(tone) }}
          aria-hidden
        />
      )}
      <div className="flex items-center gap-1.5 text-xs font-medium text-ink2">
        {icon}
        {label}
      </div>
      <div className="mt-1.5 text-2xl font-semibold tracking-tight">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const FIELDS = 'input:not([disabled]):not([type="hidden"]):not(.sr-only), select:not([disabled]), textarea:not([disabled])';

export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  // Callers often pass an inline onClose; reading it through a ref keeps the effect below from
  // re-running (and stealing focus) on every parent render.
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  });

  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onCloseRef.current();
      } else if (e.key === "Tab" && ref.current) {
        // Keep keyboard focus inside the dialog.
        const nodes = Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE));
        if (!nodes.length) return;
        const first = nodes[0];
        const last = nodes[nodes.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    (bodyRef.current?.querySelector<HTMLElement>(FIELDS) ?? ref.current?.querySelector<HTMLElement>(FOCUSABLE))?.focus();
    return () => {
      document.removeEventListener("keydown", onKey);
      if (opener?.isConnected) opener.focus();
    };
  }, [open]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 pt-[8vh]" onMouseDown={onClose}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={clsx("card w-full bg-raised shadow-xl", wide ? "max-w-2xl" : "max-w-md")}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-line px-5 py-3">
          <h2 className="font-semibold">{title}</h2>
          <button className="btn-ghost -mr-2 p-1" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div ref={bodyRef} className="space-y-4 px-5 py-4">
          {children}
        </div>
        {footer && <div className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

/** Confirmation for destructive actions; replaces window.confirm so styling and focus handling match. */
export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel = "Confirm",
  pending,
  error,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel?: string;
  pending?: boolean;
  error?: unknown;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-danger" onClick={onConfirm} disabled={pending}>
            {pending ? "Working…" : confirmLabel}
          </button>
        </>
      }
    >
      <div className="text-sm">{children}</div>
      <ErrorBox error={error} />
    </Modal>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex items-center justify-between gap-3 border-t border-line px-3 py-2 text-xs text-ink2">
      <span className="tabular">
        {fmtNum(from)}–{fmtNum(to)} of {fmtNum(total)}
      </span>
      <div className="flex items-center gap-1">
        <button className="btn-ghost p-1" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft className="h-4 w-4" />
        </button>
        <span className="tabular px-1">
          {page} / {pages}
        </span>
        <button className="btn-ghost p-1" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

/** Stacked horizontal bar of open findings by severity, with a 2px surface gap between segments. */
export function SeverityBar({ counts, className }: { counts: Record<Severity, number>; className?: string }) {
  const total = (["critical", "high", "medium", "low"] as const).reduce((a, s) => a + counts[s], 0);
  if (!total) return <div className={clsx("h-2 rounded-full bg-line/60", className)} />;
  const label = (["critical", "high", "medium", "low"] as const)
    .map((s) => `${counts[s]} ${s}`)
    .join(", ");
  return (
    <div className={clsx("flex h-2 gap-[2px] overflow-hidden rounded-full", className)} role="img" aria-label={label} title={label}>
      {(["critical", "high", "medium", "low"] as const).map(
        (s) =>
          counts[s] > 0 && (
            <span key={s} style={{ flexGrow: counts[s], background: sevColor(s) }} className="min-w-[3px]" />
          ),
      )}
    </div>
  );
}

export function CriticalityTag({ value }: { value: string }) {
  const tone = value === "critical" ? "critical" : value === "high" ? "high" : value === "medium" ? "medium" : "low";
  return (
    <span className="inline-flex items-center gap-1 text-xs capitalize text-ink2">
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: sevColor(tone) }} />
      {value}
    </span>
  );
}

/** "← Assets" above a detail page. */
export function BackLink({ to, state, children }: { to: string; state?: unknown; children: ReactNode }) {
  return (
    <Link to={to} state={state} className="mb-3 inline-flex items-center gap-1 text-xs text-ink2 hover:text-ink">
      <ArrowLeft className="h-3.5 w-3.5" /> {children}
    </Link>
  );
}

export interface TabItem<K extends string> {
  key: K;
  label: ReactNode;
}

/**
 * A tab list that behaves like one: a single stop in the Tab order, Left/Right/Home/End to move, and
 * each tab tied to its panel. The two tab bars this replaces announced themselves as tabs to screen
 * readers but had no panel, no aria-controls and no arrow keys -- which is worse than plain buttons,
 * since the announcement promises keys that did nothing. Put the content in <div {...tabPanel(id, key)}>.
 */
export function Tabs<K extends string>({
  id,
  label,
  tabs,
  active,
  onChange,
  className,
}: {
  id: string;
  label: string;
  tabs: readonly TabItem<K>[];
  active: K;
  onChange: (key: K) => void;
  className?: string;
}) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const move = (index: number) => {
    const next = tabs[(index + tabs.length) % tabs.length];
    onChange(next.key);
    refs.current[next.key]?.focus();
  };
  return (
    <div role="tablist" aria-label={label} className={clsx("flex gap-1", className)}>
      {tabs.map((t, i) => (
        <button
          key={t.key}
          ref={(el) => {
            refs.current[t.key] = el;
          }}
          id={`${id}-tab-${t.key}`}
          role="tab"
          aria-selected={active === t.key}
          aria-controls={`${id}-panel-${t.key}`}
          tabIndex={active === t.key ? 0 : -1}
          className={clsx(
            "-mb-px border-b-2 px-3 py-2 text-sm font-medium",
            active === t.key ? "border-accent text-ink" : "border-transparent text-ink2 hover:text-ink",
          )}
          onClick={() => onChange(t.key)}
          onKeyDown={(e) => {
            const to = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
            if (to === undefined) return;
            e.preventDefault();
            move(to);
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

/** Props for the panel belonging to tab `key` of the <Tabs> with this `id`. */
// biome-ignore lint/style/useComponentExportOnlyModules: This UI helper intentionally shares the component module.
export function tabPanel(id: string, key: string) {
  return { role: "tabpanel", id: `${id}-panel-${key}`, "aria-labelledby": `${id}-tab-${key}`, tabIndex: 0 } as const;
}
