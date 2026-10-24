import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, CheckCircle2, CircleDot, ExternalLink, Eye, Gauge, MessageSquare, RotateCcw, ScanLine, ShieldQuestion, Sparkles, Tag, UserPlus, Wand2 } from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import { invalidateAfterTriage, useDirectory } from "../api/queries";
import { request } from "../api/typed";
import type { FindingDetail as FD, FindingEvent, FindingUpdate, Severity } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import AcceptanceCard from "../components/AcceptanceCard";
import DueDateDialog, { type DueChange } from "../components/DueDateDialog";
import ExploitBadge from "../components/ExploitBadge";
import FindingTickets from "../components/FindingTickets";
import StatusDialog, { type StatusChange } from "../components/StatusDialog";
import TagEditor from "../components/TagEditor";
import { useToast } from "../components/Toaster";
import { BackLink, ErrorBox, SeverityBadge, Spinner, StatusBadge, TypeBadge } from "../components/ui";
import { fmtDate, fmtDateTime, relTime, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL } from "../lib/format";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-3 py-1.5 text-sm">
      <dt className="text-ink2">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="card p-4">
      <h2 className="mb-2 text-sm font-semibold">{title}</h2>
      {children}
    </section>
  );
}

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

const cweUrl = (c: string) => `https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html`;
const safeUrl = (u?: string | null) => (u && /^https?:\/\//i.test(u) ? u : undefined);

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

export default function FindingDetail() {
  const { id } = useParams();
  return <FindingDetailPage key={id} />;
}

function FindingDetailPage() {
  const { id } = useParams();
  const location = useLocation();
  // Return to the list the user came from, with its filters (falls back to all findings).
  const backTo = (location.state as { from?: string } | null)?.from ?? "/findings";
  const qc = useQueryClient();
  const { can } = useAuth();
  const directory = useDirectory();
  const toast = useToast();
  const [statusOpen, setStatusOpen] = useState(false);
  const [dueOpen, setDueOpen] = useState(false);
  const [comment, setComment] = useState("");
  const [historyPage, setHistoryPage] = useState(1);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Each finding starts on its newest history page.
  useEffect(() => setHistoryPage(1), [id]);
  const history = useQuery({
    queryKey: ["finding", id, "events", historyPage],
    queryFn: ({ signal }) => request("get", "/api/v1/findings/{finding_id}/events", { params: { finding_id: Number(id) }, signal, query: { page: historyPage, page_size: 200 } }),
    enabled: historyPage > 1,
  });

  const q = useQuery({ queryKey: ["finding", id], queryFn: ({ signal }) => request("get", "/api/v1/findings/{finding_id}", { params: { finding_id: Number(id) }, signal }) });

  const refresh = (data?: FD) => {
    setHistoryPage(1);
    if (data) qc.setQueryData(["finding", id], data);
    invalidateAfterTriage(qc, { fresh: data ? ["finding", id] : undefined });
  };

  const patch = useMutation({
    mutationFn: (body: FindingUpdate) => request("patch", "/api/v1/findings/{finding_id}", { params: { finding_id: Number(id) }, body }),
    onSuccess: (d) => {
      setStatusOpen(false);
      setDueOpen(false);
      refresh(d);
      toast("Finding updated");
    },
  });
  const addComment = useMutation({
    mutationFn: (text: string) => request("post", "/api/v1/findings/{finding_id}/comments", { params: { finding_id: Number(id) }, body: { text } }),
    onSuccess: () => {
      setComment("");
      refresh();
    },
  });

  if (q.isLoading)
    return (
      <div className="flex justify-center py-20">
        <Spinner />
      </div>
    );
  if (q.error || !q.data) return <ErrorBox error={q.error ?? "Finding not found"} />;
  const f = q.data;

  function submitComment(e: FormEvent) {
    e.preventDefault();
    if (comment.trim()) addComment.mutate(comment.trim());
  }

  return (
    <>
      <BackLink to={backTo}>Findings</BackLink>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} score={f.cvss_score} />
            <StatusBadge status={f.status} />
            <TypeBadge type={f.type} />
            <ExploitBadge finding={f} />
            {f.overdue && <span className="text-xs font-medium text-danger">Past SLA (due {fmtDate(f.sla_due_at)})</span>}
          </div>
          <h1 className="text-xl font-semibold tracking-tight">{f.title}</h1>
          <p className="mt-1 text-sm text-ink2">
            <Link className="hover:text-accent" to={`/assets/${f.asset.id}`}>
              {f.asset.name}
            </Link>{" "}
            · #{f.id} · first seen {relTime(f.first_seen_at)} · last seen {relTime(f.last_seen_at)}
          </p>
        </div>
        {can("analyst") && (
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="input w-auto"
              value={f.assignee?.id ?? ""}
              onChange={(e) => patch.mutate(e.target.value ? { assignee_id: Number(e.target.value) } : { unassign: true })}
              aria-label="Assignee"
            >
              <option value="">Unassigned</option>
              {directory.data?.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.full_name || u.email}
                </option>
              ))}
            </select>
            {f.status !== "resolved" && (
              <button className="btn-secondary" onClick={() => patch.mutate({ status: "resolved" })} disabled={patch.isPending}>
                <CheckCircle2 className="h-4 w-4" /> Resolve
              </button>
            )}
            <button
              className="btn-primary"
              onClick={() => {
                patch.reset();
                setStatusOpen(true);
              }}
            >
              Change status
            </button>
          </div>
        )}
      </div>
      <ErrorBox error={statusOpen || dueOpen ? null : patch.error} />

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <AcceptanceCard findingId={f.id} status={f.status} />
          {f.status_justification && (f.status === "false_positive" || f.status === "risk_accepted") && (
            <div className="rounded-xl border border-line bg-raised p-4 text-sm">
              <div className="mb-1 font-medium">
                {STATUS_LABEL[f.status]}
                {f.risk_accepted_until && <span className="font-normal text-ink2"> until {fmtDate(f.risk_accepted_until)}</span>}
              </div>
              <p className="whitespace-pre-wrap text-ink2">{f.status_justification}</p>
            </div>
          )}

          <Section title={{ sast: "Code location", sca: "Affected component", iac: "Infrastructure", dast: "Request" }[f.type]}>
            {f.type === "dast" ? (
              <>
                <p className="break-all font-mono text-sm">
                  {f.http_method && <span className="mr-2 font-semibold">{f.http_method}</span>}
                  {f.url ?? "unknown URL"}
                </p>
                {f.parameter && (
                  <p className="mt-1 text-sm text-ink2">
                    Parameter <span className="font-mono">{f.parameter}</span>
                  </p>
                )}
                {f.snippet && (
                  <pre className="mt-3 overflow-x-auto rounded-lg border border-line bg-page p-3 font-mono text-xs leading-relaxed">
                    {f.snippet}
                  </pre>
                )}
              </>
            ) : f.type === "sast" || f.type === "iac" ? (
              <>
                {f.resource && (
                  <p className="mb-1 text-sm">
                    Resource <span className="font-mono font-medium">{f.resource}</span>
                  </p>
                )}
                <p className="break-all font-mono text-sm">
                  {f.file_path ?? "unknown file"}
                  {f.line_start && (
                    <span className="text-ink2">
                      :{f.line_start}
                      {f.line_end && f.line_end !== f.line_start ? `-${f.line_end}` : ""}
                    </span>
                  )}
                </p>
                {f.snippet && (
                  <pre className="mt-3 overflow-x-auto rounded-lg border border-line bg-page p-3 font-mono text-xs leading-relaxed">
                    {f.snippet}
                  </pre>
                )}
              </>
            ) : (
              <dl>
                <Row label="Package">
                  <span className="font-mono">{f.package_name}</span>
                </Row>
                <Row label="Installed">
                  <span className="font-mono">{f.package_version ?? "–"}</span>
                </Row>
                <Row label="Fixed in">
                  {f.fixed_version ? <span className="font-mono font-medium text-good">{f.fixed_version}</span> : "No fix available"}
                </Row>
                {f.ecosystem && <Row label="Ecosystem">{f.ecosystem}</Row>}
                {f.purl && (
                  <Row label="purl">
                    <span className="break-all font-mono text-xs">{f.purl}</span>
                  </Row>
                )}
                {f.file_path && (
                  <Row label="Manifest">
                    <span className="font-mono text-xs">{f.file_path}</span>
                  </Row>
                )}
              </dl>
            )}
          </Section>

          {f.description && (
            <Section title="Description">
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink2">{f.description}</p>
            </Section>
          )}
          {f.remediation && (
            <Section title="Remediation">
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink2">{f.remediation}</p>
            </Section>
          )}

          <Section title="Activity">
            {can("analyst") && (
              <form onSubmit={submitComment} className="mb-4 space-y-2">
                <textarea
                  className="input min-h-[72px]"
                  placeholder="Add a comment… (@name@example.com notifies them)"
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  aria-label="Comment"
                />
                <div className="flex justify-end">
                  <button className="btn-secondary" disabled={!comment.trim() || addComment.isPending}>
                    Comment
                  </button>
                </div>
                <ErrorBox error={addComment.error} />
              </form>
            )}
            <ol className="relative space-y-4 border-l border-line pl-5">
              {(historyPage === 1 ? f.events : history.data?.items ?? []).map((e) => (
                <li key={e.id} className="relative">
                  <span className="absolute -left-[29px] flex h-[18px] w-[18px] items-center justify-center rounded-full border border-line bg-raised text-ink2">
                    {EVENT_ICON[e.event] ?? <CircleDot className="h-3.5 w-3.5" />}
                  </span>
                  <div className="text-sm">{eventText(e)}</div>
                  <div className="text-xs text-muted" title={fmtDateTime(e.created_at)}>
                    {fmtDateTime(e.created_at)}
                  </div>
                  {e.comment && !INLINE_COMMENT.has(e.event) && (
                    <p className="mt-1.5 whitespace-pre-wrap rounded-lg bg-page px-3 py-2 text-sm text-ink2">
                      {e.event === "comment" ? withMentions(e.comment) : e.comment}
                    </p>
                  )}
                </li>
              ))}
            </ol>
            <ErrorBox error={history.error} />
            {(f.events_total ?? 0) > 200 && (
              <div className="mt-4 flex items-center justify-between gap-3">
                <button className="btn-secondary" disabled={historyPage === 1 || history.isFetching}
                  onClick={() => setHistoryPage((page) => page - 1)}>Newer events</button>
                <span className="text-sm text-muted">Page {historyPage} of {Math.ceil(f.events_total / 200)}</span>
                <button className="btn-secondary" disabled={historyPage * 200 >= f.events_total || history.isFetching}
                  onClick={() => setHistoryPage((page) => page + 1)}>Older events</button>
              </div>
            )}
          </Section>
        </div>

        <div className="space-y-4">
          <Section title="Details">
            <dl className="divide-y divide-line">
              <Row label="Tools">{f.tools.join(", ")}</Row>
              {f.rule_id && (
                <Row label="Rule">
                  <span className="break-all font-mono text-xs">{f.rule_id}</span>
                </Row>
              )}
              {f.cve_id && (
                <Row label="CVE">
                  <a className="inline-flex items-center gap-1 text-accent hover:underline" href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer">
                    {f.cve_id} <ExternalLink className="h-3 w-3" />
                  </a>
                  <Link className="ml-2 text-xs text-accent hover:underline" to={`/vulnerabilities/${f.cve_id}`}>
                    Across the estate
                  </Link>
                </Row>
              )}
              {f.vuln_id && f.vuln_id !== f.cve_id && <Row label="Advisory">{f.vuln_id}</Row>}
              {f.cwe.length > 0 && (
                <Row label="CWE">
                  <span className="flex flex-wrap gap-x-2">
                    {f.cwe.map((c) => (
                      <a key={c} className="text-accent hover:underline" href={cweUrl(c)} target="_blank" rel="noreferrer">
                        {c}
                      </a>
                    ))}
                  </span>
                </Row>
              )}
              <Row label="CVSS">{f.cvss_score?.toFixed(1) ?? "–"}</Row>
              {f.epss != null && (
                <Row label="EPSS">
                  {(f.epss * 100).toFixed(1)}% chance in 30 days
                  {f.epss_percentile != null && (
                    <span className="block text-xs text-muted">
                      higher than {(f.epss_percentile * 100).toFixed(0)}% of all CVEs
                    </span>
                  )}
                </Row>
              )}
              {f.in_kev && (
                <Row label="Exploited">
                  Listed by CISA{f.kev_ransomware && ", used in ransomware"}
                  {f.kev_due_date && (
                    <span className="block text-xs text-muted">US federal due date {fmtDate(f.kev_due_date)}</span>
                  )}
                </Row>
              )}
              <Row label="First seen">{fmtDateTime(f.first_seen_at)}</Row>
              <Row label="Last seen">{fmtDateTime(f.last_seen_at)}</Row>
              <Row label="Severity">
                {SEVERITY_LABEL[f.severity]}
                {f.severity_override && (
                  <span className="ml-1 text-xs text-muted">
                    (set manually{f.scanner_severity && f.scanner_severity !== f.severity ? `; scanners report ${SEVERITY_LABEL[f.scanner_severity].toLowerCase()}` : ""})
                  </span>
                )}
                {can("manager") && (
                  <select
                    className="input ml-2 w-auto px-1.5 py-0.5 text-xs"
                    aria-label="Change severity"
                    value={f.severity_override ?? ""}
                    disabled={patch.isPending}
                    onChange={(e) => patch.mutate(e.target.value ? { severity: e.target.value as Severity } : { clear_severity_override: true })}
                  >
                    <option value="">As reported{f.scanner_severity ? ` (${SEVERITY_LABEL[f.scanner_severity].toLowerCase()})` : ""}</option>
                    {SEVERITIES.map((sev) => (
                      <option key={sev} value={sev}>
                        {SEVERITY_LABEL[sev]}
                      </option>
                    ))}
                  </select>
                )}
              </Row>
              <Row label="Due">
                <span className={f.overdue ? "font-medium text-danger" : undefined}>{fmtDate(f.sla_due_at)}</span>
                {f.due_at_override && <span className="ml-1 text-xs text-muted">(set manually)</span>}
                {can("manager") && (
                  <button
                    className="ml-2 text-xs text-accent hover:underline"
                    aria-label="Change due date"
                    onClick={() => {
                      patch.reset();
                      setDueOpen(true);
                    }}
                  >
                    Change
                  </button>
                )}
              </Row>
              <Row label="Tickets">
                <FindingTickets
                  findingId={f.id}
                  links={f.links ?? []}
                  canEdit={can("analyst")}
                  onChange={() => refresh()}
                />
              </Row>
              <Row label="Tags">
                <TagEditor
                  tags={f.tags ?? []}
                  pending={patch.isPending}
                  onChange={can("analyst") ? (tags) => patch.mutate({ tags }) : undefined}
                />
              </Row>
              {f.closed_at && <Row label="Closed">{fmtDateTime(f.closed_at)}</Row>}
              <Row label="Detections">{f.occurrence_count}</Row>
              <Row label="Assignee">{f.assignee ? f.assignee.full_name || f.assignee.email : "Unassigned"}</Row>
            </dl>
          </Section>
          {f.references.length > 0 && (
            <Section title="References">
              <ul className="space-y-1.5 text-sm">
                {f.references.map((r, i) =>
                  safeUrl(r.url) ? (
                    <li key={i}>
                      <a className="inline-flex items-start gap-1 break-all text-accent hover:underline" href={safeUrl(r.url)} target="_blank" rel="noreferrer noopener">
                        {r.title || r.url} <ExternalLink className="mt-1 h-3 w-3 shrink-0" />
                      </a>
                    </li>
                  ) : null,
                )}
              </ul>
            </Section>
          )}
        </div>
      </div>

      {dueOpen && (
        <DueDateDialog
          finding={f}
          onClose={() => setDueOpen(false)}
          pending={patch.isPending}
          error={patch.error}
          onSubmit={(c: DueChange) => patch.mutate({ ...c })}
        />
      )}
      {statusOpen && (
        <StatusDialog
          open
          current={f.status}
          onClose={() => setStatusOpen(false)}
          pending={patch.isPending}
          error={patch.error}
          onSubmit={(c: StatusChange) => patch.mutate({ ...c })}
        />
      )}
    </>
  );
}
