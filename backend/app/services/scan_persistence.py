"""Apply a matched scan's findings, resolution rules and transactional side effects."""

import logging
from collections import Counter
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, FindingEvent, FindingLink, FindingScan, Scan, User
from app.models.enums import ACTIVE_STATUSES, EventType, Status
from app.services import events, gate, inventory, lifecycle, tickets, triage
from app.services.dedup import normalize_path
from app.services.scan_context import ScanContext
from app.services.scan_events import _EVENT_CAP, _emit_scan_events
from app.services.scan_report import _new_finding, reported_severity
from app.services.serializers import finding_payload

log = logging.getLogger(__name__)

_UPDATABLE = (
    "title",
    "description",
    "remediation",
    "cvss_score",
    "cwe",
    "rule_id",
    "line_end",
    "snippet",
    "purl",
    "ecosystem",
    "vuln_id",
    "fixed_version",
    "references",
)


@dataclass(frozen=True)
class AppliedFindings:
    new: int
    duplicate: int
    reopened: int
    new_by_severity: Counter[str]
    created: list[Finding]
    notable_new: list[Finding]
    notable_reopened: list[Finding]
    reopened_from: list[tuple[Finding, str]]


def apply_findings(db: Session, context: ScanContext) -> AppliedFindings:
    asset, scan, now = context.asset, context.scan, context.now
    batch, sources = context.prepared.findings.by_key, context.prepared.findings.sources
    existing, moved = context.existing, context.moved
    assignee = db.get(User, asset.default_assignee_id) if asset.default_assignee_id else None
    if assignee is not None and not assignee.is_active:
        assignee = None
    new_count = dup_count = reopened = 0
    new_by_severity: Counter[str] = Counter()
    touched: list[Finding] = []
    rules = triage.load_rules(db, asset.id, now)
    rule_ctx = triage.context(db, asset, rules, (nf.cve_id for nf in batch.values())) if rules else None
    new_findings: list[Finding] = []
    created: list[Finding] = []  # every new finding, uncapped: auto-ticketing applies its own cap
    reopened_from: list[tuple[Finding, str]] = []  # every reopened finding and the status it left
    reopened_findings: list[Finding] = []
    for key, nf in batch.items():
        f = existing.get(key)
        if f is None:
            f = _new_finding(asset, key, nf, scan, now)
            f.tools = sources[key]
            db.add(f)
            db.add(
                FindingEvent(
                    finding=f,
                    event=EventType.created.value,
                    to_status=f.status,
                    scan_id=scan.id,
                    comment=f"Detected by {nf.tool_name}",
                    created_at=now,
                )
            )
            if assignee is not None:
                f.assignee_id = assignee.id
                db.add(
                    FindingEvent(
                        finding=f,
                        event=EventType.assigned.value,
                        comment=f"Assigned to {assignee.full_name or assignee.email} "
                        f"(default assignee of {asset.name})",
                        scan_id=scan.id,
                        created_at=now,
                    )
                )
            if rules:
                # Auto-triage runs on brand-new findings only, never on ones a person has triaged.
                triage.apply_rules(db, f, rules, scan_id=scan.id, now=now, ctx=rule_ctx)
            new_count += 1
            created.append(f)
            new_by_severity[f.severity] += 1
            if len(new_findings) < _EVENT_CAP:
                new_findings.append(f)
        else:
            dup_count += 1
            if key in moved:
                where = f"{f.file_path}:{f.line_start}" if f.file_path else "its previous location"
                new_where = f"{normalize_path(nf.file_path)}:{nf.line_start}"
                f.file_path = normalize_path(nf.file_path) or None
                f.line_start = nf.line_start
                # The key follows the new location; no other finding can hold it (it was not in `existing`).
                f.dedup_key = key
                db.add(
                    FindingEvent(
                        finding=f,
                        event=EventType.seen_again.value,
                        comment=f"Moved from {where} to {new_where} (same {nf.tool_name} fingerprint)",
                        scan_id=scan.id,
                        created_at=now,
                    )
                )
            primary = not f.tools or f.tools[0] == nf.tool_name
            for attr in _UPDATABLE:
                val = getattr(nf, attr)
                # The originating tool refreshes metadata; other tools only fill gaps.
                if val not in (None, "", []) and (primary or getattr(f, attr) in (None, "", [])):
                    setattr(f, attr, val)
            # Severity is kept apart from the loop above: what the scanners say is recorded, but the
            # severity in effect stays whatever a person or a rule decided (severity_override).
            reported = reported_severity(f, nf)
            if not primary and reported != (f.scanner_severity or f.severity):
                f.cvss_score = nf.cvss_score or f.cvss_score
            f.scanner_severity = reported
            before_severity = f.severity
            f.severity = f.severity_override or reported
            if before_severity != f.severity:
                db.add(
                    FindingEvent(
                        finding=f,
                        event=EventType.severity_changed.value,
                        from_severity=before_severity,
                        to_severity=f.severity,
                        scan_id=scan.id,
                    )
                )
            f.tools = list(dict.fromkeys([*(f.tools or []), *sources[key]]))
            f.last_seen_at = max(f.last_seen_at, now) if f.last_seen_at else now
            f.last_scan_id = scan.id
            f.occurrence_count = (f.occurrence_count or 0) + 1

            reason = None
            if f.status == Status.resolved.value:
                reason = f"Detected again by {nf.tool_name} after being resolved"
            elif (
                f.status == Status.risk_accepted.value
                and f.risk_accepted_until is not None
                and f.risk_accepted_until <= now
            ):
                reason = "Risk acceptance expired and the issue is still present"
            if reason:
                reopened_from.append((f, f.status))
                lifecycle.reopen(db, f, reason, scan_id=scan.id, now=now)
                reopened += 1
                if reopened <= _EVENT_CAP:
                    reopened_findings.append(f)
        touched.append(f)

    db.flush()
    if touched:
        db.add_all([FindingScan(finding_id=f.id, scan_id=scan.id) for f in touched])

    return AppliedFindings(
        new_count,
        dup_count,
        reopened,
        new_by_severity,
        created,
        new_findings,
        reopened_findings,
        reopened_from,
    )


def resolve_missing(db: Session, context: ScanContext) -> int:
    asset, scan, opts, now = context.asset, context.scan, context.options, context.now
    batch, report_tools = context.prepared.findings.by_key, context.prepared.findings.tools
    report, scan_type = context.prepared.report, context.prepared.scan_type
    # 3. Optionally resolve active findings from the reporting tool(s) that were not reported this time.
    auto_resolved = 0
    if opts.close_missing and not batch and not opts.allow_empty:
        # An empty report usually means the scanner failed or everything was filtered out; resolving
        # every open finding on that basis is almost never intended.
        log.warning("scan %s: empty report, close_missing skipped (pass allow_empty to override)", scan.id)
    elif opts.close_missing:
        stale = db.scalars(
            select(Finding).where(
                Finding.asset_id == asset.id,
                # Every type the run looked for, so a Trivy run with no misconfigurations left still
                # resolves the ones it reported before.
                Finding.type.in_(sorted({scan_type, *report.covered_types})),
                Finding.status.in_([s.value for s in ACTIVE_STATUSES]),
                Finding.tools.overlap(sorted(report_tools)),
                Finding.last_scan_id.is_distinct_from(scan.id),
                Finding.first_seen_at <= now,
            )
        ).all()
        for f in stale:
            gone = [t for t in f.tools if t in report_tools]
            remaining = [t for t in f.tools if t not in report_tools]
            if remaining:
                # Another scanner still reports it: drop only this tool instead of resolving.
                f.tools = remaining
                db.add(
                    FindingEvent(
                        finding=f,
                        event=EventType.no_longer_reported.value,
                        comment=f"No longer reported by {', '.join(gone)} (scan #{scan.id}); "
                        f"still reported by {', '.join(remaining)}",
                        scan_id=scan.id,
                        created_at=now,
                    )
                )
                continue
            lifecycle.set_status(
                db,
                f,
                Status.resolved,
                actor=None,
                justification=f"Not detected by {', '.join(gone)} in scan #{scan.id}",
                event=EventType.auto_resolved,
                scan_id=scan.id,
                now=now,
            )
            auto_resolved += 1

    return auto_resolved


def persist_scan(db: Session, context: ScanContext) -> Scan:
    asset, scan, now = context.asset, context.scan, context.now
    batch, existing = context.prepared.findings.by_key, context.existing
    tool_name = context.prepared.findings.tool_name
    components = context.prepared.components
    new_in_scan = [nf for key, nf in batch.items() if key not in existing]
    result = apply_findings(db, context)
    auto_resolved = resolve_missing(db, context)
    new_count, dup_count, reopened = result.new, result.duplicate, result.reopened
    new_by_severity, created = result.new_by_severity, result.created
    new_findings, reopened_findings = result.notable_new, result.notable_reopened
    reopened_from = result.reopened_from
    db.flush()  # gate queries must observe auto-resolutions in this transaction
    scan.gate_result = gate.evaluate(
        db,
        asset=asset,
        new_by_severity=new_by_severity,
        reopened=reopened,
        policy=gate.policy_for(db, asset.id),
        new=new_in_scan,
        components=components,
    )
    scan.total_count = len(batch)
    scan.new_count = new_count
    scan.duplicate_count = dup_count
    scan.reopened_count = reopened
    scan.auto_resolved_count = auto_resolved

    # An SBOM also tells us what the asset ships, vulnerable or not.
    inventory.record(db, asset, scan, components, now)

    # Linked tickets hear about a reopen as they do when a person reopens a finding. One query finds
    # which reopened findings have tickets at all, rather than loading each one's links.
    if reopened_from:
        linked = set(
            db.scalars(
                select(FindingLink.finding_id).where(
                    FindingLink.finding_id.in_([f.id for f, _ in reopened_from])
                )
            )
        )
        for f, previous in reopened_from:
            if f.id in linked:
                tickets.queue_status_sync(db, f, previous, f"Guardiano (scan #{scan.id})")

    db.flush()  # findings need ids before they appear in an event payload
    tickets.queue_auto_tickets(db, asset.id, created)
    notable = [finding_payload(f) for f in new_findings if f.status in ACTIVE_STATUSES]
    _emit_scan_events(db, scan, asset, False, notable)
    for f in reopened_findings:
        events.emit(
            db,
            events.FINDING_REOPENED,
            finding_payload(f, scan_id=scan.id),
            asset_id=asset.id,
            severity=f.severity,
        )
    db.commit()
    log.info(
        "scan %s ingested: asset=%s tool=%s new=%d duplicate=%d reopened=%d auto_resolved=%d gate=%s",
        scan.id,
        asset.name,
        tool_name,
        new_count,
        dup_count,
        reopened,
        auto_resolved,
        gate.summary_line(scan),
    )
    return scan
