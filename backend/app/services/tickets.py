"""Creating and updating tickets for findings.

Creation is synchronous: somebody clicked a button and wants the link, so a failure must be reported to
them. Everything that follows a finding around — a comment when its status changes — runs in the worker,
because nobody is waiting for it and a tracker being down must not fail a triage action.
"""

import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Finding, FindingLink, Integration, TicketOperation, User, VulnIntel
from app.models.base import utcnow
from app.models.enums import ACTIVE_STATUSES, CLOSED_STATUSES, SEVERITY_RANK, Status
from app.services import events, jobs, lifecycle
from app.services.serializers import finding_payload, finding_url
from app.services.trackers import github, gitlab, jira
from app.services.trackers.base import RemoteState, Ticket, TicketContent, TrackerError, describe

log = logging.getLogger(__name__)

PROVIDERS = {"jira": jira, "github": github, "gitlab": gitlab}
SYNC_JOB = "tracker.sync"


def provider(kind: str) -> Any:
    try:
        return PROVIDERS[kind]
    except KeyError:
        raise TrackerError(f"Unknown tracker '{kind}'")


def available(db: Session, asset_id: int) -> list[Integration]:
    """Trackers usable for an asset: the ones bound to it, and the ones bound to no asset."""
    return list(
        db.scalars(
            select(Integration)
            .where(
                Integration.enabled.is_(True),
                or_(Integration.asset_id == asset_id, Integration.asset_id.is_(None)),
            )
            .order_by(Integration.asset_id.is_(None), Integration.id)
        )
    )


def create_ticket(db: Session, finding: Finding, integration: Integration, actor: User | None) -> FindingLink:
    """Open a ticket and link it. Raises TrackerError, which the endpoint turns into a 502."""
    key = (finding.id, integration.id)
    existing = db.scalar(
        select(FindingLink).where(
            FindingLink.finding_id == finding.id, FindingLink.integration_id == integration.id
        )
    )
    if existing is not None:
        return existing
    marker = f"guardiano-f{finding.id}-i{integration.id}"
    db.execute(
        pg_insert(TicketOperation)
        .values(finding_id=finding.id, integration_id=integration.id, marker=marker)
        .on_conflict_do_nothing()
    )
    operation = db.get(TicketOperation, key, with_for_update=True, populate_existing=True)
    api = provider(integration.kind)
    retrying = operation.dispatched_at is not None
    operation.dispatched_at = operation.dispatched_at or utcnow()
    jobs.commit_owned(db)  # reservation survives an ambiguous remote outcome or a worker crash
    finding._ticket_integration_id = integration.id
    from app.services.remote_io import network_io, snapshot

    content, config = TicketContent(finding.id, *describe(finding)), snapshot(integration)
    if retrying:
        with network_io(db):
            ticket = api.find_issue(config, marker)
        if ticket is None:
            raise TrackerError(
                "A previous ticket request has an uncertain outcome; reconciliation found no issue yet. "
                "Check the tracker before retrying."
            )
    else:
        try:
            with network_io(db):
                ticket: Ticket = api.create_issue(config, content)
        except TrackerError as exc:
            if exc.definitely_not_created:
                operation = db.get(TicketOperation, key, with_for_update=True, populate_existing=True)
                operation.dispatched_at = None
                jobs.commit_owned(db)
            raise
    # Serialize local persistence after remote reconciliation.
    db.get(TicketOperation, key, with_for_update=True, populate_existing=True)
    existing = db.scalar(
        select(FindingLink).where(
            FindingLink.finding_id == finding.id, FindingLink.integration_id == integration.id
        )
    )
    if existing is not None:
        return existing
    link = FindingLink(
        finding_id=finding.id,
        integration_id=integration.id,
        system=integration.kind,
        external_key=ticket.key,
        url=ticket.url,
        remote_status=ticket.status,
        created_by_id=actor.id if actor else None,
        synced_at=utcnow(),
    )
    db.add(link)
    integration.last_used_at, integration.last_error = utcnow(), None
    log.info("opened %s ticket %s for finding %s", integration.kind, ticket.key, finding.id)
    return link


def status_note(finding: Finding, previous: str, actor: str | None) -> str:
    """The comment posted on linked tickets when a finding's status changes."""
    who = actor or "Guardiano"
    lines = [f"{who} changed this finding from **{previous}** to **{finding.status}** in Guardiano."]
    if finding.status_justification:
        lines.append(f"\n> {finding.status_justification}")
    if url := finding_url(finding.id):
        lines.append(f"\n{url}")
    return "\n".join(lines)


def queue_status_sync(db: Session, finding: Finding, previous: str, actor: str | None) -> int:
    """Queue a comment (and a close, where the tracker supports it) on every linked ticket."""
    # The relationship, not a query: a bulk update loads every finding's links in one go, and asking
    # per finding here made updating N findings cost N extra round trips.
    links = list(finding.links)
    for link in links:
        jobs.enqueue(
            db,
            SYNC_JOB,
            {
                "link_id": link.id,
                "status": finding.status,
                "text": status_note(finding, previous, actor),
                "close": finding.status in {s.value for s in CLOSED_STATUSES},
                "reopen": finding.status == Status.open.value
                and previous in {s.value for s in CLOSED_STATUSES},
            },
        )
    return len(links)


def due_for_poll(db: Session, now: datetime, hours: int, limit: int) -> list[FindingLink]:
    """Links worth asking about: an active finding, a live tracker, and not checked recently.

    Findings that are already closed are skipped — their ticket's state cannot suggest anything useful —
    and the oldest check goes first, so a large estate works its way round rather than starving.
    """
    stale = now - timedelta(hours=hours)
    return list(
        db.scalars(
            select(FindingLink)
            .join(Finding, Finding.id == FindingLink.finding_id)
            .join(Integration, Integration.id == FindingLink.integration_id)
            .where(
                Finding.status.in_([s.value for s in ACTIVE_STATUSES]),
                Integration.enabled.is_(True),
                or_(FindingLink.synced_at.is_(None), FindingLink.synced_at < stale),
            )
            .order_by(FindingLink.synced_at.is_not(None), FindingLink.synced_at, FindingLink.id)
            .limit(limit)
        )
    )


def apply_remote_state(db: Session, link: FindingLink, state: RemoteState, now: datetime) -> bool:
    """Record what the tracker said. Returns whether this is news.

    A ticket that has just been finished becomes a *suggestion* on the finding, noted once in its
    history, unless the integration has ``close_resolves_finding`` on: then the finding is resolved,
    with the ticket named as the reason. It is not synced back to that ticket, which would only close
    what is already closed. A ticket reopened in the tracker withdraws a suggestion quietly; a finding
    it resolved stays resolved until a scan reports it again.
    """
    was_done = link.remote_done_at is not None
    link.remote_status = (state.name or "")[:50] or None
    link.synced_at = now
    if state.done and not was_done:
        link.remote_done_at = now
        finding = db.get(Finding, link.finding_id, with_for_update=True, populate_existing=True)
        if finding is None:  # gone since the link was read; nothing to note it on
            return True
        active = finding.status in {s.value for s in ACTIVE_STATUSES}
        if link.integration.close_resolves_finding and active:
            previous = finding.status
            reason = f"The linked {link.system} ticket {link.external_key} was {state.name or 'closed'}"
            lifecycle.set_status(db, finding, Status.resolved, actor=None, justification=reason, now=now)
            events.emit(
                db,
                events.FINDING_STATUS_CHANGED,
                finding_payload(
                    finding, previous_status=previous, actor=f"{link.system} ticket", justification=reason
                ),
                asset_id=finding.asset_id,
                severity=finding.severity,
            )
            return True
        lifecycle.add_comment(
            db,
            finding,
            f"The linked {link.system} ticket {link.external_key} is now "
            f"{state.name or 'closed'}. Somebody still needs to decide whether this finding is resolved.",
            actor=None,
        )
        return True
    if not state.done and was_done:
        link.remote_done_at = None
        return True
    return False


def poll(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Ask each tracker how its tickets are doing. Off unless TRACKER_POLL_HOURS is set."""
    hours = settings.tracker_poll_hours
    if hours <= 0:
        return {"checked": 0, "changed": 0, "failed": 0}
    now = now or utcnow()
    checked = changed = failed = 0
    from app.services.remote_io import integration_snapshot, network_io, ordered_dispatch

    link_ids = [link.id for link in due_for_poll(db, now, hours, settings.tracker_poll_limit)]
    jobs.commit_owned(db)
    for link_id in link_ids:
        try:
            with ordered_dispatch(db, f"ticket:{link_id}"):
                link = db.get(FindingLink, link_id, populate_existing=True)
                if link is None or link.integration_id is None:
                    continue
                config = integration_snapshot(db, link.integration_id)
                if config is None:
                    continue
                integration_id, key = config.id, link.external_key
                try:
                    with network_io(db):
                        state = provider(config.kind).fetch_status(config, key)
                except Exception as exc:
                    failed += 1
                    integration = db.get(Integration, integration_id, populate_existing=True)
                    link = db.get(FindingLink, link_id, populate_existing=True)
                    if integration is not None:
                        integration.last_error = str(exc)[:500]
                    if link is not None:
                        link.synced_at = now
                    jobs.commit_owned(db)
                    log.warning("could not read ticket %s: %s", key, exc)
                    continue
                checked += 1
                link = db.get(FindingLink, link_id, with_for_update=True, populate_existing=True)
                if link is None or link.integration_id != integration_id:
                    continue
                integration = db.get(Integration, integration_id, populate_existing=True)
                if integration is None or not integration.enabled:
                    continue
                integration.last_error = None
                try:
                    with db.begin_nested():
                        changed += int(apply_remote_state(db, link, state, now))
                except Exception as exc:
                    failed += 1
                    log.warning("could not record ticket %s: %s", key, exc)
                jobs.commit_owned(db)
        except TrackerError as exc:
            failed += 1
            log.info("ticket %s deferred: %s", link_id, exc)
    if checked or failed:
        log.info("polled %d ticket(s), %d changed, %d failed", checked, changed, failed)
    return {"checked": checked, "changed": changed, "failed": failed}


AUTO_JOB = "tracker.create"


def wants_ticket(integration: Integration, finding: Finding, exploited: set[str]) -> bool:
    if finding.status not in {s.value for s in ACTIVE_STATUSES}:
        return False  # a rule already suppressed it
    floor = integration.auto_ticket_min_severity
    if floor and SEVERITY_RANK.get(finding.severity, 0) >= SEVERITY_RANK.get(floor, 99):
        return True
    return bool(integration.auto_ticket_kev and finding.cve_id in exploited)


def queue_auto_tickets(db: Session, asset_id: int, created: list[Finding]) -> int:
    """Queue a ticket for each new finding a tracker asks for, at most AUTO_TICKET_PER_SCAN in all.

    Queued, not opened here: an upload must not wait on a tracker, or fail because one is down.
    The caller commits.
    """
    trackers = [i for i in available(db, asset_id) if i.auto_ticket_min_severity or i.auto_ticket_kev]
    if not trackers or not created:
        return 0
    cves = sorted({f.cve_id for f in created if f.cve_id})
    exploited: set[str] = set()
    if cves and any(i.auto_ticket_kev for i in trackers):
        kev = select(VulnIntel.cve_id).where(VulnIntel.cve_id.in_(cves), VulnIntel.in_kev.is_(True))
        exploited = set(db.scalars(kev))
    queued = skipped = 0
    for integration in trackers:
        for f in created:
            if not wants_ticket(integration, f, exploited):
                continue
            if queued >= settings.auto_ticket_per_scan:
                skipped += 1
                continue
            jobs.enqueue(db, AUTO_JOB, {"finding_id": f.id, "integration_id": integration.id})
            queued += 1
    if skipped:
        log.warning("asset %s: %d automatic ticket(s) not opened (AUTO_TICKET_PER_SCAN)", asset_id, skipped)
    return queued


def open_auto_ticket(db: Session, finding_id: int, integration_id: int) -> FindingLink | None:
    """The job: open the ticket unless one exists or the finding closed meanwhile. Raises TrackerError."""
    finding = db.get(Finding, finding_id)
    integration = db.get(Integration, integration_id)
    if finding is None or integration is None or not integration.enabled:
        return None
    if finding.status not in {s.value for s in ACTIVE_STATUSES}:
        return None
    if any(link.integration_id == integration.id for link in finding.links):
        return None  # somebody opened one by hand, or an earlier attempt did
    link = create_ticket(db, finding, integration, None)
    lifecycle.add_comment(
        db, finding, f"Ticket {link.external_key} opened automatically in {integration.name}", actor=None
    )
    return link
