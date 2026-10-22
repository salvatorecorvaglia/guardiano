"""Background task handlers. Importing this module registers them (see services/jobs.py)."""

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.models import (
    Asset,
    Finding,
    FindingLink,
    Integration,
    Job,
    ReportSchedule,
    Scan,
    User,
    WebhookDelivery,
)
from app.models.base import utcnow
from app.models.enums import ACTIVE_STATUSES, ROLE_RANK, Role
from app.services import (
    email,
    events,
    intel,
    jobs,
    lifecycle,
    notifications,
    reports,
    retention,
    scm,
    sla,
    tickets,
    triage,
    webhooks,
)
from app.services.jobs import DONE, handler, periodic
from app.services.queries import ACTIVE, sla_due_expr
from app.services.scope import Scope, scope_for
from app.services.serializers import finding_payload

log = logging.getLogger(__name__)


@periodic("expire_risk_acceptances", timedelta(hours=1))
def expire_risk_acceptances(db: Session, _: dict[str, Any]) -> None:
    if n := lifecycle.expire_risk_acceptances(db):
        log.info("reopened %d finding(s) with expired risk acceptance", n)


@periodic("poll_tickets", timedelta(hours=1))
def poll_tickets(db: Session, _: dict[str, Any]) -> None:
    """Ask the trackers how the linked tickets are doing. Does nothing unless TRACKER_POLL_HOURS is set."""
    tickets.poll(db)


@periodic("retention", timedelta(days=1))
def retention_sweep(db: Session, _: dict[str, Any]) -> None:
    """Apply the configured retention rules. Does nothing at all until one is switched on."""
    retention.run(db)


@periodic("prune_jobs", timedelta(days=1))
def prune_jobs(db: Session, _: dict[str, Any]) -> None:
    # Dead jobs are kept for inspection and manual retry; only successful runs are pruned.
    cutoff = utcnow() - timedelta(days=settings.job_retention_days)
    n = db.execute(delete(Job).where(Job.status == DONE, Job.finished_at < cutoff)).rowcount
    if n:
        log.info("pruned %d finished job(s)", n)
    if read := notifications.prune(db):
        log.info("pruned %d read notification(s)", read)


@handler(events.DELIVER_JOB)
def deliver_webhook(db: Session, payload: dict[str, Any]) -> None:
    """Send one queued delivery. Raising retries it through the job queue's backoff."""
    delivery = db.get(WebhookDelivery, payload.get("delivery_id"))
    if delivery is None:  # the webhook was deleted before the worker got here
        return
    webhook = delivery.webhook
    if not webhook.enabled and delivery.event != events.TEST:
        return
    if delivery.delivered_at is not None:
        return
    delivery.attempts += 1
    status, error = webhooks.deliver(delivery, webhook)
    delivery.status_code, delivery.error = status or None, error
    webhook.last_status, webhook.last_error, webhook.last_delivery_at = status or None, error, utcnow()
    if error:
        # Committed by the job runner's error path is not guaranteed, so record the attempt first.
        jobs.commit_owned(db)
        raise RuntimeError(f"webhook {webhook.id} ({webhook.name}): {error}")
    delivery.delivered_at = utcnow()


@periodic("sla_breaches", timedelta(hours=1))
def sla_breaches(db: Session, _: dict[str, Any]) -> None:
    """Emit sla.breached, once, for findings whose deadline has passed, including older backlog.

    Everything that decides "already announced" happens in SQL, before the batch limit. It used to be
    filtered in Python after LIMIT, so the same announced rows refilled the batch every hour and a
    breach past row EVENT_BATCH_LIMIT was never announced at all. What was announced is now recorded on
    the finding itself: it used to be inferred from webhook deliveries, which retention deletes and
    which do not exist when nothing subscribes, so the same findings were re-processed every hour.
    """
    now = utcnow()
    due = sla_due_expr()
    rows = db.execute(
        select(Finding, due)
        .where(
            Finding.status.in_([s.value for s in ACTIVE_STATUSES]),
            due <= now,
            or_(Finding.sla_breach_due.is_(None), Finding.sla_breach_due != due),
        )
        .order_by(due, Finding.id)
        .limit(settings.event_batch_limit)
        .with_for_update(of=Finding, skip_locked=True)
    ).all()
    for f, deadline in rows:
        f.sla_breach_due = deadline
        if f.assignee is not None:
            notifications.notify(db, [f.assignee], "sla_breached", f, "Past its remediation deadline")
        events.emit(
            db,
            events.SLA_BREACHED,
            finding_payload(f),
            asset_id=f.asset_id,
            severity=f.severity,
        )
    if rows:
        log.info("emitted sla.breached for %d finding(s)", len(rows))


@periodic("risk_acceptances_expiring", timedelta(hours=1))
def risk_acceptances_expiring(db: Session, _: dict[str, Any]) -> None:
    """Emit finding.risk_acceptance_expiring once per acceptance, some days before it ends.

    Recorded on the finding like sla_breach_due: an acceptance renewed with a new end date is announced
    again when that one approaches.
    """
    if settings.risk_acceptance_warning_days <= 0:
        return
    now = utcnow()
    horizon = now + timedelta(days=settings.risk_acceptance_warning_days)
    rows = db.scalars(
        select(Finding)
        .where(
            Finding.status == "risk_accepted",
            Finding.risk_accepted_until > now,
            Finding.risk_accepted_until <= horizon,
            or_(
                Finding.acceptance_warned_until.is_(None),
                Finding.acceptance_warned_until != Finding.risk_accepted_until,
            ),
        )
        .order_by(Finding.risk_accepted_until, Finding.id)
        .limit(settings.event_batch_limit)
    ).all()
    for f in rows:
        f.acceptance_warned_until = f.risk_accepted_until
        events.emit(
            db,
            events.RISK_ACCEPTANCE_EXPIRING,
            finding_payload(
                f,
                risk_accepted_until=f.risk_accepted_until.isoformat(),
                justification=f.status_justification,
            ),
            asset_id=f.asset_id,
            severity=f.severity,
        )
    if rows:
        log.info("emitted %s for %d finding(s)", events.RISK_ACCEPTANCE_EXPIRING, len(rows))


@handler(triage.APPLY_JOB)
def apply_triage_rule(db: Session, payload: dict[str, Any]) -> None:
    """Apply a rule to existing findings, at a manager's request (POST /triage-rules/{id}/apply)."""
    actor_id = payload.get("actor_id")
    actor = db.get(User, actor_id, populate_existing=True) if actor_id else None
    if actor is None or not actor.is_active or ROLE_RANK[Role(actor.role)] < ROLE_RANK[Role.manager]:
        log.warning("discarding triage job without a currently authorized actor")
        return
    team_ids = payload.get("team_ids")
    scope = Scope() if team_ids is None else Scope(team_ids=tuple(team_ids))
    triage.apply_to_existing(db, payload["rule_id"], scope, actor.full_name or actor.email, actor_id=actor.id)


@handler(email.SEND_JOB)
def send_email(db: Session, payload: dict[str, Any]) -> None:
    """Send one queued message. Raising retries it through the job queue's backoff."""
    kind = payload.get("kind")
    if kind in {"assignment", "digest", "report"}:
        user = db.get(User, payload.get("recipient_id"))
        if user is None or not user.is_active:
            return
        if kind == "assignment":
            finding = db.get(Finding, payload.get("finding_id"))
            if (
                finding is None
                or not user.notify_on_assignment
                or not scope_for(db, user).owns(finding.asset)
            ):
                return
            message = email.assignment(finding_payload(finding), payload.get("actor", "Guardiano"))
        elif kind == "digest":
            if user.digest_frequency != payload.get("frequency"):
                return
            rows = _digest_rows(db, user)
            if not rows["assigned"]:
                return
            message = email.digest(user.digest_frequency, rows, user.id)
        else:
            schedule = db.get(ReportSchedule, payload.get("schedule_id"))
            if schedule is None or not schedule.enabled or user not in reports.recipients(db, schedule):
                return
            message = reports.build(db, schedule, user)
        payload = message.as_payload(user.email)
    elif kind != "password_reset":
        # Pre-upgrade message bodies have no resource references with which to recheck access.
        log.warning("discarding legacy email without authorization context")
        return
    email.send(payload["to"], payload["subject"], payload["text"], payload.get("html"))


def _digest_rows(db: Session, user: User) -> dict[str, list[dict[str, Any]]]:
    """What one person's digest is about: their findings, and what is overdue or due soon."""
    now = utcnow()
    due = sla_due_expr()
    mine = (
        scope_for(db, user)
        .narrow(select(Finding), Finding.asset_id)
        .where(Finding.assignee_id == user.id, Finding.status.in_(ACTIVE))
        .options(
            selectinload(Finding.asset),
            selectinload(Finding.intel),
            selectinload(Finding.assignee),
            selectinload(Finding.links),
        )
    )
    assigned = db.scalars(mine.order_by(due).limit(settings.event_batch_limit)).unique().all()
    overdue = [f for f in assigned if (d := sla.due_at(f)) is not None and d < now]
    soon = [f for f in assigned if (d := sla.due_at(f)) is not None and now <= d <= now + timedelta(days=7)]
    return {
        "assigned": [finding_payload(f) for f in assigned],
        "overdue": [finding_payload(f) for f in overdue],
        "due_soon": [finding_payload(f) for f in soon],
    }


@periodic("email_digests", timedelta(hours=1))
def email_digests(db: Session, _: dict[str, Any]) -> None:
    """Queue the daily and weekly digests that are due, one per person, at DIGEST_HOUR_UTC."""
    if not email.enabled():
        return
    now = utcnow()
    if now.hour != settings.digest_hour_utc:
        return
    intervals = {"daily": timedelta(hours=23), "weekly": timedelta(days=6, hours=23)}
    users = db.scalars(
        select(User).where(User.is_active.is_(True), User.digest_frequency.in_(list(intervals)))
    ).all()
    sent = 0
    for user in users:
        gap = intervals[user.digest_frequency]
        if user.last_digest_at is not None and now - user.last_digest_at < gap:
            continue
        if user.digest_frequency == "weekly" and now.weekday() != 0:
            continue  # weekly digests go out on Monday
        rows = _digest_rows(db, user)
        # Nothing to say: record the run so the next one is not "overdue", but send no mail.
        user.last_digest_at = now
        if not rows["assigned"]:
            continue
        jobs.enqueue(
            db,
            email.SEND_JOB,
            {"kind": "digest", "recipient_id": user.id, "frequency": user.digest_frequency},
        )
        sent += 1
    if sent:
        log.info("queued %d %s digest(s)", sent, "daily/weekly")


@periodic("scheduled_reports", timedelta(hours=1))
def scheduled_reports(db: Session, _: dict[str, Any]) -> None:
    """Queue the weekly and monthly reports that are due, one copy per recipient, each in their scope."""
    if not email.enabled():
        return
    now = utcnow()
    for schedule in db.scalars(select(ReportSchedule).where(ReportSchedule.enabled.is_(True))):
        if not reports.due(schedule, now):
            continue
        for user in reports.recipients(db, schedule):
            jobs.enqueue(
                db, email.SEND_JOB, {"kind": "report", "recipient_id": user.id, "schedule_id": schedule.id}
            )
        schedule.last_sent_at = now
        log.info("queued report %r for %d recipient(s)", schedule.name, len(schedule.recipient_ids))


@handler(tickets.SYNC_JOB)
def sync_ticket(db: Session, payload: dict[str, Any]) -> None:
    """Order remote writes per link while keeping SQL transactions out of HTTP calls."""
    from app.services.remote_io import integration_snapshot, network_io, ordered_dispatch

    link_id = payload.get("link_id")
    with ordered_dispatch(db, f"ticket:{link_id}"):
        link = db.get(FindingLink, link_id, populate_existing=True)
        if link is None or link.integration_id is None:
            return
        config = integration_snapshot(db, link.integration_id)
        if config is None:
            return
        finding = db.get(Finding, link.finding_id, populate_existing=True)
        if finding is None:
            return
        expected = payload.get("status")
        if expected is not None and expected != finding.status:
            return
        if expected is None and (
            (payload.get("close") and finding.status in ACTIVE_STATUSES)
            or (payload.get("reopen") and finding.status != "open")
        ):
            return
        key, integration_id = link.external_key, link.integration_id
        api = tickets.provider(config.kind)
        remote_status, reopened = None, False
        try:
            with network_io(db):
                api.comment(config, key, payload["text"])
                if payload.get("close") and api.close(config, key):
                    remote_status = "closed"
                elif payload.get("reopen"):
                    reopened = api.reopen(config, key)
                    remote_status = api.fetch_status(config, key).name
        except Exception as exc:
            integration = db.get(Integration, integration_id, populate_existing=True)
            if integration is not None:
                integration.last_error = str(exc)[:500]
                jobs.commit_owned(db)
            raise
        # Re-read only the rows being updated, after the network interval.
        link = db.get(FindingLink, link_id, with_for_update=True, populate_existing=True)
        integration = db.get(Integration, integration_id, populate_existing=True)
        if link is not None and link.integration_id == integration_id:
            if remote_status is not None:
                link.remote_status = remote_status
            if reopened:
                link.remote_done_at = None
            link.synced_at = utcnow()
        if integration is not None:
            integration.last_error = None
        jobs.commit_owned(db)  # persist before releasing the cross-transaction ordering lock


@handler(tickets.AUTO_JOB)
def open_auto_ticket(db: Session, payload: dict[str, Any]) -> None:
    """Open a ticket a tracker's auto-ticket rule asked for. A failure is retried, then left for a person."""
    integration = db.get(Integration, payload.get("integration_id"))
    try:
        tickets.open_auto_ticket(db, payload["finding_id"], payload["integration_id"])
    except Exception as exc:
        if integration is not None:
            integration.last_error = str(exc)[:500]
            jobs.commit_owned(db)
        raise


@handler(scm.FEEDBACK_JOB)
def post_scm_feedback(db: Session, payload: dict[str, Any]) -> None:
    """Publish ordered SCM feedback using detached data outside SQL transactions."""
    from app.services.remote_io import integration_snapshot, network_io, ordered_dispatch, snapshot

    integration_id = payload.get("integration_id")
    with ordered_dispatch(db, f"scm:{integration_id}"):
        scan = db.get(Scan, payload.get("scan_id"), populate_existing=True)
        config = integration_snapshot(db, integration_id)
        if scan is None or config is None or not config.scm_feedback:
            return
        asset = db.get(Asset, scan.asset_id)
        if asset is None:
            return
        api = tickets.provider(config.kind)
        data = scm.payload_for(scan, asset)
        commit_sha = scan.commit_sha
        data["state"], data["description"] = scm.aggregate_outcome(db, config, commit_sha)
        if data["branch"]:
            latest = db.scalar(
                select(Scan)
                .where(
                    Scan.asset_id == asset.id,
                    Scan.branch == data["branch"],
                )
                .order_by(Scan.id.desc())
                .limit(1)
            )
            if latest is not None:
                data["comment"] = scm.comment_body(latest, asset)
        asset_snapshot = snapshot(asset)
        try:
            with network_io(db):
                api.commit_status(
                    config,
                    commit_sha,
                    data["state"],
                    data["description"],
                    data["target_url"],
                    data["context"],
                )
                number = api.find_open_pr(config, data["branch"]) if data["branch"] else None
            if number:
                scm.post_or_update_comment(db, api, config, asset_snapshot, number, data["comment"])
            integration = db.get(Integration, integration_id, populate_existing=True)
            if integration is not None:
                integration.last_error = None
                integration.last_used_at = utcnow()
            jobs.commit_owned(db)
        except Exception as exc:
            integration = db.get(Integration, integration_id, populate_existing=True)
            if integration is not None:
                integration.last_error = str(exc)[:500]
                jobs.commit_owned(db)
            raise


@periodic("intel_sync", timedelta(hours=24), priority=200)
def intel_sync(db: Session, _: dict[str, Any]) -> None:
    """Refresh the CISA KEV catalogue and the EPSS scores for the CVEs we hold."""
    if not settings.intel_sync_enabled:
        return
    counts = {"kev": intel.sync_kev(db), "epss": intel.sync_epss(db)}
    for ident in intel.pending_aliases(db):
        jobs.enqueue(db, "intel.alias", {"vuln_id": ident}, priority=200)
    log.info("exploitability sync: %s", counts)


@handler("intel.alias")
def resolve_one_alias(db: Session, payload: dict[str, Any]) -> None:
    intel.resolve_aliases(db, only=[payload["vuln_id"]])


@periodic("kev_announcements", timedelta(minutes=1))
def drain_kev_announcements(db: Session, _: dict[str, Any]) -> None:
    intel.drain_kev_announcements(db)
