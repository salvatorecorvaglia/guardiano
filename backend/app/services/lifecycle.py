"""Remediation lifecycle: status transitions, permissions and audit events."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Finding, FindingEvent, User
from app.models.base import utcnow
from app.models.enums import CLOSED_STATUSES, ROLE_RANK, EventType, Role, Status
from app.services.errors import PermissionDenied, ValidationFailed

JUSTIFICATION_REQUIRED = {Status.false_positive, Status.risk_accepted}


def ensure_can_override_due(user: User) -> None:
    # Moving a remediation deadline is a governance decision, like accepting a risk.
    if ROLE_RANK[Role(user.role)] < ROLE_RANK[Role.manager]:
        raise PermissionDenied("Changing a due date requires manager or higher")


def min_role_for_status(target: Status, current: str | None = None) -> Role:
    if target == Status.risk_accepted:
        return Role.manager
    # Turning a manager's time-limited acceptance into a permanent suppression needs the same authority.
    if target == Status.false_positive and current == Status.risk_accepted.value:
        return Role.manager
    return Role.analyst


def ensure_can_set_status(user: User, target: Status, current: str | None = None) -> None:
    if target == Status.risk_accepted and settings.risk_acceptance_four_eyes:
        raise PermissionDenied(
            "Risk acceptance needs a second person here: request it on the finding, and another manager "
            "approves the request"
        )
    needed = min_role_for_status(target, current)
    if ROLE_RANK[Role(user.role)] < ROLE_RANK[needed]:
        if current == Status.risk_accepted.value and target != Status.risk_accepted:
            raise PermissionDenied(
                f"Changing a risk-accepted finding to '{target.value}' requires {needed.value} or higher"
            )
        raise PermissionDenied(
            f"Role '{user.role}' cannot set status '{target.value}' (requires {needed.value} or higher)"
        )


def validate_transition(
    target: Status,
    justification: str | None,
    risk_accepted_until: datetime | None = None,
    now: datetime | None = None,
) -> None:
    if target in JUSTIFICATION_REQUIRED and not (justification and justification.strip()):
        raise ValidationFailed(f"A justification is required to mark a finding as '{target.value}'")
    if target == Status.risk_accepted:
        validate_acceptance_window(risk_accepted_until, now)


def validate_acceptance_window(until: datetime | None, now: datetime | None = None) -> None:
    """The end date a risk acceptance may have: in the future, and within the configured bounds."""
    now = now or utcnow()
    if until is not None and until <= now:
        raise ValidationFailed("risk_accepted_until must be in the future")
    if until is None and (settings.risk_acceptance_require_expiry or settings.risk_acceptance_max_days > 0):
        raise ValidationFailed("A risk acceptance needs an end date (risk_accepted_until)")
    limit = settings.risk_acceptance_max_days
    if limit > 0 and until is not None and until > now + timedelta(days=limit):
        raise ValidationFailed(f"A risk acceptance may last at most {limit} days")


def set_status(
    db: Session,
    finding: Finding,
    target: Status,
    *,
    actor: User | None,
    justification: str | None = None,
    risk_accepted_until: datetime | None = None,
    event: EventType = EventType.status_changed,
    scan_id: int | None = None,
    now: datetime | None = None,
) -> bool:
    """Apply a status change. Returns False when nothing changed."""
    now = now or utcnow()
    previous = finding.status
    until = risk_accepted_until if target == Status.risk_accepted else None
    if previous == target.value and finding.risk_accepted_until == until and not justification:
        return False

    finding.status = target.value
    if target in CLOSED_STATUSES:
        if previous not in {s.value for s in CLOSED_STATUSES} or finding.closed_at is None:
            finding.closed_at = now
    else:
        finding.closed_at = None
    finding.risk_accepted_until = until
    if justification is not None:
        finding.status_justification = justification.strip() or None
    elif target not in JUSTIFICATION_REQUIRED:
        finding.status_justification = None

    db.add(
        FindingEvent(
            finding=finding,
            actor_id=actor.id if actor else None,
            event=event.value,
            from_status=previous,
            to_status=target.value,
            comment=justification,
            scan_id=scan_id,
            created_at=now,
        )
    )
    return True


def reopen(
    db: Session, finding: Finding, reason: str, *, scan_id: int | None = None, now: datetime | None = None
) -> None:
    set_status(
        db,
        finding,
        Status.open,
        actor=None,
        justification=reason,
        event=EventType.reopened,
        scan_id=scan_id,
        now=now,
    )


def expire_risk_acceptances(db: Session, now: datetime | None = None) -> int:
    """Reopen every finding whose risk acceptance has expired. The caller commits."""
    now = now or utcnow()
    rows = db.scalars(
        select(Finding).where(
            Finding.status == Status.risk_accepted.value,
            Finding.risk_accepted_until.is_not(None),
            Finding.risk_accepted_until <= now,
        )
        .order_by(Finding.id)
        .with_for_update(of=Finding, skip_locked=True)
        .execution_options(populate_existing=True)
    ).all()
    for f in rows:
        reopen(db, f, "Risk acceptance expired", now=now)
    return len(rows)


def assign(db: Session, finding: Finding, assignee: User | None, *, actor: User) -> bool:
    new_id = assignee.id if assignee else None
    if finding.assignee_id == new_id:
        return False
    finding.assignee_id = new_id
    db.add(
        FindingEvent(
            finding=finding,
            actor_id=actor.id,
            event=EventType.assigned.value,
            comment=f"Assigned to {assignee.full_name or assignee.email}" if assignee else "Unassigned",
        )
    )
    return True


def add_comment(db: Session, finding: Finding, text: str, *, actor: User | None) -> FindingEvent:
    """``actor=None`` is Guardiano itself speaking, e.g. when a tracker reports a ticket finished."""
    ev = FindingEvent(
        finding=finding,
        actor_id=actor.id if actor else None,
        event=EventType.comment.value,
        comment=text.strip(),
    )
    db.add(ev)
    return ev


def normalize_tags(tags: list[str]) -> list[str]:
    """Lower-case, trimmed, de-duplicated and sorted, so equal sets compare equal."""
    return sorted({t.strip().lower() for t in tags if t and t.strip()})


def set_tags(db: Session, finding: Finding, tags: list[str], *, actor: User) -> bool:
    old, new = list(finding.tags or []), normalize_tags(tags)
    if old == new:
        return False
    added = [t for t in new if t not in old]
    removed = [t for t in old if t not in new]
    finding.tags = new
    parts = ([f"added {', '.join(added)}"] if added else []) + (
        [f"removed {', '.join(removed)}"] if removed else []
    )
    db.add(
        FindingEvent(
            finding=finding,
            actor_id=actor.id,
            event=EventType.tags_changed.value,
            comment="Tags " + "; ".join(parts),
        )
    )
    return True


def ensure_can_override_severity(user: User) -> None:
    # Severity drives the SLA, so lowering it moves a deadline: the same governance as a due date.
    if ROLE_RANK[Role(user.role)] < ROLE_RANK[Role.manager]:
        raise PermissionDenied("Changing a severity requires manager or higher")


def set_severity(
    db: Session, finding: Finding, severity: str | None, *, actor: User, reason: str | None = None
) -> bool:
    """Override the severity (``None`` returns it to what the scanners report). Rescans keep an override."""
    if finding.severity_override == severity:
        return False
    before = finding.severity
    finding.severity_override = severity
    finding.severity = severity or finding.scanner_severity or finding.severity
    text = (
        f"Severity set to {severity} (scanners report {finding.scanner_severity or before})"
        if severity
        else f"Severity returned to what the scanners report ({finding.severity})"
    )
    if reason and reason.strip():
        text += f": {reason.strip()}"
    db.add(
        FindingEvent(
            finding=finding,
            actor_id=actor.id,
            event=EventType.severity_changed.value,
            from_severity=before,
            to_severity=finding.severity,
            comment=text,
        )
    )
    return True


def set_due_date(
    db: Session, finding: Finding, due: datetime | None, *, actor: User, reason: str | None = None
) -> bool:
    """Override (or with ``due=None`` clear) the SLA-derived remediation deadline."""
    if finding.due_at_override == due:
        return False
    finding.due_at_override = due
    # The exact instant in UTC: a bare date would read as a different day in some timezones.
    text = f"Due date set to {due.astimezone(UTC):%Y-%m-%d %H:%M} UTC" if due else "Due date reset to the SLA"
    if reason and reason.strip():
        text += f": {reason.strip()}"
    db.add(
        FindingEvent(finding=finding, actor_id=actor.id, event=EventType.due_date_changed.value, comment=text)
    )
    return True
