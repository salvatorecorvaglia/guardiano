"""Risk-acceptance requests.

Anyone who triages can ask for a risk to be accepted; a manager who is not the requester decides. Approval
goes through services/status.py, so an approved request tells tickets and webhooks exactly as a manager
accepting the risk directly would. With RISK_ACCEPTANCE_FOUR_EYES on, a request is the only way in.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AcceptanceRequest, Finding, FindingEvent, User
from app.models.base import utcnow
from app.models.enums import ACTIVE_STATUSES, EventType, Status
from app.services import lifecycle, notifications, status
from app.services.errors import PermissionDenied, ValidationFailed

PENDING, APPROVED, REJECTED = "pending", "approved", "rejected"
_ACTIVE = {s.value for s in ACTIVE_STATUSES}


def _name(user: User | None) -> str:
    return (user.full_name or user.email) if user else "somebody"


def request(
    db: Session, finding: Finding, user: User, justification: str, until: datetime | None
) -> AcceptanceRequest:
    if finding.status not in _ACTIVE:
        raise ValidationFailed("Only an open or in-progress finding can have its risk accepted")
    if not justification.strip():
        raise ValidationFailed("A request needs a justification")
    lifecycle.validate_acceptance_window(until)
    pending = db.scalar(
        select(AcceptanceRequest).where(
            AcceptanceRequest.finding_id == finding.id, AcceptanceRequest.state == PENDING
        )
    )
    if pending is not None:
        raise ValidationFailed("This finding already has a request waiting for a decision")
    req = AcceptanceRequest(
        finding_id=finding.id, justification=justification.strip(), until=until, requested_by_id=user.id
    )
    db.add(req)
    ending = f" until {until:%Y-%m-%d}" if until else " with no end date"
    db.add(
        FindingEvent(
            finding=finding,
            actor_id=user.id,
            event=EventType.acceptance_requested.value,
            comment=f"requested risk acceptance{ending}: {req.justification}",
        )
    )
    notifications.notify(
        db, notifications.managers(db), "acceptance_requested", finding,
        f"{_name(user)} asks to accept a risk{ending}", actor=user,
    )  # fmt: skip
    return req


def _decidable(req: AcceptanceRequest, user: User) -> None:
    if req.state != PENDING:
        raise ValidationFailed(f"This request was already {req.state}")
    if req.requested_by_id == user.id:
        raise PermissionDenied("A request is decided by somebody other than the person who made it")


def approve(db: Session, req: AcceptanceRequest, user: User, note: str | None = None) -> None:
    db.refresh(req, with_for_update={"of": AcceptanceRequest})
    db.refresh(req.finding, with_for_update={"of": Finding})
    _decidable(req, user)
    finding = req.finding
    if finding.status not in _ACTIVE:
        raise ValidationFailed("The finding is no longer open; reject the request instead")
    lifecycle.validate_acceptance_window(req.until)  # the bounds may have changed, or the date passed
    justification = f"{req.justification} (requested by {_name(req.requested_by)}, approved by {_name(user)})"
    if note and note.strip():
        justification += f": {note.strip()}"
    status.change(
        db,
        finding,
        Status.risk_accepted,
        actor=user,
        justification=justification,
        risk_accepted_until=req.until,
    )
    req.state, req.decided_by_id, req.decided_at, req.decision_note = APPROVED, user.id, utcnow(), note
    notifications.notify(
        db, [req.requested_by], "acceptance_decided", finding,
        f"{_name(user)} approved your risk-acceptance request", actor=user,
    )  # fmt: skip


def reject(db: Session, req: AcceptanceRequest, user: User, note: str | None = None) -> None:
    db.refresh(req, with_for_update={"of": AcceptanceRequest})
    db.refresh(req.finding, with_for_update={"of": Finding})
    _decidable(req, user)
    req.state, req.decided_by_id, req.decided_at, req.decision_note = REJECTED, user.id, utcnow(), note
    reason = f": {note.strip()}" if note and note.strip() else ""
    db.add(
        FindingEvent(
            finding_id=req.finding_id,
            actor_id=user.id,
            event=EventType.acceptance_rejected.value,
            comment=f"rejected the risk-acceptance request by {_name(req.requested_by)}{reason}",
        )
    )
    notifications.notify(
        db, [req.requested_by], "acceptance_decided", req.finding,
        f"{_name(user)} rejected your risk-acceptance request{reason}", actor=user,
    )  # fmt: skip
