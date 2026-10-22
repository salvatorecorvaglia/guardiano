"""Shared transactional finding changes for single and bulk triage."""

from sqlalchemy.orm import Session

from app.models import Finding, User
from app.schemas.finding import MAX_TAGS, BulkChange, FindingUpdate
from app.services import email, events, jobs, lifecycle, notifications
from app.services import status as status_change
from app.services.errors import ValidationFailed
from app.services.scope import ScopeCache
from app.services.serializers import finding_payload


def check_overrides(body: FindingUpdate | BulkChange, user: User) -> None:
    if body.due_at is not None or body.clear_due_at:
        if body.due_at is not None and body.clear_due_at:
            raise ValidationFailed("Pass either due_at or clear_due_at, not both")
        lifecycle.ensure_can_override_due(user)
    if body.severity is not None or body.clear_severity_override:
        if body.severity is not None and body.clear_severity_override:
            raise ValidationFailed("Pass either severity or clear_severity_override, not both")
        lifecycle.ensure_can_override_severity(user)


def emit_assigned(db: Session, f: Finding, assignee: User | None, actor: User, hooks: dict | None) -> None:
    events.emit(
        db,
        events.FINDING_ASSIGNED,
        finding_payload(
            f,
            assignee=(assignee.full_name or assignee.email) if assignee else None,
            assignee_email=assignee.email if assignee else None,
            actor=actor.full_name or actor.email,
        ),
        asset_id=f.asset_id,
        severity=f.severity,
        cache=hooks,
    )


def apply_change(
    db: Session,
    f: Finding,
    body: FindingUpdate | BulkChange,
    user: User,
    hooks: dict | None = None,
    scopes: ScopeCache | None = None,
) -> bool:
    scopes = scopes or ScopeCache(db)
    changed = False
    if body.status is not None:
        lifecycle.ensure_can_set_status(user, body.status, f.status)
        lifecycle.validate_transition(body.status, body.justification, body.risk_accepted_until)
        changed |= status_change.change(
            db,
            f,
            body.status,
            actor=user,
            justification=body.justification,
            risk_accepted_until=body.risk_accepted_until,
            hooks=hooks,
        )
    if body.unassign:
        if lifecycle.assign(db, f, None, actor=user):
            changed = True
            emit_assigned(db, f, None, user, hooks)
    elif body.assignee_id is not None:
        assignee = scopes.user(body.assignee_id)
        if assignee is None or not assignee.is_active:
            raise ValidationFailed("Assignee not found")
        if not scopes.scope(assignee).owns(f.asset):
            raise ValidationFailed("Assignee cannot access this asset")
        if lifecycle.assign(db, f, assignee, actor=user):
            changed = True
            emit_assigned(db, f, assignee, user, hooks)
            by = user.full_name or user.email
            notifications.notify(
                db, [assignee], "assigned", f, f"{by} assigned you", actor=user, scopes=scopes
            )
            # Only a person assigning to somebody else is worth an email; the asset's default assignee
            # would mean one message per new finding.
            if assignee.id != user.id and assignee.notify_on_assignment and email.enabled():
                jobs.enqueue(
                    db,
                    email.SEND_JOB,
                    {
                        "kind": "assignment",
                        "recipient_id": assignee.id,
                        "finding_id": f.id,
                        "actor": user.full_name or user.email,
                    },
                )
    if body.due_at is not None or body.clear_due_at:
        changed |= lifecycle.set_due_date(db, f, body.due_at, actor=user, reason=body.due_reason)
    if body.severity is not None or body.clear_severity_override:
        target = body.severity.value if body.severity is not None else None
        changed |= lifecycle.set_severity(db, f, target, actor=user, reason=body.severity_reason)
    if isinstance(body, FindingUpdate):
        if body.tags is not None:
            changed |= lifecycle.set_tags(db, f, body.tags, actor=user)
    elif body.add_tags or body.remove_tags:
        remove = set(lifecycle.normalize_tags(body.remove_tags))
        tags = [t for t in (f.tags or []) if t not in remove] + body.add_tags
        if len(lifecycle.normalize_tags(tags)) > MAX_TAGS:
            raise ValidationFailed(f"Finding #{f.id} would exceed {MAX_TAGS} tags")
        changed |= lifecycle.set_tags(db, f, tags, actor=user)
    return changed
