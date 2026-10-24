from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload

from app.api.v1.references import ensure_asset
from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import Asset, TriageRule, User
from app.models.enums import ROLE_RANK, Role
from app.schemas.triage import (
    TriageApplyOut,
    TriagePreviewOut,
    TriagePreviewRequest,
    TriageRuleCreate,
    TriageRuleOut,
    TriageRuleUpdate,
)
from app.services import audit, jobs, triage
from app.services.errors import PermissionDenied, ValidationFailed
from app.services.queries import findings_query
from app.services.scope import Scope
from app.services.serializers import finding_out

router = APIRouter(prefix="/triage-rules", tags=["auto-triage"])
manager = require(Role.manager, None)

# How many findings a preview examines; path globs and title matching cannot be done in SQL.
PREVIEW_SCAN_LIMIT = 2000


def _load(db: Session, rule_id: int, scope: Scope) -> TriageRule:
    rule = db.get(TriageRule, rule_id)
    # A rule on an asset the caller cannot see is reported as missing, as the asset itself would be.
    if rule is None or (rule.asset_id is not None and not scope.owns(rule.asset)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    return rule


def _ensure_can_edit_global(user: User, asset_id: int | None) -> None:
    # A rule for every asset reaches every team's findings, so, like the global quality gate, only
    # administrators may change one. Managers keep the rules of the assets they can see.
    if asset_id is None and ROLE_RANK[Role(user.role)] < ROLE_RANK[Role.admin]:
        raise PermissionDenied("Changing a rule that applies to every asset requires the admin role")


def _ensure_visible_asset(db: Session, asset_id: int | None, scope: Scope) -> None:
    """A rule may only target an asset the caller can see, or it would triage another team's findings."""
    ensure_asset(db, asset_id)
    if asset_id is not None and not scope.owns(db.get(Asset, asset_id)):
        raise HTTPException(422, "Asset not found")


@router.get("", response_model=list[TriageRuleOut])
def list_rules(
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Every rule the reader can see, in the order they are applied."""
    stmt = select(TriageRule).options(joinedload(TriageRule.asset), joinedload(TriageRule.created_by))
    if not scope.unrestricted:
        # A rule names its asset and what it matches there, so another team's rules stay hidden.
        stmt = stmt.where(or_(TriageRule.asset_id.is_(None), scope.where(TriageRule.asset_id)))
    return db.scalars(stmt.order_by(TriageRule.priority, TriageRule.id)).all()


@router.post("", response_model=TriageRuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(
    body: TriageRuleCreate,
    request: Request,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    _ensure_visible_asset(db, body.asset_id, scope)
    _ensure_can_edit_global(user, body.asset_id)
    rule = TriageRule(
        name=body.name.strip(),
        enabled=body.enabled,
        priority=body.priority,
        asset_id=body.asset_id,
        match=body.match.model_dump(exclude_defaults=True, exclude_none=True, mode="json"),
        action=body.action.model_dump(exclude_defaults=True, exclude_none=True, mode="json"),
        expires_at=body.expires_at,
        created_by_id=user.id,
    )
    db.add(rule)
    db.flush()
    audit.record(
        db,
        "triage_rule.create",
        actor=user,
        request=request,
        target_type="triage_rule",
        target_id=rule.id,
        target_label=rule.name,
        changes={"match": rule.match, "action": rule.action, "asset_id": rule.asset_id},
    )
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/{rule_id}", response_model=TriageRuleOut)
def update_rule(
    rule_id: int,
    body: TriageRuleUpdate,
    request: Request,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    rule = _load(db, rule_id, scope)
    _ensure_can_edit_global(user, rule.asset_id)
    if "asset_id" in body.model_fields_set:
        _ensure_visible_asset(db, body.asset_id, scope)
        _ensure_can_edit_global(user, body.asset_id)
        rule.asset_id = body.asset_id
    before = audit.snapshot(rule, ("name", "enabled", "priority", "match", "action"))
    if body.name is not None:
        rule.name = body.name.strip()
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.priority is not None:
        rule.priority = body.priority
    if body.match is not None:
        rule.match = body.match.model_dump(exclude_defaults=True, exclude_none=True, mode="json")
    if body.action is not None:
        rule.action = body.action.model_dump(exclude_defaults=True, exclude_none=True, mode="json")
    if body.clear_expiry:
        rule.expires_at = None
    elif body.expires_at is not None:
        rule.expires_at = body.expires_at

    # Re-validate the whole rule: a patch must not leave it without conditions or without an action.
    try:
        TriageRuleCreate(
            name=rule.name,
            enabled=rule.enabled,
            priority=rule.priority,
            asset_id=rule.asset_id,
            match=rule.match,
            action=rule.action,
        )
    except ValidationError as exc:
        db.rollback()
        # Raised inside the handler, so FastAPI would return 500 rather than 422 without this.
        raise ValidationFailed("; ".join(e["msg"].removeprefix("Value error, ") for e in exc.errors()))
    if changes := audit.diff(before, rule):
        audit.record(
            db,
            "triage_rule.update",
            actor=user,
            request=request,
            target_type="triage_rule",
            target_id=rule.id,
            target_label=rule.name,
            changes=changes,
        )
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: int,
    request: Request,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Deleting a rule leaves the findings it already triaged as they are."""
    rule = _load(db, rule_id, scope)
    _ensure_can_edit_global(user, rule.asset_id)
    audit.record(
        db,
        "triage_rule.delete",
        actor=user,
        request=request,
        target_type="triage_rule",
        target_id=rule.id,
        target_label=rule.name,
        changes={"match": rule.match, "action": rule.action, "applied_count": rule.applied_count},
    )
    db.delete(rule)
    db.commit()


@router.post("/preview", response_model=TriagePreviewOut)
def preview(
    body: TriagePreviewRequest,
    _: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Which existing findings a rule's conditions would match, without changing anything.

    Conditions that map to SQL narrow the search; the rest are applied by the same matcher ingestion uses.
    """
    match = body.match.model_dump(exclude_defaults=True, exclude_none=True, mode="json")
    filters = triage.prefilter(match, body.asset_id, scope)
    candidates = (
        db.scalars(findings_query(filters, "-first_seen", db).limit(PREVIEW_SCAN_LIMIT)).unique().all()
    )
    matched = [f for f in candidates if triage.matches(match, f)]
    return TriagePreviewOut(
        scanned=len(candidates),
        matched=len(matched),
        truncated=len(candidates) == PREVIEW_SCAN_LIMIT,
        sample=[finding_out(f) for f in matched[: body.limit]],
    )


@router.post("/{rule_id}/apply", response_model=TriageApplyOut, status_code=status.HTTP_202_ACCEPTED)
def apply_to_existing(
    rule_id: int,
    request: Request,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Apply a rule to the open and in-progress findings it matches now, in the background.

    Closed findings are left alone, as are assignees people chose. Run the preview first to see what
    will match. Only findings on assets you can see are touched.
    """
    rule = _load(db, rule_id, scope)
    job = jobs.enqueue(
        db,
        triage.APPLY_JOB,
        {
            "rule_id": rule.id,
            "actor_id": user.id,
            "team_ids": None if scope.unrestricted else list(scope.team_ids or ()),
            "actor": user.full_name or user.email,
        },
        max_attempts=1,  # it commits as it goes; a retry would only pick up what is still unmatched
    )
    audit.record(
        db,
        "triage_rule.apply",
        actor=user,
        request=request,
        target_type="triage_rule",
        target_id=rule.id,
        target_label=rule.name,
        changes={"match": rule.match, "action": rule.action},
    )
    db.commit()
    return TriageApplyOut(job_id=job.id)
