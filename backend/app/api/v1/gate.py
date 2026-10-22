from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import Asset, GatePolicy, User
from app.models.enums import ROLE_RANK, Role
from app.schemas.gate import GatePolicyOut, GatePolicyUpsert
from app.services import audit
from app.services.errors import PermissionDenied, ValidationFailed
from app.services.scope import Scope

router = APIRouter(prefix="/gate-policies", tags=["quality gates"])
manager = require(Role.manager, None)


def _ensure_can_edit(user: User, asset_id: int | None) -> None:
    # The global policy covers every asset, so only administrators may change it.
    if asset_id is None and ROLE_RANK[Role(user.role)] < ROLE_RANK[Role.admin]:
        raise PermissionDenied("Editing the global quality gate requires the admin role")


def _label(policy: GatePolicy) -> str:
    return policy.asset.name if policy.asset else "global"


@router.get("", response_model=list[GatePolicyOut])
def list_policies(
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """The global policy first, then one policy per asset the reader can see."""
    stmt = select(GatePolicy).options(joinedload(GatePolicy.asset))
    if not scope.unrestricted:
        # A policy names its asset, so listing one for an asset they cannot see would leak its name.
        stmt = stmt.where(or_(GatePolicy.asset_id.is_(None), scope.where(GatePolicy.asset_id)))
    return db.scalars(stmt.order_by(GatePolicy.asset_id.is_not(None), GatePolicy.id)).all()


@router.put("", response_model=GatePolicyOut)
def upsert_policy(
    body: GatePolicyUpsert,
    request: Request,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Create or replace the policy for an asset, or the global one (`asset_id: null`)."""
    _ensure_can_edit(user, body.asset_id)
    try:
        body.conditions.non_negative()
    except ValueError as exc:
        raise ValidationFailed(str(exc))
    if body.asset_id is not None and not scope.owns(db.get(Asset, body.asset_id)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")

    policy = db.scalar(select(GatePolicy).where(GatePolicy.asset_id.is_not_distinct_from(body.asset_id)))
    before = {"enabled": policy.enabled, "conditions": policy.conditions} if policy else None
    if policy is None:
        policy = GatePolicy(asset_id=body.asset_id)
        db.add(policy)
    policy.enabled = body.enabled
    policy.conditions = body.conditions.model_dump(mode="json", exclude_defaults=True)
    db.flush()
    after = {"enabled": policy.enabled, "conditions": policy.conditions}
    audit.record(
        db,
        "gate.update" if before else "gate.create",
        actor=user,
        request=request,
        target_type="gate_policy",
        target_id=policy.id,
        target_label=_label(policy),
        changes={"from": before, "to": after} if before else after,
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: int,
    request: Request,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    policy = db.get(GatePolicy, policy_id)
    if policy is None or (policy.asset_id is not None and not scope.owns(policy.asset)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    _ensure_can_edit(user, policy.asset_id)
    audit.record(
        db,
        "gate.delete",
        actor=user,
        request=request,
        target_type="gate_policy",
        target_id=policy.id,
        target_label=_label(policy),
        changes={"conditions": policy.conditions},
    )
    db.delete(policy)
    db.commit()
