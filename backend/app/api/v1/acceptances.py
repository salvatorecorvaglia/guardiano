"""Risk-acceptance requests: asked for on a finding, decided by a manager (services/acceptance.py)."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import AcceptanceRequest, Finding, User
from app.models.enums import Role
from app.schemas.finding import AcceptanceDecision, AcceptanceRequestCreate, AcceptanceRequestOut
from app.services import acceptance
from app.services.scope import Scope

router = APIRouter(tags=["risk acceptance"])
analyst = require(Role.analyst, None)
manager = require(Role.manager, None)


def _out(req: AcceptanceRequest) -> AcceptanceRequestOut:
    f = req.finding
    return AcceptanceRequestOut(
        id=req.id,
        finding_id=f.id,
        finding_title=f.title,
        asset=f.asset,
        severity=f.severity,
        state=req.state,
        justification=req.justification,
        until=req.until,
        requested_by=req.requested_by,
        decided_by=req.decided_by,
        decided_at=req.decided_at,
        decision_note=req.decision_note,
        created_at=req.created_at,
    )


def _query(scope: Scope):
    return scope.narrow(
        select(AcceptanceRequest)
        .join(Finding, Finding.id == AcceptanceRequest.finding_id)
        .options(
            joinedload(AcceptanceRequest.finding).joinedload(Finding.asset),
            joinedload(AcceptanceRequest.requested_by),
            joinedload(AcceptanceRequest.decided_by),
        )
        # After a decision the same request is read again, and its decided_by must not stay the empty
        # value loaded before it.
        .execution_options(populate_existing=True),
        Finding.asset_id,
    )


def _load(db: Session, request_id: int, scope: Scope) -> AcceptanceRequest:
    req = db.scalar(_query(scope).where(AcceptanceRequest.id == request_id))
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request not found")
    return req


@router.post(
    "/findings/{finding_id}/acceptance-requests",
    response_model=AcceptanceRequestOut,
    status_code=status.HTTP_201_CREATED,
)
def create_request(
    finding_id: int,
    body: AcceptanceRequestCreate,
    user: User = Depends(analyst),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Ask for this finding's risk to be accepted. A manager other than you decides."""
    f = db.scalar(scope.narrow(select(Finding), Finding.asset_id).where(
        Finding.id == finding_id
    ).with_for_update(of=Finding).execution_options(populate_existing=True))
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    req = acceptance.request(db, f, user, body.justification, body.until)
    db.commit()
    return _out(_load(db, req.id, scope))


@router.get("/acceptance-requests", response_model=list[AcceptanceRequestOut])
def list_requests(
    state: Literal["pending", "approved", "rejected"] | None = Query("pending"),
    finding_id: int | None = None,
    limit: int = Query(100, ge=1, le=500),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Requests on findings you can see, newest first; the pending ones by default."""
    stmt = _query(scope)
    if state:
        stmt = stmt.where(AcceptanceRequest.state == state)
    if finding_id:
        stmt = stmt.where(AcceptanceRequest.finding_id == finding_id)
    rows = db.scalars(stmt.order_by(AcceptanceRequest.created_at.desc()).limit(limit)).unique().all()
    return [_out(r) for r in rows]


@router.post("/acceptance-requests/{request_id}/approve", response_model=AcceptanceRequestOut)
def approve(
    request_id: int,
    body: AcceptanceDecision,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    req = _load(db, request_id, scope)
    acceptance.approve(db, req, user, body.note)
    db.commit()
    return _out(_load(db, request_id, scope))


@router.post("/acceptance-requests/{request_id}/reject", response_model=AcceptanceRequestOut)
def reject(
    request_id: int,
    body: AcceptanceDecision,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    req = _load(db, request_id, scope)
    acceptance.reject(db, req, user, body.note)
    db.commit()
    return _out(_load(db, request_id, scope))
