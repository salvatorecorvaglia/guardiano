from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.api.v1.references import ensure_asset
from app.core.crypto import encrypt
from app.core.db import get_db
from app.core.deps import admin_only
from app.models import FindingLink, Integration, Job, PrComment, TicketOperation, User
from app.schemas.integration import (
    IntegrationCheck,
    IntegrationCreate,
    IntegrationOut,
    IntegrationUpdate,
)
from app.services import audit, tickets
from app.services.trackers.base import TrackerError

router = APIRouter(prefix="/integrations", tags=["issue trackers"])


def _load(db: Session, integration_id: int) -> Integration:
    integration = db.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Integration not found")
    return integration


@router.get("", response_model=list[IntegrationOut])
def list_integrations(_: User = Depends(admin_only), db: Session = Depends(get_db)):
    return db.scalars(
        select(Integration).options(joinedload(Integration.asset)).order_by(Integration.id)
    ).all()


@router.post("", response_model=IntegrationOut, status_code=status.HTTP_201_CREATED)
def create_integration(
    body: IntegrationCreate, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)
):
    ensure_asset(db, body.asset_id)
    integration = Integration(
        **body.model_dump(mode="json", exclude={"token"}),
        secret_encrypted=encrypt(body.token),
    )
    db.add(integration)
    db.flush()
    audit.record(
        db,
        "integration.create",
        actor=user,
        request=request,
        target_type="integration",
        target_id=integration.id,
        target_label=f"{integration.kind}:{integration.name}",
        # Never the token, and never anything derived from it.
        changes={"kind": integration.kind, "project": integration.project, "base_url": integration.base_url},
    )
    db.commit()
    db.refresh(integration)
    return integration


@router.patch("/{integration_id}", response_model=IntegrationOut)
def update_integration(
    integration_id: int,
    body: IntegrationUpdate,
    request: Request,
    user: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    integration = db.get(Integration, integration_id, with_for_update=True, populate_existing=True)
    if integration is None:
        raise HTTPException(404, "Integration not found")
    destination_changed = any(
        field in body.model_fields_set
        and (field == "asset_id" or getattr(body, field) is not None)
        and getattr(body, field) != getattr(integration, field)
        for field in ("asset_id", "base_url", "project")
    )
    if destination_changed:
        references = (FindingLink, PrComment, TicketOperation)
        linked = any(
            db.scalar(select(model.integration_id).where(model.integration_id == integration.id).limit(1))
            is not None
            for model in references
        )
        queued = db.scalar(
            select(Job.id)
            .where(
                Job.kind.in_([tickets.AUTO_JOB, "scm.feedback"]),
                Job.status.in_(["queued", "running", "dead"]),
                Job.payload["integration_id"].as_integer() == integration.id,
            )
            .limit(1)
        )
        if linked or queued is not None:
            raise HTTPException(
                409, "This destination has linked tickets or pending work; create a new integration"
            )
    if body.scm_feedback and integration.kind not in ("github", "gitlab"):
        raise HTTPException(422, "Commit and pull-request feedback needs GitHub or GitLab")
    fields = (
        "name", "base_url", "project", "username", "issue_type", "enabled", "scm_feedback",
        "close_resolves_finding", "done_transition", "reopen_transition", "auto_ticket_kev",
        "auto_ticket_min_severity", "asset_id", "labels",
    )  # fmt: skip
    before = audit.snapshot(integration, fields)
    for field in fields:
        if field == "asset_id":
            if field in body.model_fields_set:
                ensure_asset(db, body.asset_id)
                integration.asset_id = body.asset_id
            continue
        if (value := getattr(body, field)) is not None:
            setattr(integration, field, value)
    if "auto_ticket_min_severity" in body.model_fields_set and body.auto_ticket_min_severity is None:
        integration.auto_ticket_min_severity = None  # given as null: turned off
    # An empty transition name removes it: Guardiano then only comments, as before.
    integration.done_transition = integration.done_transition or None
    integration.reopen_transition = integration.reopen_transition or None
    changes = audit.diff(before, integration)
    if body.token:
        integration.secret_encrypted = encrypt(body.token)
        changes["token"] = "replaced"
    if changes:
        audit.record(
            db,
            "integration.update",
            actor=user,
            request=request,
            target_type="integration",
            target_id=integration.id,
            target_label=f"{integration.kind}:{integration.name}",
            changes=changes,
        )
    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_integration(
    integration_id: int, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)
):
    """Tickets already opened keep their links; they simply stop being updated."""
    integration = _load(db, integration_id)
    audit.record(
        db,
        "integration.delete",
        actor=user,
        request=request,
        target_type="integration",
        target_id=integration.id,
        target_label=f"{integration.kind}:{integration.name}",
    )
    db.delete(integration)
    db.commit()


@router.post("/{integration_id}/check", response_model=IntegrationCheck)
def check_integration(integration_id: int, _: User = Depends(admin_only), db: Session = Depends(get_db)):
    """Verify the credentials and the project, without creating anything."""
    integration = _load(db, integration_id)
    from app.services.remote_io import network_io, snapshot

    config = snapshot(integration)
    try:
        with network_io(db):
            detail = tickets.provider(config.kind).check(config)
    except (TrackerError, ValueError) as exc:
        integration.last_error = str(exc)[:500]
        db.commit()
        return IntegrationCheck(ok=False, detail=str(exc))
    integration.last_error = None
    db.commit()
    return IntegrationCheck(ok=True, detail=detail)
