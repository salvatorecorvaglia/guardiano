import secrets
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.api.v1.references import ensure_asset
from app.core.db import get_db
from app.core.deps import admin_only
from app.models import User, Webhook, WebhookDelivery
from app.schemas.common import Page
from app.schemas.webhook import DeliveryOut, WebhookCreate, WebhookCreated, WebhookOut, WebhookUpdate
from app.services import audit, events, jobs

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _load(db: Session, webhook_id: int) -> Webhook:
    hook = db.get(Webhook, webhook_id)
    if hook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Webhook not found")
    return hook


def _host(url: str) -> str:
    """Just the host. A webhook URL can carry a token in its path (Slack, Teams), so the audit log
    records where deliveries go without recording the credential that goes with it."""
    return urlsplit(url).netloc or url


@router.get("", response_model=list[WebhookOut])
def list_webhooks(_: User = Depends(admin_only), db: Session = Depends(get_db)):
    return db.scalars(select(Webhook).options(joinedload(Webhook.asset)).order_by(Webhook.id)).all()


@router.post("", response_model=WebhookCreated, status_code=status.HTTP_201_CREATED)
def create_webhook(
    body: WebhookCreate, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)
):
    """The response carries the signing secret. It is not shown again."""
    ensure_asset(db, body.asset_id)
    hook = Webhook(
        **body.model_dump(mode="json", exclude={"events"}),
        events=[e for e in body.events],
        secret=secrets.token_hex(32),
    )
    db.add(hook)
    db.flush()
    audit.record(
        db,
        "webhook.create",
        actor=user,
        request=request,
        target_type="webhook",
        target_id=hook.id,
        target_label=hook.name,
        changes={"host": _host(hook.url), "events": hook.events, "format": hook.format},
    )
    db.commit()
    db.refresh(hook)
    return hook


@router.patch("/{webhook_id}", response_model=WebhookOut)
def update_webhook(
    webhook_id: int,
    body: WebhookUpdate,
    request: Request,
    user: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    hook = _load(db, webhook_id)
    # One tuple for the snapshot and the writes: a field that is written but not snapshotted cannot
    # be seen by audit.diff, which is how repointing a webhook used to go unrecorded.
    audited = ("name", "asset_id", "events", "format", "min_severity", "enabled")
    before = audit.snapshot(hook, audited)
    before_host = _host(hook.url)

    if "asset_id" in body.model_fields_set:
        ensure_asset(db, body.asset_id)
        hook.asset_id = body.asset_id
    for field in ("name", "url", "format", "min_severity", "enabled"):
        if (value := getattr(body, field)) is not None:
            setattr(hook, field, value.value if hasattr(value, "value") else value)
    if body.events is not None:
        hook.events = list(body.events)
    if body.rotate_secret:
        hook.secret = secrets.token_hex(32)
    changes = audit.diff(before, hook)
    # As on create: the URL can carry a token (Slack, Teams), so only its host is recorded.
    if (after_host := _host(hook.url)) != before_host:
        changes["host"] = {"from": before_host, "to": after_host}
    if body.rotate_secret:
        changes["secret"] = "rotated"
    if changes:
        audit.record(
            db,
            "webhook.update",
            actor=user,
            request=request,
            target_type="webhook",
            target_id=hook.id,
            target_label=hook.name,
            changes=changes,
        )
    db.commit()
    db.refresh(hook)
    # The rotated secret is returned through a dedicated response so it is never logged by accident.
    return hook


@router.post("/{webhook_id}/rotate-secret", response_model=WebhookCreated)
def rotate_secret(
    webhook_id: int, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)
):
    hook = _load(db, webhook_id)
    hook.secret = secrets.token_hex(32)
    audit.record(
        db,
        "webhook.update",
        actor=user,
        request=request,
        target_type="webhook",
        target_id=hook.id,
        target_label=hook.name,
        changes={"secret": "rotated"},
    )
    db.commit()
    db.refresh(hook)
    return hook


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(
    webhook_id: int, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)
):
    hook = _load(db, webhook_id)
    audit.record(
        db,
        "webhook.delete",
        actor=user,
        request=request,
        target_type="webhook",
        target_id=hook.id,
        target_label=hook.name,
    )
    db.delete(hook)
    db.commit()


@router.post("/{webhook_id}/test", response_model=DeliveryOut, status_code=status.HTTP_202_ACCEPTED)
def send_test(webhook_id: int, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    """Queue a test event for this webhook. The worker sends it; poll the deliveries for the outcome."""
    hook = _load(db, webhook_id)
    delivery = WebhookDelivery(
        webhook_id=hook.id,
        event=events.TEST,
        payload={"message": "Test event from Guardiano", "requested_by": user.email},
        attempts=0,
    )
    db.add(delivery)
    db.flush()
    jobs.enqueue(db, events.DELIVER_JOB, {"delivery_id": delivery.id})
    db.commit()
    db.refresh(delivery)
    return delivery


@router.get("/{webhook_id}/deliveries", response_model=Page[DeliveryOut])
def list_deliveries(
    webhook_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    _load(db, webhook_id)
    stmt = select(WebhookDelivery).where(WebhookDelivery.webhook_id == webhook_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(
        stmt.order_by(WebhookDelivery.created_at.desc(), WebhookDelivery.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(items=items, total=total, page=page, page_size=page_size)
