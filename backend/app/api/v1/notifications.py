"""The bell: your own notifications (services/notifications.py)."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session, joinedload

from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import Finding, Notification, User
from app.models.base import utcnow
from app.models.enums import Role
from app.schemas.user import UserBrief
from app.services.scope import Scope

router = APIRouter(prefix="/notifications", tags=["notifications"])
me = require(Role.viewer, None)


class NotificationOut(BaseModel):
    id: int
    kind: str
    text: str
    finding_id: int | None
    actor: UserBrief | None
    read_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class NotificationList(BaseModel):
    items: list[NotificationOut]
    unread: int


class MarkRead(BaseModel):
    ids: list[int] | None = Field(None, max_length=500, description="null marks every notification read")


def _mine(user: User, scope: Scope):
    """Your notifications, narrowed to findings you can still see."""
    return (
        select(Notification)
        .outerjoin(Finding, Finding.id == Notification.finding_id)
        .where(
            Notification.user_id == user.id,
            or_(Notification.finding_id.is_(None), scope.where(Finding.asset_id)),
        )
    )


@router.get("", response_model=NotificationList)
def list_notifications(
    unread_only: bool = False,
    limit: int = Query(30, ge=1, le=100),
    user: User = Depends(me),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Newest first, with how many are unread."""
    stmt = _mine(user, scope)
    unread = db.scalar(
        select(func.count()).select_from(stmt.where(Notification.read_at.is_(None)).subquery())
    )
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    rows = db.scalars(
        stmt.options(joinedload(Notification.actor))
        .order_by(Notification.created_at.desc(), Notification.id.desc())
        .limit(limit)
    ).all()
    return NotificationList(items=rows, unread=unread or 0)


@router.post("/read", response_model=NotificationList)
def mark_read(
    body: MarkRead,
    user: User = Depends(me),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    stmt = update(Notification).where(Notification.user_id == user.id, Notification.read_at.is_(None))
    if body.ids is not None:
        stmt = stmt.where(Notification.id.in_(body.ids))
    db.execute(stmt.values(read_at=utcnow()))
    db.commit()
    return list_notifications(False, 30, user, scope, db)
