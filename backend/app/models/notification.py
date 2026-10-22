from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.base import utcnow
from app.models.finding import Finding
from app.models.user import User


class Notification(Base):
    """Something a person should know about, shown under the bell (services/notifications.py)."""

    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_user_read_created", "user_id", "read_at", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # assigned | mentioned | acceptance_requested | acceptance_decided | sla_breached | kev_added
    kind: Mapped[str] = mapped_column(String(30))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    text: Mapped[str] = mapped_column(String(500))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding | None] = relationship()
    actor: Mapped[User | None] = relationship(foreign_keys=[actor_id])
