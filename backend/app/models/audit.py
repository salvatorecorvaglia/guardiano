from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import utcnow


class AuditLog(Base):
    """Security-relevant actions outside the finding lifecycle (which has its own FindingEvent trail)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    # Snapshot, so the entry stays readable after the actor is deleted.
    actor_email: Mapped[str | None] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(50), index=True)
    target_type: Mapped[str | None] = mapped_column(String(30))
    target_id: Mapped[int | None]
    target_label: Mapped[str | None] = mapped_column(String(320))
    changes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
