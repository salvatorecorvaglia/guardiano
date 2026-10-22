from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.crypto import decrypt, encrypt
from app.core.db import Base
from app.models.asset import Asset
from app.models.base import TimestampMixin, utcnow


class Webhook(TimestampMixin, Base):
    """An outbound HTTP endpoint notified of events (see services/events.py)."""

    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    url: Mapped[str] = mapped_column(Text)
    # The signing secret (X-Guardiano-Signature), encrypted like tracker tokens; read and written through
    # ``secret`` below. Shown once when created or rotated.
    secret_encrypted: Mapped[str | None] = mapped_column(Text)
    # Legacy plaintext secrets. Emptied by encrypt_legacy_secrets()
    # (services/webhooks.py) at startup; read as a fallback until then, so an upgrade never breaks delivery.
    secret_plaintext: Mapped[str | None] = mapped_column("secret", String(64))
    format: Mapped[str] = mapped_column(String(20), default="guardiano")  # guardiano | slack | teams
    events: Mapped[list[str]] = mapped_column(ARRAY(String(40)), default=list)
    min_severity: Mapped[str] = mapped_column(String(10), default="high")
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Last outcome, so a broken endpoint is visible without opening the delivery log.
    last_status: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    asset: Mapped[Asset | None] = relationship()

    @property
    def secret(self) -> str:
        """The signing secret. Raises ValueError when it was encrypted with a different key."""
        if self.secret_encrypted is not None:
            return decrypt(self.secret_encrypted)
        return self.secret_plaintext or ""

    @secret.setter
    def secret(self, value: str) -> None:
        self.secret_encrypted, self.secret_plaintext = encrypt(value), None


class WebhookDelivery(Base):
    """One attempt series to deliver one event to one webhook."""

    __tablename__ = "webhook_deliveries"
    __table_args__ = (Index("ix_webhook_deliveries_webhook_created", "webhook_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    webhook_id: Mapped[int] = mapped_column(ForeignKey("webhooks.id", ondelete="CASCADE"))
    event: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    status_code: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    webhook: Mapped[Webhook] = relationship()
