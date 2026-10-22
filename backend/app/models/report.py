from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.base import TimestampMixin
from app.models.product import Product


class ReportSchedule(TimestampMixin, Base):
    """A security report emailed weekly or monthly (services/reports.py).

    Recipients are Guardiano users, never free-form addresses, and each gets the report as they would
    see it in the app: their own teams' assets. So a report cannot carry figures to anybody who could
    not already read them.
    """

    __tablename__ = "report_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    frequency: Mapped[str] = mapped_column(String(10))  # weekly | monthly
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id", ondelete="SET NULL"))
    recipient_ids: Mapped[list[int]] = mapped_column(ARRAY(Integer), default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    product: Mapped[Product | None] = relationship()
