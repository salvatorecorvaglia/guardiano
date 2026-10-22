from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import utcnow


class Job(Base):
    """A unit of background work, executed by ``python -m app.cli worker`` (see services/jobs.py)."""

    __tablename__ = "jobs"
    # Serves the worker's claim query: WHERE status = 'queued' AND run_after <= now ORDER BY run_after.
    __table_args__ = (
        Index("ix_jobs_status_run_after", "status", "run_after"),
        Index("ix_jobs_status_priority_run_after", "status", "priority", "run_after"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(100))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[int] = mapped_column(Integer, default=100, server_default="100")
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    run_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    claim_token: Mapped[str | None] = mapped_column(String(32))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class PeriodicTask(Base):
    """Last run of each periodic task; the row lock makes scheduling safe across worker replicas."""

    __tablename__ = "periodic_tasks"

    name: Mapped[str] = mapped_column(String(100), primary_key=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
