from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.asset import Asset
from app.models.base import utcnow
from app.models.user import User


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_commit_asset_tool", "commit_sha", "asset_id", "tool_name", "scan_type"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    scan_type: Mapped[str] = mapped_column(String(10))
    tool_name: Mapped[str] = mapped_column(String(100))
    tool_version: Mapped[str | None] = mapped_column(String(100))
    format: Mapped[str] = mapped_column(String(30))
    branch: Mapped[str | None] = mapped_column(String(255))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(10), default="upload")
    uploaded_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    file_name: Mapped[str | None] = mapped_column(String(255))
    file_sha256: Mapped[str | None] = mapped_column(String(64))
    # None marks pre-snapshot inventory whose full membership cannot be reconstructed.
    inventory_complete: Mapped[bool | None] = mapped_column(Boolean)
    total_count: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    auto_resolved_count: Mapped[int] = mapped_column(Integer, default=0)
    # Quality-gate outcome, NULL when no policy applied (see services/gate.py).
    gate_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # For source="preview": what the report would change, without touching the inventory.
    preview_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    asset: Mapped[Asset] = relationship()
    uploaded_by: Mapped[User | None] = relationship()
