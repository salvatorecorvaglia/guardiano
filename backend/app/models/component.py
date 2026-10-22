from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.asset import Asset
from app.models.base import TimestampMixin, utcnow


class Component(TimestampMixin, Base):
    """A package an asset ships, from an SBOM. Answers "who uses this?" on a zero-day morning."""

    __tablename__ = "components"
    __table_args__ = (
        UniqueConstraint("asset_id", "key", name="uq_components_asset_key"),
        Index("ix_components_name", "name"),
        Index("ix_components_purl", "purl"),
        Index("ix_components_licenses", "licenses", postgresql_using="gin"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    # SHA-256 of the complete ecosystem/name/version identity; version case is preserved.
    key: Mapped[str] = mapped_column(String(400))
    name: Mapped[str] = mapped_column(String(300))
    version: Mapped[str | None] = mapped_column(String(100))
    ecosystem: Mapped[str | None] = mapped_column(String(50))
    purl: Mapped[str | None] = mapped_column(String(1000))
    licenses: Mapped[list[str]] = mapped_column(ARRAY(String(100)), default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))

    asset: Mapped[Asset] = relationship()


class ComponentScan(Base):
    """Membership in a particular inventory, independent of other scanners' observations."""

    __tablename__ = "component_scans"
    component_id: Mapped[int] = mapped_column(
        ForeignKey("components.id", ondelete="CASCADE"), primary_key=True
    )
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True, index=True
    )
