from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.asset import Asset
from app.models.base import TimestampMixin
from app.models.user import User


class SlaPolicy(Base):
    """Remediation deadline in days for a severity, optionally specific to an asset criticality.

    ``criticality == "any"`` rows replace the SLA_*_DAYS environment defaults; criticality-specific rows
    take precedence over both. See services/sla.py for the resolution order.
    """

    __tablename__ = "sla_policies"
    __table_args__ = (
        UniqueConstraint("severity", "criticality", name="uq_sla_policies_severity_criticality"),
        CheckConstraint("days >= 1", name="ck_sla_policies_days_positive"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    severity: Mapped[str] = mapped_column(String(10))
    criticality: Mapped[str] = mapped_column(String(20))
    days: Mapped[int] = mapped_column(Integer)


class SavedView(TimestampMixin, Base):
    """A named findings filter (the Findings page URL query), private to its owner or shared with everyone."""

    __tablename__ = "saved_views"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    query: Mapped[str] = mapped_column(Text, default="")
    shared: Mapped[bool] = mapped_column(default=False)

    user: Mapped[User] = relationship()


class GatePolicy(TimestampMixin, Base):
    """Pass/fail rules applied to a scan when it is ingested (see services/gate.py).

    ``asset_id`` NULL is the global policy, used for assets without one of their own.
    """

    __tablename__ = "gate_policies"
    __table_args__ = (
        # One policy per asset, and one global policy (NULL asset_id).
        Index("uq_gate_policies_asset", "asset_id", unique=True, postgresql_nulls_not_distinct=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    asset: Mapped[Asset | None] = relationship()


class TriageRule(TimestampMixin, Base):
    """Automatic triage applied to findings as they are created (see services/triage.py).

    ``match`` and ``action`` are validated by app/schemas/triage.py; rules run in ``priority`` order
    (lowest first) and a rule with an ``asset_id`` only applies to that asset.
    """

    __tablename__ = "triage_rules"
    __table_args__ = (Index("ix_triage_rules_enabled_priority", "enabled", "priority"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    match: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    action: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # How many findings the rule has acted on, for spotting a rule that suppresses too much.
    applied_count: Mapped[int] = mapped_column(Integer, default=0)

    asset: Mapped[Asset | None] = relationship()
    created_by: Mapped[User | None] = relationship()


class LicensePolicy(Base):
    """How one licence should be treated when it turns up in the component inventory."""

    __tablename__ = "license_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Stored lower-cased; matching is case-insensitive and exact (see services/licenses.py).
    licence: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    rule: Mapped[str] = mapped_column(String(10))  # allowed | denied | review
    note: Mapped[str | None] = mapped_column(Text)
