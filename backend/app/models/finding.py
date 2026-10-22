from datetime import datetime
from typing import Any

from sqlalchemy import (
    Computed,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, foreign, mapped_column, relationship

from app.core.db import Base
from app.models.asset import Asset
from app.models.base import TimestampMixin, utcnow
from app.models.integration import FindingLink
from app.models.intel import VulnIntel
from app.models.user import User

SEARCH_VECTOR_SQL = (
    "setweight(to_tsvector('simple', coalesce(title, '')), 'A') || "
    "setweight(to_tsvector('simple', coalesce(cve_id, '') || ' ' || coalesce(vuln_id, '') || ' ' || "
    "coalesce(rule_id, '') || ' ' || coalesce(package_name, '')), 'A') || "
    "setweight(to_tsvector('simple', coalesce(file_path, '')), 'B') || "
    "setweight(to_tsvector('english', coalesce(description, '')), 'C')"
)


TRGM_COLUMNS = ("title", "package_name", "file_path", "rule_id", "cve_id", "vuln_id")


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "dedup_key", name="uq_findings_asset_dedup"),
        Index("ix_findings_asset_status_severity", "asset_id", "status", "severity"),
        Index("ix_findings_status_severity", "status", "severity"),
        Index("ix_findings_search", "search_vector", postgresql_using="gin"),
        Index("ix_findings_tools", "tools", postgresql_using="gin"),
        Index("ix_findings_tags", "tags", postgresql_using="gin"),
        Index("ix_findings_asset_fingerprint", "asset_id", "fingerprint"),
        # Trigram indexes serve the ILIKE '%q%' fallbacks of full-text search.
        *(
            Index(
                f"ix_findings_{col}_trgm", col, postgresql_using="gin", postgresql_ops={col: "gin_trgm_ops"}
            )
            for col in TRGM_COLUMNS
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Indexed via uq_findings_asset_dedup / ix_findings_asset_status_severity (leading column).
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(10))
    dedup_key: Mapped[str] = mapped_column(String(64))

    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    # The severity in effect: ``severity_override`` when set, else ``scanner_severity``. Everything that
    # filters, gates or measures reads this one column.
    severity: Mapped[str] = mapped_column(String(10), index=True)
    # What the scanners last said (the reporting tool refreshes it; other tools can only raise it).
    scanner_severity: Mapped[str | None] = mapped_column(String(10))
    # A person's or a triage rule's decision, which a rescan must not undo.
    severity_override: Mapped[str | None] = mapped_column(String(10))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(20), default="open")  # see ix_findings_status_severity
    cwe: Mapped[list[str]] = mapped_column(ARRAY(String(20)), default=list)
    rule_id: Mapped[str | None] = mapped_column(String(300))
    tools: Mapped[list[str]] = mapped_column(ARRAY(String(100)), default=list)

    # SAST
    file_path: Mapped[str | None] = mapped_column(String(1000))
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    snippet: Mapped[str | None] = mapped_column(Text)

    # SCA
    package_name: Mapped[str | None] = mapped_column(String(300), index=True)
    package_version: Mapped[str | None] = mapped_column(String(100))
    ecosystem: Mapped[str | None] = mapped_column(String(50))
    purl: Mapped[str | None] = mapped_column(String(1000))
    cve_id: Mapped[str | None] = mapped_column(String(50), index=True)
    vuln_id: Mapped[str | None] = mapped_column(String(100))
    fixed_version: Mapped[str | None] = mapped_column(String(200))
    references: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # IaC
    resource: Mapped[str | None] = mapped_column(String(500))
    # DAST
    url: Mapped[str | None] = mapped_column(String(2000))
    http_method: Mapped[str | None] = mapped_column(String(10))
    parameter: Mapped[str | None] = mapped_column(String(300))

    # Lifecycle
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    first_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    status_justification: Mapped[str | None] = mapped_column(Text)
    risk_accepted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Manual remediation deadline; replaces the SLA-derived due date when set (see services/sla.py).
    due_at_override: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The deadline an sla.breached event was last emitted for (services/tasks.py). Kept on the finding
    # because it is a fact about the finding: a new deadline that passes is announced again.
    sla_breach_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The acceptance end date a finding.risk_acceptance_expiring event was last emitted for; same idea.
    acceptance_warned_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Triage labels set by users (distinct from the asset's tags).
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list, server_default="{}")
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    # Scanner-provided identity of the code snippet (SARIF partialFingerprints, Semgrep extra.fingerprint).
    # Used to follow a finding when its line moves; see DEDUP_FINGERPRINTS in services/dedup.py.
    fingerprint: Mapped[str | None] = mapped_column(String(200))

    search_vector: Mapped[Any] = mapped_column(TSVECTOR, Computed(SEARCH_VECTOR_SQL, persisted=True))

    # Read-only join on the CVE id: exploitability data has its own life cycle and no foreign key.
    # Lists and the detail view eager-load it (services/queries.py); elsewhere it is one small lookup.
    intel: Mapped[VulnIntel | None] = relationship(
        primaryjoin=lambda: foreign(Finding.cve_id) == VulnIntel.cve_id, viewonly=True
    )
    asset: Mapped[Asset] = relationship()
    assignee: Mapped[User | None] = relationship()
    links: Mapped[list[FindingLink]] = relationship(
        cascade="all, delete-orphan", order_by=lambda: FindingLink.created_at
    )
    events: Mapped[list["FindingEvent"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        # id breaks ties between events written in the same transaction (they share a timestamp).
        order_by=lambda: [FindingEvent.created_at.desc(), FindingEvent.id.desc()],
    )


class FindingScan(Base):
    __tablename__ = "finding_scans"

    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True, index=True
    )


class FindingEvent(Base):
    __tablename__ = "finding_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    event: Mapped[str] = mapped_column(String(30))
    from_status: Mapped[str | None] = mapped_column(String(20))
    to_status: Mapped[str | None] = mapped_column(String(20))
    from_severity: Mapped[str | None] = mapped_column(String(10))
    to_severity: Mapped[str | None] = mapped_column(String(10))
    comment: Mapped[str | None] = mapped_column(Text)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    finding: Mapped[Finding] = relationship(back_populates="events")
    actor: Mapped[User | None] = relationship()


class AcceptanceRequest(Base):
    """Somebody asking for a risk to be accepted; a manager other than them approves or rejects it."""

    __tablename__ = "acceptance_requests"
    __table_args__ = (
        # At most one open request per finding.
        Index(
            "uq_acceptance_requests_pending",
            "finding_id",
            unique=True,
            postgresql_where=text("state = 'pending'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(10), default="pending")  # pending | approved | rejected
    justification: Mapped[str] = mapped_column(Text)
    until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    finding: Mapped[Finding] = relationship()
    requested_by: Mapped[User | None] = relationship(foreign_keys=[requested_by_id])
    decided_by: Mapped[User | None] = relationship(foreign_keys=[decided_by_id])
