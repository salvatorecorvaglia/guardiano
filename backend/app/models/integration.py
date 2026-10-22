from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.asset import Asset
from app.models.base import TimestampMixin, utcnow
from app.models.user import User


class Integration(TimestampMixin, Base):
    """An issue tracker Guardiano can open tickets in (see services/trackers/)."""

    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(20))  # jira | github | gitlab
    name: Mapped[str] = mapped_column(String(100))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    base_url: Mapped[str] = mapped_column(Text)
    # Jira project key, GitHub "owner/repo", GitLab project path or numeric id.
    project: Mapped[str] = mapped_column(String(200))
    username: Mapped[str | None] = mapped_column(String(200))  # Jira account email
    # API token, encrypted at rest (core/crypto.py). Never returned by the API.
    secret_encrypted: Mapped[str] = mapped_column(Text)
    issue_type: Mapped[str | None] = mapped_column(String(50))  # Jira issue type, e.g. "Bug"
    # Report scan and gate results on commits and pull requests (GitHub and GitLab only).
    scm_feedback: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # A ticket closed in the tracker resolves its finding (when polling sees it), instead of only noting it.
    close_resolves_finding: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # Jira only: the workflow transitions Guardiano may use to close and reopen a ticket, by name.
    done_transition: Mapped[str | None] = mapped_column(String(100))
    reopen_transition: Mapped[str | None] = mapped_column(String(100))
    # Open a ticket for each new finding at or above this severity, or whose CVE is in CISA KEV.
    auto_ticket_min_severity: Mapped[str | None] = mapped_column(String(10))
    auto_ticket_kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    labels: Mapped[list[str]] = mapped_column(ARRAY(String(50)), default=list)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    last_error: Mapped[str | None] = mapped_column(Text)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    asset: Mapped[Asset | None] = relationship()


class FindingLink(Base):
    """A ticket opened for a finding. Deleting it unlinks; the ticket itself is left alone."""

    __tablename__ = "finding_links"
    __table_args__ = (UniqueConstraint("finding_id", "integration_id", name="uq_finding_links_finding_int"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    integration_id: Mapped[int | None] = mapped_column(ForeignKey("integrations.id", ondelete="SET NULL"))
    system: Mapped[str] = mapped_column(String(20))
    external_key: Mapped[str] = mapped_column(String(100))  # PROJ-123, or the issue number
    url: Mapped[str] = mapped_column(Text)
    remote_status: Mapped[str | None] = mapped_column(String(50))
    # When polling first saw the tracker call this ticket finished. It is a *suggestion* to resolve the
    # finding, never applied automatically: the lifecycle rules stay the authority. NULL once reopened.
    remote_done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    integration: Mapped[Integration | None] = relationship()
    created_by: Mapped[User | None] = relationship()


class PrComment(Base):
    """The pull-request comment Guardiano keeps for one asset, so later scans edit it instead of adding more.

    Per asset as well as per pull request: in a monorepo several assets report to the same one, and each
    keeps its own summary.
    """

    __tablename__ = "pr_comments"
    __table_args__ = (UniqueConstraint("integration_id", "asset_id", "pr_number", name="uq_pr_comments"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    pr_number: Mapped[str] = mapped_column(String(50))
    comment_id: Mapped[str] = mapped_column(String(50))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TicketOperation(Base):
    """A reservation survives crashes between remote creation and linking."""

    __tablename__ = "ticket_operations"
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    integration_id: Mapped[int] = mapped_column(
        ForeignKey("integrations.id", ondelete="CASCADE"), primary_key=True
    )
    marker: Mapped[str] = mapped_column(String(64), unique=True)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
