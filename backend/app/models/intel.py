from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import utcnow


class VulnIntel(Base):
    """What the world knows about a CVE: how likely it is to be exploited, and whether it already is.

    Filled by the daily feed sync (services/intel.py) and joined to findings at read time, so refreshing
    the feeds never rewrites the inventory.
    """

    __tablename__ = "vuln_intel"
    __table_args__ = (Index("ix_vuln_intel_kev_epss", "in_kev", "epss"),)

    cve_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    # FIRST EPSS: probability of exploitation in the next 30 days, and its percentile among all CVEs.
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    # CISA Known Exploited Vulnerabilities.
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_name: Mapped[str | None] = mapped_column(Text)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VulnAlias(Base):
    """The CVE an advisory id (GHSA, PYSEC, RUSTSEC, ...) is also known as, from OSV.

    Remembered with when it was asked, so an advisory that has no CVE is not asked about every day.
    """

    __tablename__ = "vuln_aliases"

    vuln_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    cve_id: Mapped[str | None] = mapped_column(String(50))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KevAnnouncement(Base):
    """Durable backlog, independent of feed changes and webhook retention."""

    __tablename__ = "kev_announcements"
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    announced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
