from datetime import date as Date
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.asset import SeverityCounts


class StatusCounts(BaseModel):
    open: int = 0
    in_progress: int = 0
    false_positive: int = 0
    risk_accepted: int = 0
    resolved: int = 0


class TypeCounts(BaseModel):
    sast: int = 0
    sca: int = 0
    iac: int = 0
    dast: int = 0


class SeverityDays(BaseModel):
    critical: float | None = None
    high: float | None = None
    medium: float | None = None
    low: float | None = None
    info: float | None = None


class Summary(BaseModel):
    open_total: int
    open_by_severity: SeverityCounts
    by_status: StatusCounts
    open_by_type: TypeCounts
    overdue: int
    known_exploited: int = 0  # active findings whose CVE is in CISA KEV
    mttr_days: SeverityDays
    mttr_days_overall: float | None
    new_last_30d: int
    resolved_last_30d: int
    scans_last_30d: int
    assets_total: int


class OpenPoint(SeverityCounts):
    date: Date


class FlowPoint(BaseModel):
    period: Date
    new: int
    closed: int


class Trends(BaseModel):
    severity_history_complete: bool = True
    days: int
    bucket: Literal["day", "week"]
    open_by_severity: list[OpenPoint]
    new_vs_closed: list[FlowPoint]


class TopAsset(BaseModel):
    id: int
    name: str
    criticality: str
    risk_score: float
    open: int
    critical: int
    high: int
    medium: int
    low: int


class UncoveredAsset(BaseModel):
    id: int
    name: str
    criticality: str
    last_scan_at: datetime | None
    last_sast_at: datetime | None
    last_sca_at: datetime | None
    has_sbom: bool


class Coverage(BaseModel):
    """How many assets are scanned recently enough. Preview scans do not count."""

    stale_days: int
    assets: int
    covered: int
    stale: int = Field(description="Scanned, but not within stale_days")
    never_scanned: int
    without_sast: int
    without_sca: int
    uncovered: list[UncoveredAsset] = Field(
        description="Never-scanned assets first, then the longest-unscanned; at most 200"
    )


class TopCwe(BaseModel):
    cwe: str
    count: int


class TopPackage(BaseModel):
    package: str
    ecosystem: str | None
    count: int
    assets: int
    critical_high: int


class Meta(BaseModel):
    name: str
    version: str
    formats: list[str]
    max_upload_mb: int
    sla_days: dict[str, int]
    email_enabled: bool = False  # false hides the password-reset and digest features in the UI
    local_login: bool = True  # false means single sign-on only
    oidc_enabled: bool = False
    oidc_label: str = "Sign in with SSO"
    docs_enabled: bool = False


class OwaspCategory(BaseModel):
    id: str  # A01 … A10
    title: str
    open: int
    critical_high: int


class Owasp(BaseModel):
    edition: str
    categories: list[OwaspCategory]
    open_total: int
    mapped: int  # findings reaching at least one category
    unmapped: int  # the rest: no CWE, or a CWE OWASP does not map


class TopWeakness(BaseModel):
    rank: int
    cwe: str
    name: str
    open: int
    critical_high: int


class SlaSeverity(BaseModel):
    severity: str
    open: int
    within_sla: int
    within_sla_pct: float | None
    resolved: int
    resolved_on_time: int
    resolved_on_time_pct: float | None


class SlaPerformance(SlaSeverity):
    days: int
    severity: str = "all"
    by_severity: list[SlaSeverity]


class MttrPoint(BaseModel):
    period: Date
    days: float
    resolved: int


class Compliance(BaseModel):
    generated_at: datetime
    asset_id: int | None = None
    owasp: Owasp
    cwe_top_25: list[TopWeakness]
    cwe_top_25_edition: str
    sla: SlaPerformance
    mttr_trend: list[MttrPoint]


class BreakdownRow(BaseModel):
    key: str | None = Field(description="Product or team id, environment, or tool name; null for none")
    label: str
    open: int
    critical_high: int
    overdue: int
    accepted: int = Field(description="Findings with an active risk acceptance")
    resolved: int = Field(description="Resolved within the window")
    mttr_days: float | None = Field(description="Mean days to resolve, over those resolved in the window")
    median_triage_hours: float | None = Field(
        description="Median hours from first seen to a person's first action, for findings new in the window"
    )
    unique_open: int | None = Field(None, description="By tool: open findings only this tool reports")
    shared_open: int | None = Field(None, description="By tool: open findings another tool reports too")
