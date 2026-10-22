from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, Field, StringConstraints, field_validator

from app.models.enums import EventType, ScanType, Severity, Status
from app.schemas.common import ORMModel
from app.schemas.integration import FindingLinkOut
from app.schemas.scan import AssetRef
from app.schemas.user import UserBrief


def _as_utc(v: datetime | None) -> datetime | None:
    return v.replace(tzinfo=UTC) if v is not None and v.tzinfo is None else v


# Timestamps without an offset are interpreted as UTC.
UtcDatetime = Annotated[datetime | None, AfterValidator(_as_utc)]
# Finding tags: lower-case labels such as "needs-review" or "team:payments".
FindingTag = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, to_lower=True, min_length=1, max_length=64, pattern=r"^[\w.:/+-]+$"
    ),
]
MAX_TAGS = 20


class Reference(BaseModel):
    url: str | None = None
    title: str | None = None


class FindingOut(ORMModel):
    id: int
    asset: AssetRef
    type: ScanType
    title: str
    severity: Severity
    cvss_score: float | None
    status: Status
    cwe: list[str]
    rule_id: str | None
    tools: list[str]
    file_path: str | None
    line_start: int | None
    package_name: str | None
    package_version: str | None
    cve_id: str | None
    vuln_id: str | None
    fixed_version: str | None
    resource: str | None = None
    url: str | None = None
    http_method: str | None = None
    parameter: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    closed_at: datetime | None
    assignee: UserBrief | None
    tags: list[str] = []
    due_at_override: datetime | None = None
    severity_override: Severity | None = None
    scanner_severity: Severity | None = None
    sla_due_at: datetime | None = None
    overdue: bool = False
    # Exploitability, when the feeds cover this CVE.
    epss: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    kev_due_date: date | None = None
    kev_ransomware: bool = False
    priority: float = Field(
        0.0,
        description="Severity weight x exploitability x asset criticality (0-40 with default settings); "
        "see services/priority.py",
    )


class FindingEventOut(ORMModel):
    id: int
    event: EventType
    from_status: Status | None
    to_status: Status | None
    comment: str | None
    scan_id: int | None
    actor: UserBrief | None
    created_at: datetime


class FindingDetail(FindingOut):
    description: str
    remediation: str
    line_end: int | None
    snippet: str | None
    ecosystem: str | None
    purl: str | None
    references: list[Reference]
    status_justification: str | None
    risk_accepted_until: datetime | None
    occurrence_count: int
    first_scan_id: int | None
    last_scan_id: int | None
    links: list[FindingLinkOut] = []  # tickets opened for this finding
    events: list[FindingEventOut]
    events_total: int = 0

    @field_validator("references", mode="before")
    @classmethod
    def _lenient_references(cls, v: Any) -> list[dict[str, Any]]:
        # Rows ingested before input sanitisation may hold arbitrary JSON; keep only well-formed parts.
        out = []
        for r in v or []:
            if isinstance(r, dict):
                url, title = r.get("url"), r.get("title")
                out.append(
                    {
                        "url": url if isinstance(url, str) else None,
                        "title": title if isinstance(title, str) else None,
                    }
                )
        return out


class FindingUpdate(BaseModel):
    status: Status | None = None
    justification: str | None = Field(None, max_length=5000)
    risk_accepted_until: UtcDatetime = None
    assignee_id: int | None = None
    unassign: bool = False
    tags: list[FindingTag] | None = Field(
        None, max_length=MAX_TAGS, description="Replaces the finding's tags"
    )
    due_at: UtcDatetime = Field(None, description="Override the SLA due date (manager or higher)")
    clear_due_at: bool = Field(False, description="Remove the override and return to the SLA due date")
    due_reason: str | None = Field(None, max_length=2000)
    severity: Severity | None = Field(None, description="Override the severity (manager or higher)")
    clear_severity_override: bool = Field(False, description="Return to the severity the scanners report")
    severity_reason: str | None = Field(None, max_length=2000)


class BulkChange(BaseModel):
    """One change applied to many findings."""

    status: Status | None = None
    justification: str | None = Field(None, max_length=5000)
    risk_accepted_until: UtcDatetime = None
    assignee_id: int | None = None
    unassign: bool = False
    add_tags: list[FindingTag] = Field(default_factory=list, max_length=MAX_TAGS)
    remove_tags: list[FindingTag] = Field(default_factory=list, max_length=MAX_TAGS)
    due_at: UtcDatetime = Field(None, description="Override the SLA due date (manager or higher)")
    clear_due_at: bool = Field(False, description="Remove the override and return to the SLA due date")
    due_reason: str | None = Field(None, max_length=2000)
    severity: Severity | None = Field(None, description="Override the severity (manager or higher)")
    clear_severity_override: bool = Field(False, description="Return to the severity the scanners report")
    severity_reason: str | None = Field(None, max_length=2000)

    def is_empty(self) -> bool:
        return (
            self.status is None
            and self.assignee_id is None
            and not self.unassign
            and not self.add_tags
            and not self.remove_tags
            and self.due_at is None
            and not self.clear_due_at
            and self.severity is None
            and not self.clear_severity_override
        )


class BulkUpdate(BulkChange):
    ids: list[int] = Field(min_length=1, max_length=1000)


class BulkResult(BaseModel):
    updated: int


class TagCount(BaseModel):
    tag: str
    count: int
    active: int


class CommentCreate(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


class AcceptanceRequestCreate(BaseModel):
    justification: str = Field(min_length=1, max_length=5000)
    until: UtcDatetime = Field(None, description="When the acceptance should end; may be required by policy")


class AcceptanceDecision(BaseModel):
    note: str | None = Field(None, max_length=2000)


class AcceptanceRequestOut(ORMModel):
    id: int
    finding_id: int
    finding_title: str
    asset: AssetRef
    severity: Severity
    state: Literal["pending", "approved", "rejected"]
    justification: str
    until: datetime | None
    requested_by: UserBrief | None
    decided_by: UserBrief | None
    decided_at: datetime | None
    decision_note: str | None
    created_at: datetime
