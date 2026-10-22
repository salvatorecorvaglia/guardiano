from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.models.enums import Criticality, ScanType, Severity
from app.schemas.common import ORMModel
from app.schemas.finding import MAX_TAGS, FindingOut, FindingTag, UtcDatetime
from app.schemas.scan import AssetRef
from app.schemas.user import UserBrief


class RuleMatch(BaseModel):
    """Conditions a finding must all satisfy. At least one must be given."""

    type: ScanType | None = None
    severity: list[Severity] = Field(default_factory=list)
    tool: str | None = Field(None, max_length=100)
    rule_id: str | None = Field(None, max_length=300)
    cwe: str | None = Field(None, max_length=20, description='"89" or "CWE-89"')
    package: str | None = Field(None, max_length=300)
    path_glob: str | None = Field(None, max_length=500, description='e.g. "tests/*" or "*/vendor/*"')
    title_contains: str | None = Field(None, max_length=200)
    cve: str | None = Field(None, max_length=50, description='Exact CVE id, e.g. "CVE-2021-44228"')
    ecosystem: str | None = Field(None, max_length=50, description='e.g. "npm", "pypi", "maven"')
    kev: bool | None = Field(
        None, description="true: only CVEs in CISA's KEV catalogue; false: only CVEs that are not"
    )
    epss_min: float | None = Field(None, ge=0, le=1, description="Only CVEs with at least this EPSS")
    asset_tags: list[str] = Field(
        default_factory=list, max_length=20, description="The asset must carry every one of these tags"
    )
    asset_criticality: list[Criticality] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.model_dump(exclude_defaults=True, exclude_none=True)


class RuleAction(BaseModel):
    """What to do with a matching finding. At least one effect must be given."""

    status: Literal["false_positive"] | None = Field(
        None, description="Only false_positive: risk acceptance needs a person and an expiry date"
    )
    justification: str | None = Field(None, max_length=2000)
    severity: Severity | None = Field(None, description="Override the scanner's severity")
    assignee_id: int | None = None
    tags: list[FindingTag] = Field(default_factory=list, max_length=MAX_TAGS)

    def is_empty(self) -> bool:
        return not self.model_dump(exclude_defaults=True, exclude_none=True)


class TriageRuleBase(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    priority: int = Field(100, ge=1, le=1000, description="Lowest runs first")
    asset_id: int | None = Field(None, description="null applies the rule to every asset")
    match: RuleMatch = Field(default_factory=RuleMatch)
    action: RuleAction = Field(default_factory=RuleAction)
    expires_at: UtcDatetime = None

    @model_validator(mode="after")
    def _check(self) -> "TriageRuleBase":
        if self.match.is_empty():
            raise ValueError("A rule needs at least one match condition")
        if self.action.is_empty():
            raise ValueError("A rule needs at least one action")
        # Mirrors lifecycle.validate_transition: suppressing a finding always needs a reason.
        if self.action.status == "false_positive" and not (self.action.justification or "").strip():
            raise ValueError("Marking findings as false positive requires a justification")
        return self


class TriageRuleCreate(TriageRuleBase):
    pass


class TriageRuleUpdate(BaseModel):
    """Only the fields given are changed; match and action are replaced wholesale."""

    name: str | None = Field(None, min_length=1, max_length=200)
    enabled: bool | None = None
    priority: int | None = Field(None, ge=1, le=1000)
    asset_id: int | None = None
    match: RuleMatch | None = None
    action: RuleAction | None = None
    expires_at: UtcDatetime = None
    clear_expiry: bool = False


class TriageRuleOut(ORMModel):
    id: int
    name: str
    enabled: bool
    priority: int
    asset: AssetRef | None
    match: RuleMatch
    action: RuleAction
    expires_at: datetime | None
    applied_count: int
    created_by: UserBrief | None
    created_at: datetime
    updated_at: datetime


class TriagePreviewRequest(BaseModel):
    match: RuleMatch
    asset_id: int | None = None
    limit: int = Field(20, ge=1, le=100, description="How many matching findings to return")


class TriageApplyOut(BaseModel):
    """Applying a rule to existing findings runs in the background; the audit log records the request."""

    job_id: int


class TriagePreviewOut(BaseModel):
    """A dry run over findings that already exist. Rules themselves only ever act on new findings."""

    scanned: int
    matched: int
    truncated: bool  # more findings exist than were examined
    sample: list[FindingOut]
