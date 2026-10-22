from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.urlguard import check_url
from app.models.enums import TRACKER_KINDS, Severity
from app.schemas.common import ORMModel
from app.schemas.scan import AssetRef
from app.schemas.user import UserBrief

Kind = Literal[TRACKER_KINDS]  # type: ignore[valid-type]


def _check_url(v: str) -> str:
    """Scheme plus the SSRF guard, so an unreachable target is refused where it is typed in."""
    return check_url(v)


class IntegrationBase(BaseModel):
    kind: Kind
    name: str = Field(min_length=1, max_length=100)
    base_url: str = Field(
        max_length=2000,
        examples=["https://your-org.atlassian.net", "https://api.github.com", "https://gitlab.com"],
    )
    project: str = Field(min_length=1, max_length=200, description="Jira key, owner/repo, or GitLab path")
    username: str | None = Field(None, max_length=200, description="Jira account email; blank for a PAT")
    issue_type: str | None = Field(None, max_length=50, description='Jira issue type, e.g. "Bug"')
    labels: list[str] = Field(default_factory=list, max_length=20)
    asset_id: int | None = Field(None, description="null offers this tracker for every asset")
    scm_feedback: bool = Field(
        False, description="Report scan and gate results on commits and pull requests (GitHub/GitLab)"
    )
    close_resolves_finding: bool = Field(
        False, description="Resolve a finding when polling finds its ticket closed (needs TRACKER_POLL_HOURS)"
    )
    done_transition: str | None = Field(None, max_length=100, description="Jira: transition that closes")
    reopen_transition: str | None = Field(None, max_length=100, description="Jira: transition that reopens")
    auto_ticket_min_severity: Severity | None = Field(
        None, description="Open a ticket for each new finding at or above this severity"
    )
    auto_ticket_kev: bool = Field(
        False, description="Open a ticket for each new finding whose CVE is in CISA KEV"
    )
    enabled: bool = True

    _url = field_validator("base_url")(_check_url)


class IntegrationCreate(IntegrationBase):
    token: str = Field(min_length=1, max_length=500, description="API token; stored encrypted")

    @model_validator(mode="after")
    def _scm_only_for_forges(self) -> "IntegrationCreate":
        if self.scm_feedback and self.kind == "jira":
            raise ValueError("Commit and pull-request feedback needs GitHub or GitLab")
        return self


class IntegrationUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    base_url: str | None = Field(None, max_length=2000)
    project: str | None = Field(None, min_length=1, max_length=200)
    username: str | None = Field(None, max_length=200)
    issue_type: str | None = Field(None, max_length=50)
    labels: list[str] | None = Field(None, max_length=20)
    asset_id: int | None = None
    scm_feedback: bool | None = None
    close_resolves_finding: bool | None = None
    done_transition: str | None = Field(None, max_length=100, description='"" removes it')
    reopen_transition: str | None = Field(None, max_length=100, description='"" removes it')
    auto_ticket_min_severity: Severity | None = Field(None, description="null (when given) turns it off")
    auto_ticket_kev: bool | None = None
    enabled: bool | None = None
    token: str | None = Field(None, min_length=1, max_length=500, description="Replaces the stored token")

    _url = field_validator("base_url")(lambda cls, v: v if v is None else _check_url(v))


class IntegrationOut(ORMModel):
    """The token is never returned."""

    id: int
    kind: str
    name: str
    base_url: str
    project: str
    username: str | None
    issue_type: str | None
    labels: list[str]
    asset: AssetRef | None
    scm_feedback: bool
    close_resolves_finding: bool
    done_transition: str | None
    reopen_transition: str | None
    auto_ticket_min_severity: Severity | None
    auto_ticket_kev: bool
    enabled: bool
    last_error: str | None
    last_used_at: datetime | None
    created_at: datetime


class IntegrationCheck(BaseModel):
    ok: bool
    detail: str


class FindingLinkOut(ORMModel):
    id: int
    system: str
    external_key: str
    url: str
    remote_status: str | None
    # Set when the tracker reported the ticket finished: a suggestion to resolve, never an action.
    remote_done_at: datetime | None = None
    created_by: UserBrief | None
    created_at: datetime
    synced_at: datetime | None


class TicketCreate(BaseModel):
    integration_id: int | None = Field(None, description="Defaults to the only tracker available")
